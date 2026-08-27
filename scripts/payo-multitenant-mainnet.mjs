import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Account,
  CallData,
  Contract,
  RpcProvider,
  constants,
  hash,
  num,
  uint256,
  validateAndParseAddress,
} from "starknet";

const ROOT = resolve(import.meta.dirname, "..");
const PLAN_PATH = resolve(ROOT, "circuits/payroll_integrity/target/payo-multitenant-mainnet-plan.json");
const EVIDENCE_PATH = resolve(ROOT, "circuits/payroll_integrity/target/payo-multitenant-mainnet-deployment.json");
const PHASE2_PATH = resolve(ROOT, "circuits/payroll_integrity/target/payo-mainnet-deployment.json");
const PHASE3_PATH = resolve(ROOT, "circuits/payroll_integrity/target/payo-phase3-mainnet-deployment.json");
const TENANT_SIERRA = resolve(ROOT, "contracts/target/dev/payo_contracts_PayoTenantObligationRootRegistry.contract_class.json");
const TENANT_CASM = resolve(ROOT, "contracts/target/dev/payo_contracts_PayoTenantObligationRootRegistry.compiled_contract_class.json");
const POLICY_SIERRA = resolve(ROOT, "contracts/target/dev/payo_contracts_PayoPolicyRegistry.contract_class.json");
const SEAL_SIERRA = resolve(ROOT, "contracts/target/dev/payo_contracts_PayoPayrollSeal.contract_class.json");
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const LIFETIME_SECONDS = 365 * 24 * 60 * 60;
const action = process.argv[2];

if (!["plan", "estimate", "declare", "deploy", "activate", "verify"].includes(action)) {
  throw new Error("Usage: node scripts/payo-multitenant-mainnet.mjs <plan|estimate|declare|deploy|activate|verify>");
}

const provider = new RpcProvider({
  nodeUrl: process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL,
});

function canonicalAddress(value, label) {
  if (!value) throw new Error(`${label} is required.`);
  const address = validateAndParseAddress(value);
  if (BigInt(address) === 0n) throw new Error(`${label} must be non-zero.`);
  return num.toHex(BigInt(address));
}

function artifactHash(artifact) {
  return num.toHex(BigInt(hash.computeContractClassHash(artifact)));
}

function compiledHash(artifact) {
  return num.toHex(BigInt(hash.computeCompiledClassHash(artifact)));
}

function addressFor(classHash, salt, constructorCalldata) {
  return num.toHex(BigInt(hash.calculateContractAddressFromHash(
    salt,
    classHash,
    CallData.compile(constructorCalldata),
    0,
  )));
}

function feeFields(fee) {
  const fri = BigInt(fee.overall_fee);
  return { feeFri: fri.toString(), feeStrk: Number(fri) / 1e18 };
}

function actualFee(receipt) {
  return BigInt(receipt.actual_fee?.amount ?? receipt.actual_fee ?? 0);
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function readJsonIfExists(path) {
  try {
    return await readJson(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function stablePlan(plan) {
  return JSON.stringify({ ...plan, generatedAt: undefined });
}

async function loadEvidence(plan) {
  const evidence = await readJsonIfExists(EVIDENCE_PATH);
  if (evidence?.plan && stablePlan(evidence.plan) !== stablePlan(plan)) {
    throw new Error("The existing multi-tenant deployment evidence belongs to another plan.");
  }
  return evidence ?? {
    schemaVersion: 1,
    network: "starknet-mainnet",
    plan,
  };
}

async function requireMainnet() {
  const chainId = await provider.getChainId();
  if (BigInt(chainId) !== BigInt(constants.StarknetChainId.SN_MAIN)) {
    throw new Error(`Refusing operation: RPC reports non-Mainnet chain ${chainId}.`);
  }
  return num.toHex(BigInt(chainId));
}

async function isDeclared(classHash) {
  try {
    await provider.getClass(classHash, "latest");
    return true;
  } catch (error) {
    if (/class hash not found|undeclared class|class_hash_not_found/i.test(String(error))) return false;
    throw error;
  }
}

async function deployedClassHash(address, block = "latest") {
  try {
    return num.toHex(BigInt(await provider.getClassHashAt(address, block)));
  } catch (error) {
    if (/contract not found|contract_address_not_found|uninitialized contract/i.test(String(error))) return null;
    throw error;
  }
}

async function balance(address) {
  const response = await provider.callContract({
    contractAddress: STRK,
    entrypoint: "balance_of",
    calldata: [address],
  }, "latest");
  return uint256.uint256ToBN({ low: response[0], high: response[1] });
}

function accountFor(address) {
  const key = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!key || !/^0x[0-9a-fA-F]+$/.test(key)) throw new Error("PAYO_PROOF_RELAYER_PRIVATE_KEY is required.");
  return new Account({ provider, address, signer: key, cairoVersion: "1" });
}

async function buildPlan() {
  const [phase2, phase3, tenantSierra, tenantCasm, policySierra, sealSierra] = await Promise.all([
    readJson(PHASE2_PATH),
    readJson(PHASE3_PATH),
    readJson(TENANT_SIERRA),
    readJson(TENANT_CASM),
    readJson(POLICY_SIERRA),
    readJson(SEAL_SIERRA),
  ]);
  if (phase2.verification?.passed !== true || phase3.activation?.passed !== true) {
    throw new Error("The existing verified Phase 2/3 Mainnet topology is incomplete.");
  }
  const chainId = await requireMainnet();
  const deployerAddress = canonicalAddress(process.env.PAYO_PROOF_RELAYER_ADDRESS, "PAYO_PROOF_RELAYER_ADDRESS");
  if (tenantCasm.compiler_version !== "2.16.1") {
    throw new Error(
      `The tenant registry was compiled with Cairo ${tenantCasm.compiler_version ?? "unknown"}; expected pinned 2.16.1.`,
    );
  }
  const tenantClassHash = artifactHash(tenantSierra);
  const tenantCompiledClassHash = compiledHash(tenantCasm);
  const policyClassHash = artifactHash(policySierra);
  const sealClassHash = artifactHash(sealSierra);
  if (BigInt(policyClassHash) !== BigInt(phase2.plan.contracts.policyRegistry.classHash)) {
    throw new Error("The rebuilt policy registry differs from its declared Mainnet class.");
  }
  if (BigInt(sealClassHash) !== BigInt(phase3.declarations.payrollSeal.classHash)) {
    throw new Error("The rebuilt payroll seal differs from its declared Phase 3 Mainnet class.");
  }
  const salts = {
    policyRegistry: "0x7061796f2d6d756c746974656e616e742d706f6c6963792d7631",
    obligationRegistry: "0x7061796f2d74656e616e742d6f626c69676174696f6e732d7631",
    payrollSeal: "0x7061796f2d6d756c746974656e616e742d7365616c2d7631",
  };
  const constructors = {
    policyRegistry: [deployerAddress],
    obligationRegistry: [deployerAddress],
  };
  const contracts = {
    policyRegistry: {
      classHash: policyClassHash,
      salt: salts.policyRegistry,
      constructorCalldata: constructors.policyRegistry,
      address: addressFor(policyClassHash, salts.policyRegistry, constructors.policyRegistry),
    },
    obligationRegistry: {
      classHash: tenantClassHash,
      compiledClassHash: tenantCompiledClassHash,
      salt: salts.obligationRegistry,
      constructorCalldata: constructors.obligationRegistry,
      address: addressFor(tenantClassHash, salts.obligationRegistry, constructors.obligationRegistry),
    },
  };
  const sealConstructor = [
    phase2.plan.poolAddress,
    contracts.policyRegistry.address,
    contracts.obligationRegistry.address,
    chainId,
  ];
  contracts.payrollSeal = {
    classHash: sealClassHash,
    salt: salts.payrollSeal,
    constructorCalldata: sealConstructor,
    address: addressFor(sealClassHash, salts.payrollSeal, sealConstructor),
  };
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    network: "starknet-mainnet",
    chainId,
    deployerAddress,
    poolAddress: phase2.plan.poolAddress,
    baselinePolicyRoot: phase2.baseline.policyRoot,
    contracts,
    verifierProfiles: [
      { mode: 0, proofVersion: 1, address: phase2.plan.contracts.bundleVerifier.address },
      { mode: 0, proofVersion: 2, address: phase3.activation.profiles.find((item) => item.mode === "0" && item.proofVersion === "2").bundleAddress },
      { mode: 2, proofVersion: 3, address: phase3.activation.profiles.find((item) => item.mode === "2").bundleAddress },
      { mode: 3, proofVersion: 4, address: phase3.activation.profiles.find((item) => item.mode === "3").bundleAddress },
    ],
  };
}

async function loadPlan() {
  const [stored, rebuilt] = await Promise.all([readJson(PLAN_PATH), buildPlan()]);
  if (stablePlan(stored) !== stablePlan(rebuilt)) {
    throw new Error("The reviewed multi-tenant plan is stale relative to the compiled artifacts.");
  }
  return stored;
}

function payloads(plan, comparableTenantClassHash) {
  const contract = (entry, classHash = entry.classHash) => ({
    classHash,
    constructorCalldata: CallData.compile(entry.constructorCalldata),
    salt: entry.salt,
    unique: false,
  });
  return {
    policy: contract(plan.contracts.policyRegistry),
    tenant: contract(plan.contracts.obligationRegistry, comparableTenantClassHash ?? plan.contracts.obligationRegistry.classHash),
    seal: contract(plan.contracts.payrollSeal),
  };
}

async function activationCalls(plan) {
  const latest = await provider.getBlock("latest");
  const validAfter = Number(latest.timestamp);
  const expiresAt = validAfter + LIFETIME_SECONDS;
  const policy = new Contract({
    abi: (await readJson(POLICY_SIERRA)).abi,
    address: plan.contracts.policyRegistry.address,
    providerOrAccount: provider,
  });
  const root = BigInt(plan.baselinePolicyRoot);
  return {
    validAfter,
    expiresAt,
    calls: [
      policy.populate("schedule_policy_root", [root >> 128n, root & ((1n << 128n) - 1n), validAfter, expiresAt]),
      ...plan.verifierProfiles.map((profile) => policy.populate("schedule_verifier", [
        profile.mode, profile.proofVersion, profile.address, validAfter, expiresAt,
      ])),
    ],
  };
}

async function verify(plan) {
  const blockNumber = await provider.getBlockNumber();
  const classChecks = await Promise.all(Object.entries(plan.contracts).map(async ([name, entry]) => ({
    code: `${name}.class_hash`,
    expected: entry.classHash,
    actual: await deployedClassHash(entry.address, blockNumber),
  })));
  const dependencyChecks = await Promise.all([
    { code: "pool.deployed", address: plan.poolAddress },
    ...plan.verifierProfiles.map((profile) => ({
      code: `verifier.${profile.mode}.${profile.proofVersion}.deployed`,
      address: profile.address,
    })),
  ].map(async (dependency) => ({
    ...dependency,
    classHash: await deployedClassHash(dependency.address, blockNumber),
  })));
  const policy = new Contract({ abi: (await readJson(POLICY_SIERRA)).abi, address: plan.contracts.policyRegistry.address, providerOrAccount: provider });
  const tenant = new Contract({ abi: (await readJson(TENANT_SIERRA)).abi, address: plan.contracts.obligationRegistry.address, providerOrAccount: provider });
  const seal = new Contract({ abi: (await readJson(SEAL_SIERRA)).abi, address: plan.contracts.payrollSeal.address, providerOrAccount: provider });
  const root = BigInt(plan.baselinePolicyRoot);
  const [policyAdmin, publisher, tenantAdmin, pool, catalog, obligations, policyValid, ...profiles] = await Promise.all([
    policy.call("get_admin", [], { blockIdentifier: blockNumber }),
    policy.call("get_fx_publisher", [], { blockIdentifier: blockNumber }),
    tenant.call("get_admin", [], { blockIdentifier: blockNumber }),
    seal.call("get_pool", [], { blockIdentifier: blockNumber }),
    seal.call("get_catalog_registry", [], { blockIdentifier: blockNumber }),
    seal.call("get_obligation_registry", [], { blockIdentifier: blockNumber }),
    policy.call("is_policy_root_valid", [root >> 128n, root & ((1n << 128n) - 1n)], { blockIdentifier: blockNumber }),
    ...plan.verifierProfiles.map((profile) => Promise.all([
      policy.call("is_verifier_valid", [profile.mode, profile.proofVersion], { blockIdentifier: blockNumber }),
      policy.call("get_verifier", [profile.mode, profile.proofVersion], { blockIdentifier: blockNumber }),
    ])),
  ]);
  const scalar = (value) => BigInt(Array.isArray(value) ? value[0] : value);
  const checks = [
    ...classChecks.map((check) => ({ ...check, passed: check.actual !== null && BigInt(check.actual) === BigInt(check.expected) })),
    ...dependencyChecks.map((check) => ({ ...check, passed: check.classHash !== null })),
    { code: "policy.admin", passed: scalar(policyAdmin) === BigInt(plan.deployerAddress) },
    { code: "policy.fx_publisher", passed: scalar(publisher) === BigInt(plan.deployerAddress) },
    { code: "obligations.emergency_admin", passed: scalar(tenantAdmin) === BigInt(plan.deployerAddress) },
    { code: "seal.pool", passed: scalar(pool) === BigInt(plan.poolAddress) },
    { code: "seal.policy_registry", passed: scalar(catalog) === BigInt(plan.contracts.policyRegistry.address) },
    { code: "seal.obligation_registry", passed: scalar(obligations) === BigInt(plan.contracts.obligationRegistry.address) },
    { code: "policy.baseline", passed: Boolean(policyValid) },
    ...profiles.map((profile, index) => ({
      code: `verifier.${plan.verifierProfiles[index].mode}.${plan.verifierProfiles[index].proofVersion}`,
      passed: Boolean(profile[0]) && scalar(profile[1]) === BigInt(plan.verifierProfiles[index].address),
    })),
  ];
  return { passed: checks.every((check) => check.passed), blockNumber, checks };
}

await requireMainnet();

if (action === "plan") {
  const plan = await buildPlan();
  await writeJson(PLAN_PATH, plan);
  console.log(JSON.stringify({ planPath: PLAN_PATH, plan }, null, 2));
  process.exit(0);
}

const plan = await loadPlan();
const account = accountFor(plan.deployerAddress);

if (action === "estimate") {
  const tenantDeclared = await isDeclared(plan.contracts.obligationRegistry.classHash);
  const artifacts = await Promise.all([readJson(TENANT_SIERRA), readJson(TENANT_CASM)]);
  const declaration = tenantDeclared
    ? { declared: true, feeFri: "0", feeStrk: 0 }
    : { declared: false, ...feeFields(await account.estimateDeclareFee({ contract: artifacts[0], casm: artifacts[1] })) };
  const comparableClassHash = tenantDeclared
    ? undefined
    : (await readJson(PHASE2_PATH)).plan.contracts.obligationRegistry.classHash;
  const deploy = payloads(plan, comparableClassHash);
  const pending = [];
  for (const [name, payload] of Object.entries(deploy)) {
    const planned = plan.contracts[name === "tenant" ? "obligationRegistry" : name === "policy" ? "policyRegistry" : "payrollSeal"];
    const actual = await deployedClassHash(planned.address);
    if (!actual) pending.push(payload);
    else if (BigInt(actual) !== BigInt(planned.classHash)) throw new Error(`${name} predicted address contains another class.`);
  }
  const deployment = pending.length ? feeFields(await account.estimateDeployFee(pending)) : { feeFri: "0", feeStrk: 0 };
  const currentBalance = await balance(plan.deployerAddress);
  const estimated = BigInt(declaration.feeFri) + BigInt(deployment.feeFri);
  console.log(JSON.stringify({
    observedAt: new Date().toISOString(),
    declaration,
    deployment: { ...deployment, registryEstimateComparable: !tenantDeclared },
    activationHistoricalUpperBoundStrk: 0.5,
    estimatedTotalStrk: Number(estimated) / 1e18 + 0.5,
    safeReserveStrk: (Number(estimated) / 1e18 + 0.5) * 1.25,
    balanceStrk: Number(currentBalance) / 1e18,
  }, null, 2));
  process.exit(0);
}

if (action === "declare") {
  if (process.env.PAYO_MULTITENANT_MAINNET_CONFIRM !== "DECLARE_PAYO_MULTITENANT_MAINNET") {
    throw new Error("Set PAYO_MULTITENANT_MAINNET_CONFIRM=DECLARE_PAYO_MULTITENANT_MAINNET after reviewing the estimate.");
  }
  if (await isDeclared(plan.contracts.obligationRegistry.classHash)) {
    const evidence = await loadEvidence(plan);
    await writeJson(EVIDENCE_PATH, {
      ...evidence,
      declaration: evidence.declaration ?? {
        classHash: plan.contracts.obligationRegistry.classHash,
        transactionHash: null,
        alreadyDeclared: true,
        observedAt: new Date().toISOString(),
      },
    });
    console.log("Tenant obligation registry class is already declared and recorded.");
    process.exit(0);
  }
  const [contract, casm] = await Promise.all([readJson(TENANT_SIERRA), readJson(TENANT_CASM)]);
  const estimate = await account.estimateDeclareFee({ contract, casm });
  if (await balance(plan.deployerAddress) < BigInt(estimate.overall_fee)) throw new Error("Relayer balance is below the declaration estimate.");
  const submitted = await account.declare({ contract, casm });
  const receipt = await provider.waitForTransaction(submitted.transaction_hash, { retries: 400, retryInterval: 3_000 });
  if (!await isDeclared(plan.contracts.obligationRegistry.classHash)) throw new Error("Tenant class declaration did not become readable.");
  const evidence = await loadEvidence(plan);
  await writeJson(EVIDENCE_PATH, { ...evidence, declaration: {
    classHash: plan.contracts.obligationRegistry.classHash,
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: estimate.overall_fee.toString(),
    actualFeeFri: actualFee(receipt).toString(),
    blockNumber: receipt.block_number,
  } });
  console.log(JSON.stringify({ transactionHash: submitted.transaction_hash, actualFeeStrk: Number(actualFee(receipt)) / 1e18 }, null, 2));
  process.exit(0);
}

if (action === "deploy") {
  if (process.env.PAYO_MULTITENANT_MAINNET_CONFIRM !== "DEPLOY_PAYO_MULTITENANT_MAINNET") {
    throw new Error("Set PAYO_MULTITENANT_MAINNET_CONFIRM=DEPLOY_PAYO_MULTITENANT_MAINNET after declaration read-back.");
  }
  if (!await isDeclared(plan.contracts.obligationRegistry.classHash)) throw new Error("Declare the tenant registry first.");
  const deploy = payloads(plan);
  const pending = [];
  for (const [name, payload] of Object.entries(deploy)) {
    const key = name === "tenant" ? "obligationRegistry" : name === "policy" ? "policyRegistry" : "payrollSeal";
    const actual = await deployedClassHash(plan.contracts[key].address);
    if (!actual) pending.push(payload);
    else if (BigInt(actual) !== BigInt(plan.contracts[key].classHash)) throw new Error(`${name} predicted address contains another class.`);
  }
  if (!pending.length) {
    const evidence = await loadEvidence(plan);
    await writeJson(EVIDENCE_PATH, { ...evidence, deployment: evidence.deployment ?? {
      transactionHash: null,
      alreadyDeployed: true,
      observedAt: new Date().toISOString(),
    } });
    console.log("Multi-tenant contracts are already deployed and recorded.");
    process.exit(0);
  }
  const estimate = await account.estimateDeployFee(pending);
  if (await balance(plan.deployerAddress) < BigInt(estimate.overall_fee)) throw new Error("Relayer balance is below the deployment estimate.");
  const submitted = await account.deployContract(pending);
  const receipt = await provider.waitForTransaction(submitted.transaction_hash, { retries: 400, retryInterval: 3_000 });
  for (const entry of Object.values(plan.contracts)) {
    const actual = await deployedClassHash(entry.address);
    if (!actual || BigInt(actual) !== BigInt(entry.classHash)) throw new Error("A deployed class failed read-back.");
  }
  const evidence = await loadEvidence(plan);
  await writeJson(EVIDENCE_PATH, { ...evidence, deployment: {
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: estimate.overall_fee.toString(),
    actualFeeFri: actualFee(receipt).toString(),
    blockNumber: receipt.block_number,
  } });
  console.log(JSON.stringify({ transactionHash: submitted.transaction_hash, actualFeeStrk: Number(actualFee(receipt)) / 1e18 }, null, 2));
  process.exit(0);
}

if (action === "activate") {
  if (process.env.PAYO_MULTITENANT_MAINNET_CONFIRM !== "ACTIVATE_PAYO_MULTITENANT_MAINNET") {
    throw new Error("Set PAYO_MULTITENANT_MAINNET_CONFIRM=ACTIVATE_PAYO_MULTITENANT_MAINNET after deployment read-back.");
  }
  const existing = await verify(plan);
  if (existing.passed) {
    const evidence = await loadEvidence(plan);
    await writeJson(EVIDENCE_PATH, { ...evidence, verification: existing });
    console.log("The multi-tenant topology is already active and verified.");
    process.exit(0);
  }
  const activation = await activationCalls(plan);
  const estimate = await account.estimateInvokeFee(activation.calls);
  if (await balance(plan.deployerAddress) < BigInt(estimate.overall_fee)) throw new Error("Relayer balance is below the activation estimate.");
  const submitted = await account.execute(activation.calls);
  const receipt = await provider.waitForTransaction(submitted.transaction_hash, { retries: 400, retryInterval: 3_000 });
  const result = await verify(plan);
  if (!result.passed) throw new Error("The activated topology failed read-back verification.");
  const evidence = await loadEvidence(plan);
  await writeJson(EVIDENCE_PATH, { ...evidence, activation: {
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: estimate.overall_fee.toString(),
    actualFeeFri: actualFee(receipt).toString(),
    blockNumber: receipt.block_number,
    validAfter: activation.validAfter, expiresAt: activation.expiresAt,
  }, verification: result });
  console.log(JSON.stringify({ transactionHash: submitted.transaction_hash, actualFeeStrk: Number(actualFee(receipt)) / 1e18, verification: result }, null, 2));
  process.exit(0);
}

const result = await verify(plan);
console.log(JSON.stringify(result, null, 2));
if (!result.passed) process.exitCode = 1;
