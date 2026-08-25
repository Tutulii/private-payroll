import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Account,
  Contract,
  RpcProvider,
  constants,
  hash,
  num,
  validateAndParseAddress,
} from "starknet";
import {
  assertFreshPayoDeployArtifacts,
  readAllPayoDeployArtifacts,
  repositoryRoot,
} from "./lib/payo-contract-artifacts.mjs";

const MAINNET_CHAIN_ID = constants.StarknetChainId.SN_MAIN;
const STRK20_MAINNET_POOL =
  "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a";
const DEFAULT_RPC_URL = "https://rpc.starknet.lava.build";
const DEFAULT_PLAN_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-mainnet-plan.json",
);
const DEFAULT_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-mainnet-deployment.json",
);
const DEPLOY_CONFIRMATION = "DEPLOY_PAYO_MAINNET";
const BASELINE_CONFIRMATION = "SCHEDULE_PAYO_MAINNET_BASELINE";
const action = process.argv[2];

if (!["plan", "deploy", "schedule-baseline", "verify"].includes(action)) {
  throw new Error(
    "Usage: node scripts/payo-mainnet-deployment.mjs <plan|deploy|schedule-baseline|verify>",
  );
}

const rpcUrl = process.env.STARKNET_RPC_URL
  ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL
  ?? DEFAULT_RPC_URL;
const provider = new RpcProvider({ nodeUrl: rpcUrl });

function canonicalAddress(value, label) {
  if (!value) throw new Error(`${label} is required.`);
  try {
    const address = validateAndParseAddress(value);
    if (BigInt(address) === 0n) throw new Error();
    return num.toHex(BigInt(address));
  } catch {
    throw new Error(`${label} must be a non-zero Starknet address.`);
  }
}

function canonicalHash(value, label) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value ?? "")) {
    throw new Error(`${label} must be a canonical 32-byte hash.`);
  }
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function contractAddress(classHash, constructorCalldata, salt) {
  return num.toHex(BigInt(hash.calculateContractAddressFromHash(
    salt,
    classHash,
    constructorCalldata,
    0,
  )));
}

function normalizeError(error) {
  return error instanceof Error ? error.message : String(error);
}

function asScalar(value, label) {
  if (["bigint", "number", "string"].includes(typeof value)) return BigInt(value);
  if (Array.isArray(value) && value.length === 1) return asScalar(value[0], label);
  if (value && typeof value === "object") {
    const values = Object.values(value);
    if (values.length === 1) return asScalar(values[0], label);
  }
  throw new Error(`${label} returned an unexpected Starknet response.`);
}

function isMissingClass(error) {
  return /class hash not found|undeclared class|class_hash_not_found/i.test(normalizeError(error));
}

function isMissingContract(error) {
  return /contract not found|contract_address_not_found|uninitialized contract/i.test(normalizeError(error));
}

async function requireMainnet() {
  const chainId = await provider.getChainId();
  if (BigInt(chainId) !== BigInt(MAINNET_CHAIN_ID)) {
    throw new Error(`Refusing PAYO Mainnet operation: RPC reports chain ID ${chainId}.`);
  }
  return num.toHex(BigInt(chainId));
}

async function classDeclared(classHash) {
  try {
    await provider.getClass(classHash, "latest");
    return true;
  } catch (error) {
    if (isMissingClass(error)) return false;
    throw error;
  }
}

async function deployedClassHash(address, blockIdentifier = "latest") {
  try {
    return num.toHex(BigInt(await provider.getClassHashAt(address, blockIdentifier)));
  } catch (error) {
    if (isMissingContract(error)) return null;
    throw error;
  }
}

async function createPlan(adminAddress) {
  await assertFreshPayoDeployArtifacts();
  const [chainId, artifacts] = await Promise.all([
    requireMainnet(),
    readAllPayoDeployArtifacts(),
  ]);
  const salts = {
    generatedVerifier: "0x7061796f2d7665726966696572",
    bundleVerifier: "0x7061796f2d62756e646c65",
    policyRegistry: "0x7061796f2d706f6c696379",
    obligationRegistry: "0x7061796f2d6f626c69676174696f6e",
    payrollSeal: "0x7061796f2d7365616c",
  };
  const constructorCalldata = {};
  const addresses = {};
  constructorCalldata.generatedVerifier = [];
  addresses.generatedVerifier = contractAddress(
    artifacts.generatedVerifier.classHash,
    constructorCalldata.generatedVerifier,
    salts.generatedVerifier,
  );
  constructorCalldata.bundleVerifier = [addresses.generatedVerifier];
  addresses.bundleVerifier = contractAddress(
    artifacts.bundleVerifier.classHash,
    constructorCalldata.bundleVerifier,
    salts.bundleVerifier,
  );
  constructorCalldata.policyRegistry = [adminAddress];
  addresses.policyRegistry = contractAddress(
    artifacts.policyRegistry.classHash,
    constructorCalldata.policyRegistry,
    salts.policyRegistry,
  );
  constructorCalldata.obligationRegistry = [adminAddress];
  addresses.obligationRegistry = contractAddress(
    artifacts.obligationRegistry.classHash,
    constructorCalldata.obligationRegistry,
    salts.obligationRegistry,
  );
  constructorCalldata.payrollSeal = [
    STRK20_MAINNET_POOL,
    addresses.policyRegistry,
    addresses.obligationRegistry,
    chainId,
  ];
  addresses.payrollSeal = contractAddress(
    artifacts.payrollSeal.classHash,
    constructorCalldata.payrollSeal,
    salts.payrollSeal,
  );
  const declarationStateEntries = await Promise.all(Object.entries(artifacts).map(
    async ([name, artifact]) => [name, await classDeclared(artifact.classHash)],
  ));
  const deploymentStateEntries = await Promise.all(Object.entries(addresses).map(
    async ([name, address]) => [name, await deployedClassHash(address)],
  ));
  const contracts = Object.fromEntries(Object.keys(artifacts).map((name) => [name, {
    address: addresses[name],
    salt: salts[name],
    constructorCalldata: constructorCalldata[name],
    classHash: artifacts[name].classHash,
    compiledClassHash: artifacts[name].compiledClassHash,
    sierraSha256: artifacts[name].sierraSha256,
    casmSha256: artifacts[name].casmSha256,
    classDeclared: Object.fromEntries(declarationStateEntries)[name],
    deployedClassHash: Object.fromEntries(deploymentStateEntries)[name],
  }]));
  for (const [name, contract] of Object.entries(contracts)) {
    if (contract.deployedClassHash && BigInt(contract.deployedClassHash) !== BigInt(contract.classHash)) {
      throw new Error(`${name} predicted address already contains an unexpected class.`);
    }
  }
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    network: "starknet-mainnet",
    chainId,
    rpcUrl,
    adminAddress,
    initialFxPublisherAddress: adminAddress,
    poolAddress: STRK20_MAINNET_POOL,
    uniqueDeployment: false,
    contracts,
  };
}

async function saveJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function loadPlan() {
  const path = process.env.PAYO_MAINNET_PLAN_PATH ?? DEFAULT_PLAN_PATH;
  const plan = JSON.parse(await readFile(path, "utf8"));
  if (plan.network !== "starknet-mainnet" || BigInt(plan.chainId) !== BigInt(MAINNET_CHAIN_ID)) {
    throw new Error("The PAYO deployment plan is not bound to Starknet Mainnet.");
  }
  return { path, plan };
}

function assertPlanMatchesArtifacts(plan, artifacts) {
  if (BigInt(plan.chainId) !== BigInt(MAINNET_CHAIN_ID)) {
    throw new Error("The plan chain ID is not Starknet Mainnet.");
  }
  if (BigInt(plan.poolAddress) !== BigInt(STRK20_MAINNET_POOL)) {
    throw new Error("The plan does not bind the canonical STRK20 Mainnet pool.");
  }
  for (const [name, artifact] of Object.entries(artifacts)) {
    const planned = plan.contracts?.[name];
    if (!planned) throw new Error(`The deployment plan is missing ${name}.`);
    for (const field of [
      "classHash",
      "compiledClassHash",
      "sierraSha256",
      "casmSha256",
    ]) {
      const equal = field.endsWith("Hash")
        ? BigInt(planned[field]) === BigInt(artifact[field])
        : planned[field] === artifact[field];
      if (!equal) {
        throw new Error(`${name} ${field} changed after the Mainnet plan was reviewed. Generate and review a new plan.`);
      }
    }
  }
}

function accountFromEnvironment(expectedAdmin) {
  const deployerAddress = canonicalAddress(
    process.env.PAYO_MAINNET_DEPLOYER_ADDRESS,
    "PAYO_MAINNET_DEPLOYER_ADDRESS",
  );
  const privateKey = process.env.PAYO_MAINNET_DEPLOYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error(
      "PAYO_MAINNET_DEPLOYER_PRIVATE_KEY is required only for the explicit mutation command. Keep it in a temporary secret environment, never in the repository.",
    );
  }
  if (process.env.PAYO_MAINNET_REQUIRE_ADMIN_DEPLOYER !== "false"
    && BigInt(deployerAddress) !== BigInt(expectedAdmin)) {
    throw new Error("The deployer must equal the planned PAYO administrator unless PAYO_MAINNET_REQUIRE_ADMIN_DEPLOYER=false is explicit.");
  }
  return new Account({
    provider,
    address: deployerAddress,
    signer: privateKey,
    cairoVersion: "1",
  });
}

async function waitFor(transactionHash) {
  return provider.waitForTransaction(transactionHash, { retries: 400, retryInterval: 3_000 });
}

async function verifyDeployment(plan) {
  const blockNumber = await provider.getBlockNumber();
  const checks = [];
  for (const [name, planned] of Object.entries(plan.contracts)) {
    const actualClassHash = await deployedClassHash(planned.address, blockNumber);
    checks.push({
      code: `${name}.class_hash`,
      passed: actualClassHash !== null && BigInt(actualClassHash) === BigInt(planned.classHash),
      expected: planned.classHash,
      actual: actualClassHash,
    });
  }
  const artifacts = await readAllPayoDeployArtifacts();
  const contracts = {
    bundle: new Contract({
      abi: artifacts.bundleVerifier.sierra.abi,
      address: plan.contracts.bundleVerifier.address,
      providerOrAccount: provider,
    }),
    policy: new Contract({
      abi: artifacts.policyRegistry.sierra.abi,
      address: plan.contracts.policyRegistry.address,
      providerOrAccount: provider,
    }),
    obligations: new Contract({
      abi: artifacts.obligationRegistry.sierra.abi,
      address: plan.contracts.obligationRegistry.address,
      providerOrAccount: provider,
    }),
    seal: new Contract({
      abi: artifacts.payrollSeal.sierra.abi,
      address: plan.contracts.payrollSeal.address,
      providerOrAccount: provider,
    }),
  };
  if (checks.every(({ passed }) => passed)) {
    const callOptions = { blockIdentifier: blockNumber };
    const bindings = await Promise.all([
      contracts.bundle.call("get_underlying_verifier", [], callOptions),
      contracts.policy.call("get_admin", [], callOptions),
      contracts.policy.call("get_fx_publisher", [], callOptions),
      contracts.obligations.call("get_admin", [], callOptions),
      contracts.seal.call("get_pool", [], callOptions),
      contracts.seal.call("get_catalog_registry", [], callOptions),
      contracts.seal.call("get_obligation_registry", [], callOptions),
    ]);
    const expected = [
      plan.contracts.generatedVerifier.address,
      plan.adminAddress,
      plan.initialFxPublisherAddress,
      plan.adminAddress,
      plan.poolAddress,
      plan.contracts.policyRegistry.address,
      plan.contracts.obligationRegistry.address,
    ];
    const codes = [
      "bundle.underlying_verifier",
      "policy.admin",
      "policy.fx_publisher",
      "obligations.admin",
      "seal.pool",
      "seal.policy_registry",
      "seal.obligation_registry",
    ];
    bindings.forEach((actual, index) => checks.push({
      code: codes[index],
      passed: asScalar(actual, codes[index]) === BigInt(expected[index]),
      expected: num.toHex(BigInt(expected[index])),
      actual: num.toHex(asScalar(actual, codes[index])),
    }));
  }
  return {
    passed: checks.every(({ passed }) => passed),
    verifiedAt: new Date().toISOString(),
    blockNumber,
    chainId: await requireMainnet(),
    checks,
  };
}

if (action === "plan") {
  const adminAddress = canonicalAddress(
    process.env.PAYO_MAINNET_ADMIN_ADDRESS,
    "PAYO_MAINNET_ADMIN_ADDRESS",
  );
  const plan = await createPlan(adminAddress);
  const planPath = process.env.PAYO_MAINNET_PLAN_PATH ?? DEFAULT_PLAN_PATH;
  await saveJson(planPath, plan);
  process.stdout.write(`${JSON.stringify({ planPath, ...plan }, null, 2)}\n`);
}

if (action === "deploy") {
  if (process.env.PAYO_MAINNET_CONFIRM !== DEPLOY_CONFIRMATION) {
    throw new Error(`Refusing Mainnet writes. Set PAYO_MAINNET_CONFIRM=${DEPLOY_CONFIRMATION} only after reviewing the generated plan and fee simulations.`);
  }
  const { path: planPath, plan } = await loadPlan();
  await assertFreshPayoDeployArtifacts();
  await requireMainnet();
  const artifacts = await readAllPayoDeployArtifacts();
  assertPlanMatchesArtifacts(plan, artifacts);
  const account = accountFromEnvironment(plan.adminAddress);
  const declarations = {};
  for (const [name, artifact] of Object.entries(artifacts)) {
    if (await classDeclared(artifact.classHash)) {
      declarations[name] = { classHash: artifact.classHash, transactionHash: null, alreadyDeclared: true };
      continue;
    }
    const fee = await account.estimateDeclareFee({ contract: artifact.sierra, casm: artifact.casm });
    process.stdout.write(`${name} declare simulated fee: ${fee.overall_fee.toString()} FRI\n`);
    const declaration = await account.declare({ contract: artifact.sierra, casm: artifact.casm });
    await waitFor(declaration.transaction_hash);
    if (BigInt(declaration.class_hash) !== BigInt(artifact.classHash)) {
      throw new Error(`${name} declaration returned an unexpected class hash.`);
    }
    declarations[name] = {
      classHash: artifact.classHash,
      transactionHash: declaration.transaction_hash,
      alreadyDeclared: false,
      simulatedFeeFri: fee.overall_fee.toString(),
    };
  }
  const deploymentPayloads = [];
  for (const [name, planned] of Object.entries(plan.contracts)) {
    const actualClassHash = await deployedClassHash(planned.address);
    if (actualClassHash) {
      if (BigInt(actualClassHash) !== BigInt(planned.classHash)) {
        throw new Error(`${name} predicted address contains an unexpected class.`);
      }
      continue;
    }
    deploymentPayloads.push({
      classHash: planned.classHash,
      constructorCalldata: planned.constructorCalldata,
      salt: planned.salt,
      unique: false,
    });
  }
  let deploymentTransactionHash = null;
  let simulatedDeploymentFeeFri = "0";
  if (deploymentPayloads.length > 0) {
    const fee = await account.estimateDeployFee(deploymentPayloads);
    simulatedDeploymentFeeFri = fee.overall_fee.toString();
    process.stdout.write(`PAYO deployment simulated fee: ${simulatedDeploymentFeeFri} FRI\n`);
    const deployment = await account.deployContract(deploymentPayloads);
    deploymentTransactionHash = deployment.transaction_hash;
    await waitFor(deploymentTransactionHash);
  }
  const verification = await verifyDeployment(plan);
  if (!verification.passed) throw new Error("The deployed PAYO topology failed read-back verification.");
  const evidence = {
    schemaVersion: 1,
    network: "starknet-mainnet",
    planPath,
    plan,
    declarations,
    deploymentTransactionHash,
    simulatedDeploymentFeeFri,
    verification,
  };
  const evidencePath = process.env.PAYO_MAINNET_EVIDENCE_PATH ?? DEFAULT_EVIDENCE_PATH;
  await saveJson(evidencePath, evidence);
  process.stdout.write(`${JSON.stringify({ evidencePath, ...evidence }, null, 2)}\n`);
}

if (action === "schedule-baseline") {
  if (process.env.PAYO_MAINNET_CONFIRM !== BASELINE_CONFIRMATION) {
    throw new Error(`Refusing Mainnet writes. Set PAYO_MAINNET_CONFIRM=${BASELINE_CONFIRMATION} only after reviewing the baseline roots and fee simulation.`);
  }
  const { path: planPath, plan } = await loadPlan();
  await assertFreshPayoDeployArtifacts();
  await requireMainnet();
  const artifacts = await readAllPayoDeployArtifacts();
  assertPlanMatchesArtifacts(plan, artifacts);
  const topologyVerification = await verifyDeployment(plan);
  if (!topologyVerification.passed) {
    throw new Error("Refusing baseline scheduling because the deployed PAYO topology is not verified.");
  }
  const account = accountFromEnvironment(plan.adminAddress);
  const policyRoot = canonicalHash(process.env.PAYO_POLICY_ROOT, "PAYO_POLICY_ROOT");
  const { high: rootHigh, low: rootLow } = (() => {
    const rootValue = BigInt(policyRoot);
    return { high: rootValue >> 128n, low: rootValue & ((1n << 128n) - 1n) };
  })();
  const latest = await provider.getBlock("latest");
  const validAfter = Number(latest.timestamp);
  const expiresAt = validAfter + 365 * 24 * 60 * 60;
  const calls = [
    {
      contractAddress: plan.contracts.policyRegistry.address,
      entrypoint: "schedule_policy_root",
      calldata: [rootHigh, rootLow, validAfter, expiresAt],
    },
    {
      contractAddress: plan.contracts.policyRegistry.address,
      entrypoint: "schedule_verifier",
      calldata: [0, 1, plan.contracts.bundleVerifier.address, validAfter, expiresAt],
    },
  ];
  const fee = await account.estimateInvokeFee(calls);
  process.stdout.write(`PAYO baseline scheduling simulated fee: ${fee.overall_fee.toString()} FRI\n`);
  const scheduled = await account.execute(calls);
  await waitFor(scheduled.transaction_hash);
  const policyRegistry = new Contract({
    abi: artifacts.policyRegistry.sierra.abi,
    address: plan.contracts.policyRegistry.address,
    providerOrAccount: provider,
  });
  const [policyActive, verifierActive] = await Promise.all([
    policyRegistry.call("is_policy_root_valid", [rootHigh, rootLow]),
    policyRegistry.call("is_verifier_valid", [0, 1]),
  ]);
  if (asScalar(policyActive, "policy root activation") === 0n
    || asScalar(verifierActive, "verifier activation") === 0n) {
    throw new Error("The PAYO baseline confirmed but did not activate immediately.");
  }
  const result = {
    schemaVersion: 1,
    network: "starknet-mainnet",
    planPath,
    policyRoot,
    verifierMode: 0,
    proofVersion: 1,
    verifierAddress: plan.contracts.bundleVerifier.address,
    validAfter,
    expiresAt,
    transactionHash: scheduled.transaction_hash,
    simulatedFeeFri: fee.overall_fee.toString(),
    activated: true,
  };
  const evidencePath = process.env.PAYO_MAINNET_EVIDENCE_PATH ?? DEFAULT_EVIDENCE_PATH;
  let deploymentEvidence = {};
  try {
    deploymentEvidence = JSON.parse(await readFile(evidencePath, "utf8"));
  } catch (error) {
    if (!/ENOENT/.test(normalizeError(error))) throw error;
  }
  await saveJson(evidencePath, {
    ...deploymentEvidence,
    schemaVersion: 1,
    network: "starknet-mainnet",
    planPath,
    plan,
    verification: topologyVerification,
    baseline: result,
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (action === "verify") {
  const { plan } = await loadPlan();
  const verification = await verifyDeployment(plan);
  if (!verification.passed) process.exitCode = 1;
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
}
