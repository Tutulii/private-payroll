import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Account,
  RpcProvider,
  constants,
  ec,
  num,
  uint256,
  validateAndParseAddress,
} from "starknet";
import {
  assertFreshPayoPhase4DeployArtifacts,
  readAllPayoPhase4DeployArtifacts,
  repositoryRoot,
} from "./lib/payo-contract-artifacts.mjs";
import {
  assertPayoPhase4MainnetPlan,
  buildPayoPhase4MainnetPlan,
  phase4DeploymentPayloads,
} from "./lib/payo-phase4-mainnet.mjs";

const DEFAULT_RPC_URL = "https://api.cartridge.gg/x/starknet/mainnet";
const STRK_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const DEFAULT_MUTATION_TIP = 1n;
const MAX_MUTATION_TIP = 1_000_000n;
const LIVE_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-multitenant-mainnet-deployment.json",
);
const PLAN_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-phase4-mainnet-plan.json",
);
const EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-phase4-mainnet-deployment.json",
);
const PUBLIC_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "evidence/phase4-mainnet-deployment.json",
);
const PROOF_PATH = resolve(
  repositoryRoot,
  "contracts/settlement_verifier_v8/tests/proof_calldata.txt",
);
const CONTRACT_NAMES = Object.freeze([
  "settlementVerifier",
  "payrollSeal",
  "policyAccount",
]);
const ACTIONS = new Set([
  "plan",
  "status",
  "estimate",
  "declare",
  "deploy",
  "verify-proof",
  "activate",
  "verify",
]);
const action = process.argv[2];
if (!ACTIONS.has(action)) {
  throw new Error(
    "Usage: node scripts/payo-phase4-mainnet.mjs "
      + "<plan|status|estimate|declare|deploy|verify-proof|activate|verify>",
  );
}

const provider = new RpcProvider({
  nodeUrl: process.env.STARKNET_RPC_URL
    ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL
    ?? DEFAULT_RPC_URL,
});

function normalizeError(error) {
  return error instanceof Error ? error.message : String(error);
}

function submissionError(error) {
  return {
    name: error?.name ?? "Error",
    code: error?.code ?? null,
    message: normalizeError(error),
    rpcError: error?.baseError ?? error?.response?.data?.error ?? null,
  };
}

function mutationTip() {
  const raw = process.env.PAYO_PHASE4_MAINNET_TIP ?? DEFAULT_MUTATION_TIP.toString();
  if (!/^\d+$/.test(raw)) {
    throw new Error("PAYO_PHASE4_MAINNET_TIP must be an unsigned integer.");
  }
  const tip = BigInt(raw);
  if (tip < 1n || tip > MAX_MUTATION_TIP) {
    throw new Error(`PAYO_PHASE4_MAINNET_TIP must be between 1 and ${MAX_MUTATION_TIP}.`);
  }
  return tip;
}

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

function canonicalFelt(value, label) {
  try {
    const felt = BigInt(value);
    if (felt <= 0n) throw new Error();
    return num.toHex(felt);
  } catch {
    throw new Error(`${label} must be a non-zero Starknet felt.`);
  }
}

function sameHex(left, right) {
  return BigInt(left) === BigInt(right);
}

function isMissingClass(error) {
  return /class hash not found|undeclared class|class_hash_not_found/i
    .test(normalizeError(error));
}

function isMissingContract(error) {
  return /contract not found|contract_address_not_found|uninitialized contract/i
    .test(normalizeError(error));
}

function formatStrk(fri) {
  return Number(fri) / 1e18;
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function readJsonIfExists(path, fallback) {
  try {
    return await readJson(path);
  } catch (error) {
    if (error?.code === "ENOENT") return fallback;
    throw error;
  }
}

async function saveJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function requireMainnet() {
  const chainId = await provider.getChainId();
  if (BigInt(chainId) !== BigInt(constants.StarknetChainId.SN_MAIN)) {
    throw new Error(`Refusing Phase 4 deployment: RPC reports non-Mainnet chain ${chainId}.`);
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

async function readBalance(address) {
  const result = await provider.callContract({
    contractAddress: STRK_ADDRESS,
    entrypoint: "balance_of",
    calldata: [address],
  }, "latest");
  return uint256.uint256ToBN({ low: result[0], high: result[1] });
}

function policyOwnerPublicKey() {
  if (process.env.PAYO_PHASE4_POLICY_OWNER_PUBLIC_KEY) {
    return canonicalFelt(
      process.env.PAYO_PHASE4_POLICY_OWNER_PUBLIC_KEY,
      "PAYO_PHASE4_POLICY_OWNER_PUBLIC_KEY",
    );
  }
  const privateKey = process.env.PAYO_PHASE4_POLICY_OWNER_PRIVATE_KEY
    ?? process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error(
      "PAYO_PHASE4_POLICY_OWNER_PUBLIC_KEY or a policy-owner private key is required.",
    );
  }
  return canonicalFelt(ec.starkCurve.getStarkKey(privateKey), "Derived policy owner public key");
}

function accountFromEnvironment(expectedAddress) {
  const address = canonicalAddress(
    process.env.PAYO_PROOF_RELAYER_ADDRESS,
    "PAYO_PROOF_RELAYER_ADDRESS",
  );
  if (!sameHex(address, expectedAddress)) {
    throw new Error("The configured deployment account does not match the reviewed topology.");
  }
  const privateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error("PAYO_PROOF_RELAYER_PRIVATE_KEY is required for simulation or mutation.");
  }
  return new Account({ provider, address, signer: privateKey, cairoVersion: "1" });
}

async function waitFor(transactionHash) {
  return provider.waitForTransaction(transactionHash, {
    retries: 400,
    retryInterval: 3_000,
  });
}

async function waitForPostcondition(transactionHash, label, postcondition) {
  try {
    return { receipt: await waitFor(transactionHash), recoveredFromWaitError: false };
  } catch (waitError) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      if (await postcondition()) {
        try {
          return {
            receipt: await provider.getTransactionReceipt(transactionHash),
            recoveredFromWaitError: true,
          };
        } catch {
          // Some RPC nodes expose deterministic state before the receipt.
        }
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 3_000));
    }
    throw new Error(
      `${label} did not reach its on-chain postcondition after the RPC wait failed: `
        + normalizeError(waitError),
    );
  }
}

function actualFee(receipt) {
  return BigInt(receipt.actual_fee?.amount ?? 0).toString();
}

async function loadContext() {
  await assertFreshPayoPhase4DeployArtifacts();
  const [liveEvidence, artifacts] = await Promise.all([
    readJson(LIVE_EVIDENCE_PATH),
    readAllPayoPhase4DeployArtifacts(),
  ]);
  if (!liveEvidence.plan || liveEvidence.verification?.passed !== true) {
    throw new Error("The tenant-aware Mainnet topology lacks passing read-back evidence.");
  }
  return {
    livePlan: liveEvidence.plan,
    liveVerification: liveEvidence.verification,
    artifacts,
    policyOwnerPublicKey: policyOwnerPublicKey(),
  };
}

async function loadReviewedPlan(context) {
  const plan = await readJson(PLAN_PATH);
  assertPayoPhase4MainnetPlan(plan, context);
  return plan;
}

async function assertLiveDependencies(plan, blockIdentifier = "latest") {
  const chainId = await requireMainnet();
  if (!sameHex(chainId, plan.chainId)) {
    throw new Error("The reviewed Phase 4 plan is bound to another chain.");
  }
  const checks = [];
  for (const name of ["pool", "policyRegistry", "obligationRegistry", "previousPayrollSeal"]) {
    const expected = plan.dependencies[name];
    const actual = await deployedClassHash(expected.address, blockIdentifier);
    checks.push({
      name,
      expectedClassHash: expected.classHash,
      actualClassHash: actual,
      passed: actual !== null && sameHex(actual, expected.classHash),
    });
  }
  const adminResult = await provider.callContract({
    contractAddress: plan.dependencies.policyRegistry.address,
    entrypoint: "get_admin",
    calldata: [],
  }, blockIdentifier);
  checks.push({
    name: "policyAdmin",
    expectedAddress: plan.deployerAddress,
    actualAddress: num.toHex(BigInt(adminResult[0] ?? 0)),
    passed: sameHex(adminResult[0] ?? 0, plan.deployerAddress),
  });
  const ownerResult = await provider.callContract({
    contractAddress: plan.deployerAddress,
    entrypoint: "get_public_key",
    calldata: [],
  }, blockIdentifier);
  checks.push({
    name: "policyOwnerKey",
    expectedPublicKey: plan.contracts.policyAccount.ownerPublicKey,
    actualPublicKey: num.toHex(BigInt(ownerResult[0] ?? 0)),
    passed: sameHex(ownerResult[0] ?? 0, plan.contracts.policyAccount.ownerPublicKey),
  });
  if (!checks.every(({ passed }) => passed)) {
    throw new Error("A Phase 4 Mainnet dependency failed class-hash or admin read-back.");
  }
  return checks;
}

async function verifierProfile(plan, blockIdentifier = "latest") {
  const profile = plan.verifierProfile;
  const registry = plan.dependencies.policyRegistry.address;
  const valid = await provider.callContract({
    contractAddress: registry,
    entrypoint: "is_verifier_valid",
    calldata: [profile.mode.toString(), profile.proofVersion.toString()],
  }, blockIdentifier);
  const active = BigInt(valid[0] ?? 0) !== 0n;
  let address = null;
  if (active) {
    const result = await provider.callContract({
      contractAddress: registry,
      entrypoint: "get_verifier",
      calldata: [profile.mode.toString(), profile.proofVersion.toString()],
    }, blockIdentifier);
    address = num.toHex(BigInt(result[0]));
    if (!sameHex(address, plan.contracts.settlementVerifier.address)) {
      throw new Error("The active SettlementMatch v8 profile points to an unexpected address.");
    }
  }
  return { ...profile, active, address };
}

async function liveStatus(plan) {
  const blockNumber = await provider.getBlockNumber();
  const declarations = {};
  const contracts = {};
  for (const name of CONTRACT_NAMES) {
    declarations[name] = await classDeclared(plan.contracts[name].classHash);
    const actualClassHash = await deployedClassHash(plan.contracts[name].address, blockNumber);
    if (actualClassHash && !sameHex(actualClassHash, plan.contracts[name].classHash)) {
      throw new Error(`${name} predicted address contains an unexpected Mainnet class.`);
    }
    contracts[name] = {
      address: plan.contracts[name].address,
      expectedClassHash: plan.contracts[name].classHash,
      actualClassHash,
      deployed: actualClassHash !== null,
    };
  }
  return {
    observedAt: new Date().toISOString(),
    blockNumber,
    declarations,
    contracts,
    verifierProfile: await verifierProfile(plan, blockNumber),
  };
}

async function updateEvidence(plan, change) {
  const current = await readJsonIfExists(EVIDENCE_PATH, {
    schemaVersion: 1,
    network: "starknet-mainnet",
    plan,
    declarations: {},
  });
  const next = { ...(await change(current)), updatedAt: new Date().toISOString() };
  await Promise.all([
    saveJson(EVIDENCE_PATH, next),
    saveJson(PUBLIC_EVIDENCE_PATH, {
      ...next,
      plan: {
        ...next.plan,
        source: "circuits/payroll_integrity/target/payo-phase4-mainnet-plan.json",
      },
    }),
  ]);
}

async function activationWindow() {
  const block = await provider.getBlock("latest");
  const validAfter = Number(block.timestamp);
  return {
    blockNumber: block.block_number,
    validAfter,
    expiresAt: validAfter + 365 * 24 * 60 * 60,
  };
}

function activationCall(plan, window) {
  return {
    contractAddress: plan.dependencies.policyRegistry.address,
    entrypoint: "schedule_verifier",
    calldata: [
      plan.verifierProfile.mode.toString(),
      plan.verifierProfile.proofVersion.toString(),
      plan.contracts.settlementVerifier.address,
      window.validAfter.toString(),
      window.expiresAt.toString(),
    ],
  };
}

async function estimateAll(plan, context, account) {
  const status = await liveStatus(plan);
  const tip = mutationTip();
  const estimates = [];
  for (const name of CONTRACT_NAMES) {
    if (status.declarations[name]) continue;
    const fee = await account.estimateDeclareFee({
      contract: context.artifacts[name].sierra,
      casm: context.artifacts[name].casm,
    }, { tip });
    estimates.push({
      label: `declare.${name}`,
      feeFri: fee.overall_fee.toString(),
      feeStrk: formatStrk(fee.overall_fee),
    });
  }
  for (const item of phase4DeploymentPayloads(plan)
    .filter(({ name }) => !status.contracts[name].deployed)) {
    let fee;
    if (status.declarations[item.name]) {
      fee = await account.estimateDeployFee(item.payload, { tip });
    } else {
      const pair = await account.estimateFeeBulk([
        {
          type: "DECLARE",
          payload: {
            contract: context.artifacts[item.name].sierra,
            casm: context.artifacts[item.name].casm,
          },
        },
        { type: "DEPLOY", payload: item.payload },
      ], { tip });
      fee = pair[1];
    }
    estimates.push({
      label: `deploy.${item.name}`,
      feeFri: fee.overall_fee.toString(),
      feeStrk: formatStrk(fee.overall_fee),
    });
  }
  let activation = null;
  if (!status.verifierProfile.active) {
    const window = await activationWindow();
    const fee = await account.estimateInvokeFee(activationCall(plan, window), { tip });
    activation = window;
    estimates.push({
      label: "activate.finalize.v8",
      feeFri: fee.overall_fee.toString(),
      feeStrk: formatStrk(fee.overall_fee),
    });
  }
  const total = estimates.reduce((sum, item) => sum + BigInt(item.feeFri), 0n);
  const balance = await readBalance(plan.deployerAddress);
  return {
    observedAt: new Date().toISOString(),
    status,
    estimates,
    activationWindow: activation,
    totalFeeFri: total.toString(),
    totalFeeStrk: formatStrk(total),
    balanceFri: balance.toString(),
    balanceStrk: formatStrk(balance),
    currentlyFunded: balance >= total,
    mutationTip: tip.toString(),
  };
}

function parseProof(text) {
  const proof = text.trim().split(/\s+/);
  if (proof.length === 0 || proof.some((felt) => !/^0x[0-9a-fA-F]+$/.test(felt))) {
    throw new Error("The SettlementMatch v8 proof fixture is malformed.");
  }
  return proof;
}

function decodeProofResult(result) {
  const count = Number(BigInt(result[1] ?? 0));
  if (result[0] !== "0x0" || count !== 11 || result.length !== 2 + count * 2) {
    throw new Error("The SettlementMatch verifier did not return 11 public inputs.");
  }
  return Array.from({ length: count }, (_, index) =>
    BigInt(result[2 + index * 2]) + (BigInt(result[3 + index * 2]) << 128n));
}

async function verifyProofFixture(plan) {
  const proof = parseProof(await readFile(PROOF_PATH, "utf8"));
  if (
    proof.length !== plan.settlementCircuit.measuredProofCalldataFelts
    || proof.length > plan.settlementCircuit.maximumProofCalldataFelts
  ) {
    throw new Error("The SettlementMatch proof violates the reviewed calldata budget.");
  }
  const request = {
    contractAddress: plan.contracts.settlementVerifier.address,
    entrypoint: "verify_ultra_keccak_zk_honk_proof",
    calldata: [proof.length.toString(), ...proof],
  };
  const startedAt = Date.now();
  const inputs = decodeProofResult(await provider.callContract(request, "latest"));
  if (inputs[0] !== 8n || inputs[9] !== 0n || inputs[10] !== 1n) {
    throw new Error("The SettlementMatch fixture returned incorrect version or chunk bindings.");
  }
  const tampered = [...proof];
  tampered[2] = num.toHex(BigInt(tampered[2]) ^ 1n);
  let tamperRejected = false;
  try {
    const result = await provider.callContract({ ...request, calldata: [
      tampered.length.toString(),
      ...tampered,
    ] }, "latest");
    tamperRejected = result[0] !== "0x0";
  } catch {
    tamperRejected = true;
  }
  if (!tamperRejected) throw new Error("SettlementMatch v8 accepted tampered proof calldata.");
  return {
    passed: true,
    verifierAddress: plan.contracts.settlementVerifier.address,
    calldataFelts: proof.length,
    publicInputCount: inputs.length,
    proofVersion: inputs[0].toString(),
    chunkIndex: inputs[9].toString(),
    chunkCount: inputs[10].toString(),
    tamperRejected,
    durationMs: Date.now() - startedAt,
  };
}

async function verifyDeployedBindings(plan, blockIdentifier) {
  const seal = plan.contracts.payrollSeal.address;
  const [pool, registry, obligations, owner, paused] = await Promise.all([
    provider.callContract({ contractAddress: seal, entrypoint: "get_pool", calldata: [] }, blockIdentifier),
    provider.callContract({ contractAddress: seal, entrypoint: "get_catalog_registry", calldata: [] }, blockIdentifier),
    provider.callContract({ contractAddress: seal, entrypoint: "get_obligation_registry", calldata: [] }, blockIdentifier),
    provider.callContract({ contractAddress: plan.contracts.policyAccount.address, entrypoint: "get_public_key", calldata: [] }, blockIdentifier),
    provider.callContract({ contractAddress: plan.contracts.policyAccount.address, entrypoint: "is_policy_account_paused", calldata: [] }, blockIdentifier),
  ]);
  const checks = [
    ["seal.pool", pool[0], plan.dependencies.pool.address],
    ["seal.policyRegistry", registry[0], plan.dependencies.policyRegistry.address],
    ["seal.obligationRegistry", obligations[0], plan.dependencies.obligationRegistry.address],
    ["policyAccount.owner", owner[0], plan.contracts.policyAccount.ownerPublicKey],
    ["policyAccount.unpaused", paused[0], "0x0"],
  ].map(([code, actual, expected]) => ({
    code,
    actual: num.toHex(BigInt(actual ?? 0)),
    expected: num.toHex(BigInt(expected)),
    passed: sameHex(actual ?? 0, expected),
  }));
  if (!checks.every(({ passed }) => passed)) {
    throw new Error("A deployed Phase 4 constructor or account-state binding is incorrect.");
  }
  return checks;
}

const context = await loadContext();
await requireMainnet();

if (action === "plan") {
  const plan = buildPayoPhase4MainnetPlan(context);
  assertPayoPhase4MainnetPlan(plan, context);
  await assertLiveDependencies(plan);
  await saveJson(PLAN_PATH, plan);
  process.stdout.write(`${JSON.stringify({ planPath: PLAN_PATH, plan }, null, 2)}\n`);
  process.exit(0);
}

const plan = await loadReviewedPlan(context);
await assertLiveDependencies(plan);

if (action === "status") {
  const [status, balance] = await Promise.all([
    liveStatus(plan),
    readBalance(plan.deployerAddress),
  ]);
  process.stdout.write(`${JSON.stringify({
    planPath: PLAN_PATH,
    balanceFri: balance.toString(),
    balanceStrk: formatStrk(balance),
    status,
  }, null, 2)}\n`);
  process.exit(0);
}

const account = accountFromEnvironment(plan.deployerAddress);

if (action === "estimate") {
  process.stdout.write(`${JSON.stringify(await estimateAll(plan, context, account), null, 2)}\n`);
  process.exit(0);
}

if (action === "declare") {
  if (process.env.PAYO_PHASE4_MAINNET_CONFIRM !== "DECLARE_PAYO_PHASE4_MAINNET") {
    throw new Error(
      "Refusing declarations without PAYO_PHASE4_MAINNET_CONFIRM=DECLARE_PAYO_PHASE4_MAINNET.",
    );
  }
  const tip = mutationTip();
  for (const name of CONTRACT_NAMES) {
    const contract = plan.contracts[name];
    if (await classDeclared(contract.classHash)) continue;
    const payload = {
      contract: context.artifacts[name].sierra,
      casm: context.artifacts[name].casm,
    };
    const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
    const fee = await account.estimateDeclareFee(payload, {
      nonce,
      skipValidate: false,
      tip,
    });
    const balance = await readBalance(plan.deployerAddress);
    if (balance < BigInt(fee.overall_fee)) {
      throw new Error(`${name} declaration requires ${fee.overall_fee} FRI; balance is ${balance}.`);
    }
    let submitted;
    try {
      submitted = await account.declare(payload, {
        nonce,
        resourceBounds: fee.resourceBounds,
        tip,
      });
    } catch (error) {
      process.stderr.write(`${JSON.stringify({
        failed: `declare.${name}`,
        nonce: num.toHex(BigInt(nonce)),
        error: submissionError(error),
      }, null, 2)}\n`);
      throw new Error(`${name} declaration submission failed.`);
    }
    const confirmation = await waitForPostcondition(
      submitted.transaction_hash,
      `${name} declaration`,
      () => classDeclared(contract.classHash),
    );
    if (!(await classDeclared(contract.classHash))) {
      throw new Error(`${name} declaration failed class-hash read-back.`);
    }
    const declaration = {
      transactionHash: submitted.transaction_hash,
      classHash: contract.classHash,
      nonce: num.toHex(BigInt(nonce)),
      tip: tip.toString(),
      recoveredFromWaitError: confirmation.recoveredFromWaitError,
      simulatedFeeFri: fee.overall_fee.toString(),
      actualFeeFri: actualFee(confirmation.receipt),
      blockNumber: confirmation.receipt.block_number,
    };
    await updateEvidence(plan, async (evidence) => ({
      ...evidence,
      declarations: { ...evidence.declarations, [name]: declaration },
    }));
    process.stdout.write(`${JSON.stringify({ declared: name, ...declaration })}\n`);
  }
  process.exit(0);
}

if (action === "deploy") {
  for (const name of CONTRACT_NAMES) {
    if (!(await classDeclared(plan.contracts[name].classHash))) {
      throw new Error(`Declare ${name} before deployment.`);
    }
  }
  const status = await liveStatus(plan);
  const pending = phase4DeploymentPayloads(plan)
    .filter(({ name }) => !status.contracts[name].deployed);
  if (pending.length === 0) {
    process.stdout.write(`${JSON.stringify({ alreadyDeployed: true })}\n`);
    process.exit(0);
  }
  if (process.env.PAYO_PHASE4_MAINNET_CONFIRM !== "DEPLOY_PAYO_PHASE4_MAINNET") {
    throw new Error(
      "Refusing deployment without PAYO_PHASE4_MAINNET_CONFIRM=DEPLOY_PAYO_PHASE4_MAINNET.",
    );
  }
  const tip = mutationTip();
  const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
  const payloads = pending.map(({ payload }) => payload);
  const fee = await account.estimateDeployFee(payloads, {
    nonce,
    skipValidate: false,
    tip,
  });
  const balance = await readBalance(plan.deployerAddress);
  if (balance < BigInt(fee.overall_fee)) {
    throw new Error(`Phase 4 deployment requires ${fee.overall_fee} FRI; balance is ${balance}.`);
  }
  const submitted = await account.deploy(payloads, {
    nonce,
    resourceBounds: fee.resourceBounds,
    tip,
  });
  const confirmation = await waitForPostcondition(
    submitted.transaction_hash,
    "Phase 4 contract deployment",
    async () => {
      for (const item of pending) {
        const actual = await deployedClassHash(item.address);
        if (!actual || !sameHex(actual, plan.contracts[item.name].classHash)) return false;
      }
      return true;
    },
  );
  for (const item of pending) {
    const actual = await deployedClassHash(item.address);
    if (!actual || !sameHex(actual, plan.contracts[item.name].classHash)) {
      throw new Error(`${item.name} failed post-deployment class-hash verification.`);
    }
  }
  const deployment = {
    names: pending.map(({ name }) => name),
    transactionHash: submitted.transaction_hash,
    nonce: num.toHex(BigInt(nonce)),
    tip: tip.toString(),
    recoveredFromWaitError: confirmation.recoveredFromWaitError,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: actualFee(confirmation.receipt),
    blockNumber: confirmation.receipt.block_number,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, deployment }));
  process.stdout.write(`${JSON.stringify(deployment, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify-proof") {
  const status = await liveStatus(plan);
  if (!status.contracts.settlementVerifier.deployed) {
    throw new Error("Deploy the SettlementMatch v8 verifier before live proof verification.");
  }
  const proofVerification = await verifyProofFixture(plan);
  await updateEvidence(plan, async (evidence) => ({ ...evidence, proofVerification }));
  process.stdout.write(`${JSON.stringify(proofVerification, null, 2)}\n`);
  process.exit(0);
}

if (action === "activate") {
  const status = await liveStatus(plan);
  if (!Object.values(status.contracts).every(({ deployed }) => deployed)) {
    throw new Error("Deploy all Phase 4 contracts before verifier activation.");
  }
  if (status.verifierProfile.active) {
    process.stdout.write(`${JSON.stringify({ alreadyActive: true })}\n`);
    process.exit(0);
  }
  if (process.env.PAYO_PHASE4_MAINNET_CONFIRM !== "ACTIVATE_PAYO_PHASE4_MAINNET") {
    throw new Error(
      "Refusing activation without PAYO_PHASE4_MAINNET_CONFIRM=ACTIVATE_PAYO_PHASE4_MAINNET.",
    );
  }
  const window = await activationWindow();
  const call = activationCall(plan, window);
  const tip = mutationTip();
  const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
  const fee = await account.estimateInvokeFee(call, {
    nonce,
    skipValidate: false,
    tip,
  });
  const balance = await readBalance(plan.deployerAddress);
  if (balance < BigInt(fee.overall_fee)) {
    throw new Error(`Phase 4 activation requires ${fee.overall_fee} FRI; balance is ${balance}.`);
  }
  const submitted = await account.execute(call, {
    nonce,
    resourceBounds: fee.resourceBounds,
    tip,
  });
  const confirmation = await waitForPostcondition(
    submitted.transaction_hash,
    "SettlementMatch verifier activation",
    async () => (await verifierProfile(plan)).active,
  );
  const active = await verifierProfile(plan);
  if (!active.active) throw new Error("SettlementMatch v8 failed activation read-back.");
  const activation = {
    transactionHash: submitted.transaction_hash,
    nonce: num.toHex(BigInt(nonce)),
    tip: tip.toString(),
    recoveredFromWaitError: confirmation.recoveredFromWaitError,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: actualFee(confirmation.receipt),
    blockNumber: confirmation.receipt.block_number,
    validAfter: window.validAfter,
    expiresAt: window.expiresAt,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, activation }));
  process.stdout.write(`${JSON.stringify(activation, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify") {
  const blockNumber = await provider.getBlockNumber();
  const [dependencies, status] = await Promise.all([
    assertLiveDependencies(plan, blockNumber),
    liveStatus(plan),
  ]);
  if (
    !Object.values(status.declarations).every(Boolean)
    || !Object.values(status.contracts).every(({ deployed }) => deployed)
    || !status.verifierProfile.active
  ) {
    throw new Error("The Phase 4 Mainnet topology is not declared, deployed, and active.");
  }
  const [bindings, proofVerification] = await Promise.all([
    verifyDeployedBindings(plan, blockNumber),
    verifyProofFixture(plan),
  ]);
  const verification = {
    passed: true,
    observedAt: new Date().toISOString(),
    blockNumber,
    dependencies,
    status,
    bindings,
    proofVerification,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, verification }));
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
  process.exit(0);
}
