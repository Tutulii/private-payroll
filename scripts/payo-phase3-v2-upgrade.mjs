import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Account,
  RpcProvider,
  constants,
  num,
  uint256,
  validateAndParseAddress,
} from "starknet";
import {
  assertFreshPayoPhase3DeployArtifacts,
  readPayoPhase3DeployArtifact,
  repositoryRoot,
} from "./lib/payo-contract-artifacts.mjs";
import {
  assertPayoPhase3V2UpgradePlan,
  assertV2UpgradeProofSummary,
  buildPayoPhase3V2UpgradePlan,
  v2UpgradeDeploymentPayloads,
} from "./lib/payo-phase3-v2-upgrade.mjs";

const DEFAULT_RPC_URL = "https://api.cartridge.gg/x/starknet/mainnet";
const STRK_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const LIVE_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-multitenant-mainnet-deployment.json",
);
const PLAN_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-phase3-v2-upgrade-plan.json",
);
const EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-phase3-v2-upgrade-deployment.json",
);
const PUBLIC_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "evidence/phase3-v2-mainnet-upgrade.json",
);
const PROOF_DIRECTORY = resolve(
  repositoryRoot,
  process.env.PAYO_PHASE3_V2_PROOF_DIRECTORY
    ?? "evidence/phase3-mainnet-v2-fixtures",
);
const PROOF_SUMMARY_PATH = resolve(PROOF_DIRECTORY, "advanced-proof.json");
const ACTIONS = new Set([
  "plan",
  "status",
  "estimate-declare",
  "declare",
  "estimate-deploy",
  "deploy",
  "verify-proof",
  "estimate-activate",
  "activate",
  "verify",
]);
const action = process.argv[2];
if (!ACTIONS.has(action)) {
  throw new Error(
    "Usage: node scripts/payo-phase3-v2-upgrade.mjs "
      + "<plan|status|estimate-declare|declare|estimate-deploy|deploy|verify-proof|estimate-activate|activate|verify>",
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

function sameHex(left, right) {
  return BigInt(left) === BigInt(right);
}

function isMissingClass(error) {
  return /class hash not found|undeclared class|class_hash_not_found/i.test(normalizeError(error));
}

function isMissingContract(error) {
  return /contract not found|contract_address_not_found|uninitialized contract/i.test(normalizeError(error));
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
    throw new Error(`Refusing v2 upgrade: RPC reports non-Mainnet chain ${chainId}.`);
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

function accountFromEnvironment(expectedAddress) {
  const address = canonicalAddress(
    process.env.PAYO_PROOF_RELAYER_ADDRESS,
    "PAYO_PROOF_RELAYER_ADDRESS",
  );
  if (!sameHex(address, expectedAddress)) {
    throw new Error("The configured deployment account does not match the reviewed live topology.");
  }
  const privateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error("PAYO_PROOF_RELAYER_PRIVATE_KEY is required for fee simulation or mutation.");
  }
  return new Account({ provider, address, signer: privateKey, cairoVersion: "1" });
}

async function waitFor(transactionHash) {
  return provider.waitForTransaction(transactionHash, { retries: 400, retryInterval: 3_000 });
}

async function loadContext() {
  await assertFreshPayoPhase3DeployArtifacts();
  const [liveEvidence, advancedVerifierArtifact, integrityBundleArtifact] = await Promise.all([
    readJson(LIVE_EVIDENCE_PATH),
    readPayoPhase3DeployArtifact("advancedVerifier"),
    readPayoPhase3DeployArtifact("integrityBundle"),
  ]);
  if (!liveEvidence.plan || liveEvidence.verification?.passed !== true) {
    throw new Error("The tenant-aware Mainnet topology lacks passing read-back evidence.");
  }
  return {
    liveEvidence,
    advancedVerifierArtifact,
    integrityBundleArtifact,
  };
}

async function loadReviewedPlan(context) {
  const plan = await readJson(PLAN_PATH);
  assertPayoPhase3V2UpgradePlan(plan, {
    livePlan: context.liveEvidence.plan,
    liveVerification: context.liveEvidence.verification,
    advancedVerifierArtifact: context.advancedVerifierArtifact,
    integrityBundleArtifact: context.integrityBundleArtifact,
  });
  return plan;
}

async function assertLiveTopology(plan, blockIdentifier = "latest") {
  const chainId = await requireMainnet();
  if (!sameHex(chainId, plan.chainId)) {
    throw new Error("The reviewed v2 plan is bound to another chain.");
  }
  const checks = [];
  for (const name of ["policyRegistry", "obligationRegistry", "payrollSeal"]) {
    const expected = plan.liveTopology[name];
    const actual = await deployedClassHash(expected.address, blockIdentifier);
    checks.push({
      name,
      passed: actual !== null && sameHex(actual, expected.classHash),
      expected: expected.classHash,
      actual,
    });
  }
  if (!checks.every(({ passed }) => passed)) {
    throw new Error("A tenant-aware Mainnet contract failed class-hash read-back.");
  }
  return checks;
}

async function readUpgradeStatus(plan) {
  const blockNumber = await provider.getBlockNumber();
  const [verifierClass, bundleClass, activeVerifier, active] = await Promise.all([
    deployedClassHash(plan.contracts.advancedVerifier.address, blockNumber),
    deployedClassHash(plan.contracts.advancedBundle.address, blockNumber),
    provider.callContract({
      contractAddress: plan.liveTopology.policyRegistry.address,
      entrypoint: "get_verifier",
      calldata: ["0", "2"],
    }, blockNumber),
    provider.callContract({
      contractAddress: plan.liveTopology.policyRegistry.address,
      entrypoint: "is_verifier_valid",
      calldata: ["0", "2"],
    }, blockNumber),
  ]);
  for (const [label, actual, expected] of [
    ["advanced verifier", verifierClass, plan.contracts.advancedVerifier.classHash],
    ["advanced bundle", bundleClass, plan.contracts.advancedBundle.classHash],
  ]) {
    if (actual && !sameHex(actual, expected)) {
      throw new Error(`The planned ${label} address contains an unexpected class.`);
    }
  }
  return {
    observedAt: new Date().toISOString(),
    blockNumber,
    declarationComplete: await classDeclared(plan.contracts.advancedVerifier.classHash),
    verifierDeployed: verifierClass !== null,
    bundleDeployed: bundleClass !== null,
    activeBundle: num.toHex(BigInt(activeVerifier[0] ?? 0)),
    expectedBundleActive:
      BigInt(active[0] ?? 0) !== 0n
      && sameHex(activeVerifier[0] ?? 0, plan.contracts.advancedBundle.address),
  };
}

async function updateEvidence(plan, change) {
  const current = await readJsonIfExists(EVIDENCE_PATH, {
    schemaVersion: 1,
    network: "starknet-mainnet",
    plan,
  });
  const next = { ...(await change(current)), updatedAt: new Date().toISOString() };
  await Promise.all([
    saveJson(EVIDENCE_PATH, next),
    saveJson(PUBLIC_EVIDENCE_PATH, {
      ...next,
      plan: {
        ...next.plan,
        source: "circuits/payroll_integrity/target/payo-phase3-v2-upgrade-plan.json",
      },
    }),
  ]);
}

function parseProof(text, label) {
  const proof = text.trim().split(/\s+/);
  if (proof.length === 0 || proof.some((felt) => !/^0x[0-9a-fA-F]+$/.test(felt))) {
    throw new Error(`${label} contains malformed proof calldata.`);
  }
  return proof;
}

function decodeVerifierInputs(result, label) {
  if (result[0] !== "0x0" || BigInt(result[1] ?? 0) !== 17n || result.length !== 36) {
    throw new Error(`${label} did not return Result::Ok with 17 public inputs.`);
  }
  return Array.from({ length: 17 }, (_, index) =>
    BigInt(result[2 + index * 2]) + (BigInt(result[3 + index * 2]) << 128n));
}

async function verifyProof(plan) {
  const status = await readUpgradeStatus(plan);
  if (!status.verifierDeployed || !status.bundleDeployed) {
    throw new Error("The merged v2 verifier topology must be deployed before proof verification.");
  }
  const [summary, ...proofTexts] = await Promise.all([
    readJson(PROOF_SUMMARY_PATH),
    ...[0, 1].map((shardIndex) => readFile(
      resolve(PROOF_DIRECTORY, `advanced-shard-${shardIndex}.txt`),
      "utf8",
    )),
  ]);
  assertV2UpgradeProofSummary(plan, summary);
  if (
    summary.circuitSha256 !== plan.circuit.circuitSha256
    || !Array.isArray(summary.shards)
    || summary.shards.length !== 2
  ) {
    throw new Error("The committed merged-v2 proof fixture does not match the reviewed circuit.");
  }
  const commonPublicInputs = summary.shards[0]?.publicInputs;
  if (
    BigInt(commonPublicInputs?.chainId ?? 0) !== BigInt(plan.chainId)
    || BigInt(commonPublicInputs?.sealAddress ?? 0) !== BigInt(plan.liveTopology.payrollSeal.address)
    || BigInt(commonPublicInputs?.proofVersion ?? 0) !== 2n
  ) {
    throw new Error("The merged-v2 proof fixture is not bound to the live tenant-aware Mainnet topology.");
  }
  const checks = [];
  for (const shardIndex of [0, 1]) {
    const publicInputs = summary.shards[shardIndex]?.publicInputs;
    if (
      BigInt(publicInputs?.chainId ?? 0) !== BigInt(plan.chainId)
      || BigInt(publicInputs?.sealAddress ?? 0) !== BigInt(plan.liveTopology.payrollSeal.address)
      || BigInt(publicInputs?.proofVersion ?? 0) !== 2n
      || BigInt(publicInputs?.shardIndex ?? -1) !== BigInt(shardIndex)
    ) {
      throw new Error(`Merged v2 shard ${shardIndex} has incorrect deployment-bound public inputs.`);
    }
    for (const name of Object.keys(commonPublicInputs).filter((name) => name !== "shardIndex")) {
      if (BigInt(publicInputs[name]) !== BigInt(commonPublicInputs[name])) {
        throw new Error(`Merged v2 shard ${shardIndex} disagrees on public input ${name}.`);
      }
    }
    const proof = parseProof(proofTexts[shardIndex], `merged v2 shard ${shardIndex}`);
    if (
      proof.length > plan.circuit.maximumProofCalldataFelts
      || proof.length !== plan.circuit.measuredProofCalldataFelts
    ) {
      throw new Error(`Merged v2 shard ${shardIndex} violates the reviewed calldata budget.`);
    }
    const result = await provider.callContract({
      contractAddress: plan.contracts.advancedBundle.address,
      entrypoint: "verify_payroll_integrity_shard",
      calldata: [proof.length.toString(), ...proof],
    }, "latest");
    const inputs = decodeVerifierInputs(result, `merged v2 shard ${shardIndex}`);
    if (inputs[2] !== 2n || inputs[16] !== BigInt(shardIndex)) {
      throw new Error(`Merged v2 shard ${shardIndex} returned the wrong version or shard index.`);
    }
    const tampered = [...proof];
    tampered[2] = num.toHex(BigInt(tampered[2]) ^ 1n);
    let tamperRejected = false;
    try {
      const tamperedResult = await provider.callContract({
        contractAddress: plan.contracts.advancedBundle.address,
        entrypoint: "verify_payroll_integrity_shard",
        calldata: [tampered.length.toString(), ...tampered],
      }, "latest");
      tamperRejected = tamperedResult[0] !== "0x0";
    } catch {
      tamperRejected = true;
    }
    if (!tamperRejected) throw new Error(`Merged v2 shard ${shardIndex} accepted tampered calldata.`);
    checks.push({ shardIndex, calldataFelts: proof.length, tamperRejected: true });
  }
  return {
    passed: true,
    observedAt: new Date().toISOString(),
    circuitSha256: summary.circuitSha256,
    bundleAddress: plan.contracts.advancedBundle.address,
    checks,
  };
}

async function activationCall(plan) {
  const block = await provider.getBlock("latest");
  const validAfter = Number(block.timestamp);
  const expiresAt = validAfter + 365 * 24 * 60 * 60;
  return {
    blockNumber: block.block_number,
    validAfter,
    expiresAt,
    call: {
      contractAddress: plan.liveTopology.policyRegistry.address,
      entrypoint: "schedule_verifier",
      calldata: ["0", "2", plan.contracts.advancedBundle.address, validAfter.toString(), expiresAt.toString()],
    },
  };
}

const context = await loadContext();
await requireMainnet();

if (action === "plan") {
  const plan = buildPayoPhase3V2UpgradePlan({
    livePlan: context.liveEvidence.plan,
    liveVerification: context.liveEvidence.verification,
    advancedVerifierArtifact: context.advancedVerifierArtifact,
    integrityBundleArtifact: context.integrityBundleArtifact,
  });
  assertPayoPhase3V2UpgradePlan(plan, {
    livePlan: context.liveEvidence.plan,
    liveVerification: context.liveEvidence.verification,
    advancedVerifierArtifact: context.advancedVerifierArtifact,
    integrityBundleArtifact: context.integrityBundleArtifact,
  });
  await assertLiveTopology(plan);
  await saveJson(PLAN_PATH, plan);
  process.stdout.write(`${JSON.stringify({ planPath: PLAN_PATH, plan }, null, 2)}\n`);
  process.exit(0);
}

const plan = await loadReviewedPlan(context);
await assertLiveTopology(plan);

if (action === "status") {
  const [status, balanceFri] = await Promise.all([
    readUpgradeStatus(plan),
    readBalance(plan.deployerAddress),
  ]);
  process.stdout.write(`${JSON.stringify({
    planPath: PLAN_PATH,
    balanceFri: balanceFri.toString(),
    balanceStrk: Number(balanceFri) / 1e18,
    status,
  }, null, 2)}\n`);
  process.exit(0);
}

const account = [
  "estimate-declare",
  "declare",
  "estimate-deploy",
  "deploy",
  "estimate-activate",
  "activate",
].includes(action) ? accountFromEnvironment(plan.deployerAddress) : null;

if (action === "estimate-declare") {
  if (await classDeclared(plan.contracts.advancedVerifier.classHash)) {
    process.stdout.write(`${JSON.stringify({ alreadyDeclared: true, feeFri: "0", feeStrk: 0 }, null, 2)}\n`);
    process.exit(0);
  }
  const fee = await account.estimateDeclareFee({
    contract: context.advancedVerifierArtifact.sierra,
    casm: context.advancedVerifierArtifact.casm,
  });
  const balanceFri = await readBalance(plan.deployerAddress);
  process.stdout.write(`${JSON.stringify({
    observedAt: new Date().toISOString(),
    classHash: plan.contracts.advancedVerifier.classHash,
    feeFri: fee.overall_fee.toString(),
    feeStrk: Number(fee.overall_fee) / 1e18,
    balanceFri: balanceFri.toString(),
    balanceStrk: Number(balanceFri) / 1e18,
    currentlyFunded: balanceFri >= BigInt(fee.overall_fee),
  }, null, 2)}\n`);
  process.exit(0);
}

if (action === "declare") {
  if (process.env.PAYO_PHASE3_V2_CONFIRM !== "DECLARE_PAYO_PHASE3_MERGED_V2_MAINNET") {
    throw new Error("Refusing declaration without PAYO_PHASE3_V2_CONFIRM=DECLARE_PAYO_PHASE3_MERGED_V2_MAINNET.");
  }
  if (await classDeclared(plan.contracts.advancedVerifier.classHash)) {
    process.stdout.write("The merged v2 verifier class is already declared.\n");
    process.exit(0);
  }
  const fee = await account.estimateDeclareFee({
    contract: context.advancedVerifierArtifact.sierra,
    casm: context.advancedVerifierArtifact.casm,
  });
  const balanceFri = await readBalance(plan.deployerAddress);
  if (balanceFri < BigInt(fee.overall_fee)) {
    throw new Error(`Declaration requires ${fee.overall_fee} FRI; deployment wallet has ${balanceFri} FRI.`);
  }
  const submitted = await account.declare({
    contract: context.advancedVerifierArtifact.sierra,
    casm: context.advancedVerifierArtifact.casm,
  });
  await waitFor(submitted.transaction_hash);
  if (!(await classDeclared(plan.contracts.advancedVerifier.classHash))) {
    throw new Error("The merged v2 verifier declaration failed read-back.");
  }
  const receipt = await provider.getTransactionReceipt(submitted.transaction_hash);
  const declaration = {
    transactionHash: submitted.transaction_hash,
    classHash: plan.contracts.advancedVerifier.classHash,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: BigInt(receipt.actual_fee?.amount ?? 0).toString(),
    blockNumber: receipt.block_number,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, declaration }));
  process.stdout.write(`${JSON.stringify(declaration, null, 2)}\n`);
  process.exit(0);
}

async function pendingDeployments() {
  const pending = [];
  for (const item of v2UpgradeDeploymentPayloads(plan)) {
    const actual = await deployedClassHash(item.address);
    if (actual) {
      if (!sameHex(actual, plan.contracts[item.name].classHash)) {
        throw new Error(`${item.name} address contains an unexpected class.`);
      }
    } else {
      pending.push(item);
    }
  }
  return pending;
}

if (action === "estimate-deploy" || action === "deploy") {
  if (!(await classDeclared(plan.contracts.advancedVerifier.classHash))) {
    throw new Error("Declare the reviewed merged-v2 verifier class before deployment simulation.");
  }
  const pending = await pendingDeployments();
  if (pending.length === 0) {
    process.stdout.write(`${JSON.stringify({ alreadyDeployed: true, feeFri: "0", feeStrk: 0 }, null, 2)}\n`);
    process.exit(0);
  }
  const fee = await account.estimateDeployFee(pending.map(({ payload }) => payload));
  const balanceFri = await readBalance(plan.deployerAddress);
  if (action === "estimate-deploy") {
    process.stdout.write(`${JSON.stringify({
      observedAt: new Date().toISOString(),
      names: pending.map(({ name }) => name),
      feeFri: fee.overall_fee.toString(),
      feeStrk: Number(fee.overall_fee) / 1e18,
      balanceFri: balanceFri.toString(),
      balanceStrk: Number(balanceFri) / 1e18,
      currentlyFunded: balanceFri >= BigInt(fee.overall_fee),
    }, null, 2)}\n`);
    process.exit(0);
  }
  if (process.env.PAYO_PHASE3_V2_CONFIRM !== "DEPLOY_PAYO_PHASE3_MERGED_V2_MAINNET") {
    throw new Error("Refusing deployment without PAYO_PHASE3_V2_CONFIRM=DEPLOY_PAYO_PHASE3_MERGED_V2_MAINNET.");
  }
  if (balanceFri < BigInt(fee.overall_fee)) {
    throw new Error(`Deployment requires ${fee.overall_fee} FRI; deployment wallet has ${balanceFri} FRI.`);
  }
  const submitted = await account.deployContract(pending.map(({ payload }) => payload));
  await waitFor(submitted.transaction_hash);
  for (const item of pending) {
    const actual = await deployedClassHash(item.address);
    if (!actual || !sameHex(actual, plan.contracts[item.name].classHash)) {
      throw new Error(`${item.name} failed post-deployment class-hash verification.`);
    }
  }
  const receipt = await provider.getTransactionReceipt(submitted.transaction_hash);
  const deployment = {
    names: pending.map(({ name }) => name),
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: BigInt(receipt.actual_fee?.amount ?? 0).toString(),
    blockNumber: receipt.block_number,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, deployment }));
  process.stdout.write(`${JSON.stringify(deployment, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify-proof") {
  const proofVerification = await verifyProof(plan);
  await updateEvidence(plan, async (evidence) => ({ ...evidence, proofVerification }));
  process.stdout.write(`${JSON.stringify(proofVerification, null, 2)}\n`);
  process.exit(0);
}

if (action === "estimate-activate" || action === "activate") {
  const proofVerification = await verifyProof(plan);
  const activation = await activationCall(plan);
  const policyAdmin = await provider.callContract({
    contractAddress: plan.liveTopology.policyRegistry.address,
    entrypoint: "get_admin",
    calldata: [],
  }, "latest");
  if (!sameHex(policyAdmin[0] ?? 0, plan.deployerAddress)) {
    throw new Error("The reviewed deployment account is not the live policy-registry administrator.");
  }
  const fee = await account.estimateInvokeFee([activation.call]);
  const balanceFri = await readBalance(plan.deployerAddress);
  if (action === "estimate-activate") {
    process.stdout.write(`${JSON.stringify({
      proofVerification,
      validAfter: activation.validAfter,
      expiresAt: activation.expiresAt,
      feeFri: fee.overall_fee.toString(),
      feeStrk: Number(fee.overall_fee) / 1e18,
      balanceFri: balanceFri.toString(),
      balanceStrk: Number(balanceFri) / 1e18,
      currentlyFunded: balanceFri >= BigInt(fee.overall_fee),
    }, null, 2)}\n`);
    process.exit(0);
  }
  if (process.env.PAYO_PHASE3_V2_CONFIRM !== "ACTIVATE_PAYO_PHASE3_MERGED_V2_MAINNET") {
    throw new Error("Refusing activation without PAYO_PHASE3_V2_CONFIRM=ACTIVATE_PAYO_PHASE3_MERGED_V2_MAINNET.");
  }
  if (balanceFri < BigInt(fee.overall_fee)) {
    throw new Error(`Activation requires ${fee.overall_fee} FRI; deployment wallet has ${balanceFri} FRI.`);
  }
  const submitted = await account.execute([activation.call]);
  await waitFor(submitted.transaction_hash);
  const status = await readUpgradeStatus(plan);
  if (!status.expectedBundleActive) {
    throw new Error("The merged-v2 verifier mapping failed post-activation read-back.");
  }
  const receipt = await provider.getTransactionReceipt(submitted.transaction_hash);
  const activationEvidence = {
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: BigInt(receipt.actual_fee?.amount ?? 0).toString(),
    blockNumber: receipt.block_number,
    validAfter: activation.validAfter,
    expiresAt: activation.expiresAt,
    activeBundle: status.activeBundle,
  };
  await updateEvidence(plan, async (evidence) => ({
    ...evidence,
    proofVerification,
    activation: activationEvidence,
  }));
  process.stdout.write(`${JSON.stringify(activationEvidence, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify") {
  const [status, proofVerification] = await Promise.all([
    readUpgradeStatus(plan),
    verifyProof(plan),
  ]);
  const passed =
    status.declarationComplete
    && status.verifierDeployed
    && status.bundleDeployed
    && status.expectedBundleActive
    && proofVerification.passed;
  if (!passed) throw new Error("The merged-v2 Mainnet upgrade is not fully active and verified.");
  const verification = { passed, observedAt: new Date().toISOString(), status, proofVerification };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, verification }));
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
}
