import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Account,
  Contract,
  RpcProvider,
  constants,
  hash,
  num,
  uint256,
  validateAndParseAddress,
} from "starknet";
import {
  assertFreshPayoPhase3DeployArtifacts,
  readAllPayoPhase3DeployArtifacts,
  repositoryRoot,
} from "./lib/payo-contract-artifacts.mjs";
import {
  PAYO_PHASE3_MAINNET_CHAIN_ID,
  assertPayoPhase3PlanMatchesArtifacts,
  buildPayoPhase3MainnetPlan,
  deploymentPayloads,
  phase3DeclarationOrder,
  phase3VerifierDeploymentOrder,
} from "./lib/payo-phase3-mainnet.mjs";

const DEFAULT_RPC_URL = "https://api.cartridge.gg/x/starknet/mainnet";
const PHASE2_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-mainnet-deployment.json",
);
const DEFAULT_PLAN_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-phase3-mainnet-plan.json",
);
const DEFAULT_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-phase3-mainnet-deployment.json",
);
const DEFAULT_PUBLIC_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "evidence/phase3-mainnet-deployment.json",
);
const PHASE3_ADVANCED_PROOF_DIRECTORY = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/phase3-mainnet-advanced",
);
const PHASE3_EXCEPTION_PROOF_DIRECTORY = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/phase3-mainnet-exceptions",
);
const STRK_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const action = process.argv[2];
const actionArgument = process.argv[3];

if (!["plan", "status", "estimate", "estimate-seal", "declare", "reconcile-declaration", "record-activation", "deploy-profile", "deploy-verifiers", "verify-verifiers", "verify-proofs", "deploy-seal"].includes(action)) {
  throw new Error(
    "Usage: node scripts/payo-phase3-mainnet.mjs "
      + "<plan|status|estimate|declare <name>|reconcile-declaration <name> <tx-hash>"
      + "|deploy-profile <advanced|claim|remediation>|deploy-verifiers|verify-verifiers"
      + "|verify-proofs|estimate-seal|record-activation <tx-hash>|deploy-seal>",
  );
}

const rpcUrl = process.env.STARKNET_RPC_URL
  ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL
  ?? DEFAULT_RPC_URL;
const provider = new RpcProvider({ nodeUrl: rpcUrl });
const planPath = process.env.PAYO_PHASE3_MAINNET_PLAN_PATH ?? DEFAULT_PLAN_PATH;
const evidencePath = process.env.PAYO_PHASE3_MAINNET_EVIDENCE_PATH ?? DEFAULT_EVIDENCE_PATH;
const publicEvidencePath = process.env.PAYO_PHASE3_MAINNET_PUBLIC_EVIDENCE_PATH
  ?? DEFAULT_PUBLIC_EVIDENCE_PATH;

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

function normalizeError(error) {
  return error instanceof Error ? error.message : String(error);
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
    if (/ENOENT/.test(normalizeError(error))) return fallback;
    throw error;
  }
}

async function saveJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function requireMainnet() {
  const chainId = await provider.getChainId();
  if (BigInt(chainId) !== BigInt(constants.StarknetChainId.SN_MAIN)
    || BigInt(chainId) !== BigInt(PAYO_PHASE3_MAINNET_CHAIN_ID)) {
    throw new Error(`Refusing PAYO Phase 3 mutation: RPC reports chain ID ${chainId}.`);
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

async function readRelayerBalance(address) {
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
  if (BigInt(address) !== BigInt(expectedAddress)) {
    throw new Error("The configured relayer does not match the reviewed Phase 3 plan.");
  }
  const privateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error("PAYO_PROOF_RELAYER_PRIVATE_KEY is required only for a confirmed mutation.");
  }
  return new Account({ provider, address, signer: privateKey, cairoVersion: "1" });
}

async function waitFor(transactionHash) {
  return provider.waitForTransaction(transactionHash, { retries: 400, retryInterval: 3_000 });
}

async function loadPhase2Plan() {
  const evidence = await readJson(PHASE2_EVIDENCE_PATH);
  const plan = evidence.plan;
  if (!plan || evidence.verification?.passed !== true) {
    throw new Error("The committed Phase 2 Mainnet topology lacks passing read-back evidence.");
  }
  return plan;
}

async function loadReviewedPlan() {
  const [plan, artifacts] = await Promise.all([
    readJson(planPath),
    readAllPayoPhase3DeployArtifacts(),
  ]);
  assertPayoPhase3PlanMatchesArtifacts(plan, artifacts);
  return { plan, artifacts };
}

async function assertReusedTopology(plan, blockIdentifier = "latest") {
  const checks = [];
  for (const name of ["baseVerifier", "policyRegistry", "obligationRegistry"]) {
    const expected = plan.contracts[name];
    const actual = await deployedClassHash(expected.address, blockIdentifier);
    checks.push({
      code: `reuse.${name}.class_hash`,
      passed: actual !== null && BigInt(actual) === BigInt(expected.classHash),
      expected: expected.classHash,
      actual,
    });
  }
  if (!checks.every((check) => check.passed)) {
    throw new Error("A reused Phase 2 Mainnet contract failed class-hash read-back.");
  }
  return checks;
}

async function liveStatus(plan) {
  const blockNumber = await provider.getBlockNumber();
  const declarationEntries = await Promise.all(phase3DeclarationOrder.map(async (name) => [
    name,
    await classDeclared(plan.declarations[name].classHash),
  ]));
  const contractEntries = await Promise.all(
    [...phase3VerifierDeploymentOrder, "payrollSeal"].map(async (name) => {
      const expected = plan.contracts[name];
      const actual = await deployedClassHash(expected.address, blockNumber);
      if (actual && BigInt(actual) !== BigInt(expected.classHash)) {
        throw new Error(`${name} predicted address contains an unexpected Mainnet class.`);
      }
      return [name, {
        address: expected.address,
        deployed: actual !== null,
        expectedClassHash: expected.classHash,
        actualClassHash: actual,
      }];
    }),
  );
  return {
    observedAt: new Date().toISOString(),
    blockNumber,
    declarations: Object.fromEntries(declarationEntries),
    contracts: Object.fromEntries(contractEntries),
  };
}

async function updateEvidence(plan, change) {
  const existing = await readJsonIfExists(evidencePath, {
    schemaVersion: 1,
    network: "starknet-mainnet",
    planPath,
    planGeneratedAt: plan.generatedAt,
    declarations: {},
    deployments: {},
    verifierProofChecks: {},
  });
  const next = await change(existing);
  const updated = { ...next, updatedAt: new Date().toISOString() };
  await Promise.all([
    saveJson(evidencePath, updated),
    saveJson(publicEvidencePath, {
      ...updated,
      planPath: "circuits/payroll_integrity/target/payo-phase3-mainnet-plan.json",
    }),
  ]);
}

const PUBLIC_INPUT_ORDER = Object.freeze([
  "chainId",
  "sealAddress",
  "proofVersion",
  "schemaVersion",
  "agreementRootHigh",
  "agreementRootLow",
  "manifestRootHigh",
  "manifestRootLow",
  "policyRootHigh",
  "policyRootLow",
  "fxRootHigh",
  "fxRootLow",
  "runNullifierHigh",
  "runNullifierLow",
  "validityStart",
  "validityExpiry",
  "shardIndex",
]);

const PROOF_PROFILES = Object.freeze({
  advanced: {
    directory: PHASE3_ADVANCED_PROOF_DIRECTORY,
    summaryFile: "advanced-matrix-proof.json",
    shardPrefix: "advanced-matrix-shard",
    contractName: "advancedBundle",
    proofVersion: 2n,
    tamperIndex: 2,
  },
  claim: {
    directory: PHASE3_EXCEPTION_PROOF_DIRECTORY,
    summaryFile: "claim-proof.json",
    shardPrefix: "claim-shard",
    contractName: "claimBundle",
    proofVersion: 3n,
    tamperIndex: 1,
  },
  remediation: {
    directory: PHASE3_EXCEPTION_PROOF_DIRECTORY,
    summaryFile: "remediation-proof.json",
    shardPrefix: "remediation-shard",
    contractName: "remediationBundle",
    proofVersion: 4n,
    tamperIndex: 1,
  },
});

function parseProofCalldata(text, label) {
  const proof = text.trim().split(/\s+/);
  if (proof.length === 0 || proof.some((felt) => !/^0x[0-9a-fA-F]+$/.test(felt))) {
    throw new Error(`${label} contains malformed proof calldata.`);
  }
  return proof;
}

function decodeVerifierInputs(result, label) {
  if (result[0] !== "0x0" || BigInt(result[1] ?? 0) !== 17n || result.length !== 36) {
    throw new Error(`${label} did not return Result::Ok with exactly 17 public inputs.`);
  }
  return Array.from({ length: 17 }, (_, index) =>
    BigInt(result[2 + index * 2]) + (BigInt(result[3 + index * 2]) << 128n));
}

async function callProofShard(bundleAddress, proof) {
  return provider.callContract({
    contractAddress: bundleAddress,
    entrypoint: "verify_payroll_integrity_shard",
    calldata: [proof.length.toString(), ...proof],
  }, "latest");
}

async function verifyProofProfile(plan, profileName) {
  const config = PROOF_PROFILES[profileName];
  const summaryPath = resolve(config.directory, config.summaryFile);
  const [summary, ...proofTexts] = await Promise.all([
    readJson(summaryPath),
    ...[0, 1].map((shardIndex) => readFile(
      resolve(config.directory, `${config.shardPrefix}-${shardIndex}.txt`),
      "utf8",
    )),
  ]);
  if (!Array.isArray(summary.shards) || summary.shards.length !== 2) {
    throw new Error(`${profileName} proof summary must contain exactly two shards.`);
  }
  const bundleAddress = plan.contracts[config.contractName].address;
  const checks = await Promise.all(summary.shards.map(async (shard, shardIndex) => {
    if (shard.shardIndex !== shardIndex) {
      throw new Error(`${profileName} proof shards are not ordered.`);
    }
    const expected = PUBLIC_INPUT_ORDER.map((name) => {
      const value = shard.publicInputs?.[name];
      if (!/^0x[0-9a-fA-F]+$/.test(value ?? "")) {
        throw new Error(`${profileName} shard ${shardIndex} lacks public input ${name}.`);
      }
      return BigInt(value);
    });
    if (
      expected[0] !== BigInt(plan.chainId)
      || expected[1] !== BigInt(plan.contracts.payrollSeal.address)
      || expected[2] !== config.proofVersion
      || expected[3] !== 1n
      || expected[16] !== BigInt(shardIndex)
    ) {
      throw new Error(`${profileName} shard ${shardIndex} is not bound to the reviewed Mainnet topology.`);
    }
    const proof = parseProofCalldata(proofTexts[shardIndex], `${profileName} shard ${shardIndex}`);
    const startedAt = Date.now();
    const returned = decodeVerifierInputs(
      await callProofShard(bundleAddress, proof),
      `${profileName} shard ${shardIndex}`,
    );
    if (returned.some((value, index) => value !== expected[index])) {
      throw new Error(`${profileName} shard ${shardIndex} returned unexpected public inputs.`);
    }
    const tampered = [...proof];
    tampered[config.tamperIndex] = num.toHex(BigInt(tampered[config.tamperIndex]) ^ 1n);
    let tamperRejected = false;
    let tamperRejection = "Result::Err";
    try {
      const tamperedResult = await callProofShard(bundleAddress, tampered);
      tamperRejected = tamperedResult[0] !== "0x0";
    } catch {
      tamperRejected = true;
      tamperRejection = "RPC_REJECTED";
    }
    if (!tamperRejected) {
      throw new Error(`${profileName} shard ${shardIndex} accepted tampered public proof calldata.`);
    }
    return {
      shardIndex,
      calldataHash: shard.calldataHash,
      calldataFelts: proof.length,
      publicInputsMatched: true,
      tamperRejected: true,
      tamperRejection,
      durationMs: Date.now() - startedAt,
    };
  }));
  return {
    passed: true,
    bundleAddress,
    proofVersion: config.proofVersion.toString(),
    circuitSha256: summary.circuitSha256,
    generatedAt: summary.generatedAt,
    checks,
  };
}

async function verifyAllProofProfiles(plan) {
  const status = await liveStatus(plan);
  for (const name of phase3VerifierDeploymentOrder) {
    if (!status.contracts[name].deployed) {
      throw new Error(`Cannot verify Phase 3 proofs before ${name} is deployed.`);
    }
  }
  const [advanced, claim, remediation] = await Promise.all([
    verifyProofProfile(plan, "advanced"),
    verifyProofProfile(plan, "claim"),
    verifyProofProfile(plan, "remediation"),
  ]);
  return {
    passed: true,
    observedAt: new Date().toISOString(),
    blockNumber: await provider.getBlockNumber(),
    chainId: plan.chainId,
    sealAddress: plan.contracts.payrollSeal.address,
    advanced,
    claim,
    remediation,
  };
}

async function recordProofChecks(plan) {
  const verifierProofChecks = await verifyAllProofProfiles(plan);
  await updateEvidence(plan, async (evidence) => ({
    ...evidence,
    verifierProofChecks,
  }));
  return verifierProofChecks;
}

async function recordDeclarationEvidence(plan, name, transactionHash, simulatedFeeFri = null) {
  const declaration = plan.declarations[name];
  const [transaction, receipt] = await Promise.all([
    provider.getTransactionByHash(transactionHash),
    provider.getTransactionReceipt(transactionHash),
  ]);
  if (transaction.type !== "DECLARE"
    || BigInt(transaction.sender_address) !== BigInt(plan.deployerAddress)
    || BigInt(transaction.class_hash) !== BigInt(declaration.classHash)) {
    throw new Error(`${transactionHash} is not the reviewed ${name} declaration.`);
  }
  if (receipt.execution_status !== "SUCCEEDED"
    || !["ACCEPTED_ON_L2", "ACCEPTED_ON_L1"].includes(receipt.finality_status)) {
    throw new Error(`${name} declaration is not accepted and successful.`);
  }
  if (!(await classDeclared(declaration.classHash))) {
    throw new Error(`${name} receipt exists but the class is unavailable at latest.`);
  }
  const entry = {
    classHash: declaration.classHash,
    transactionHash,
    simulatedFeeFri,
    actualFeeFri: BigInt(receipt.actual_fee?.amount ?? 0).toString(),
    blockNumber: receipt.block_number,
    finalityStatus: receipt.finality_status,
    executionStatus: receipt.execution_status,
  };
  await updateEvidence(plan, async (evidence) => ({
    ...evidence,
    declarations: { ...evidence.declarations, [name]: entry },
  }));
  return entry;
}

await assertFreshPayoPhase3DeployArtifacts();
await requireMainnet();

if (action === "plan") {
  const [phase2Plan, artifacts] = await Promise.all([
    loadPhase2Plan(),
    readAllPayoPhase3DeployArtifacts(),
  ]);
  const deployerAddress = canonicalAddress(
    process.env.PAYO_PROOF_RELAYER_ADDRESS,
    "PAYO_PROOF_RELAYER_ADDRESS",
  );
  const plan = buildPayoPhase3MainnetPlan({ phase2Plan, artifacts, deployerAddress });
  assertPayoPhase3PlanMatchesArtifacts(plan, artifacts);
  await assertReusedTopology(plan);
  const status = await liveStatus(plan);
  await saveJson(planPath, plan);
  process.stdout.write(`${JSON.stringify({ planPath, plan, status }, null, 2)}\n`);
  process.exit(0);
}

const { plan, artifacts } = await loadReviewedPlan();
await assertReusedTopology(plan);

if (action === "status") {
  const [status, balanceFri] = await Promise.all([
    liveStatus(plan),
    readRelayerBalance(plan.deployerAddress),
  ]);
  process.stdout.write(`${JSON.stringify({
    planPath,
    evidencePath,
    deployerAddress: plan.deployerAddress,
    balanceFri: balanceFri.toString(),
    balanceStrk: Number(balanceFri) / 1e18,
    status,
  }, null, 2)}\n`);
  process.exit(0);
}

const account = ["estimate", "estimate-seal", "declare", "deploy-profile", "deploy-verifiers", "deploy-seal"].includes(action)
  ? accountFromEnvironment(plan.deployerAddress)
  : null;

if (action === "verify-proofs") {
  process.stdout.write(`${JSON.stringify(await recordProofChecks(plan), null, 2)}\n`);
  process.exit(0);
}

if (action === "record-activation") {
  const transactionHash = actionArgument;
  if (!/^0x[0-9a-fA-F]+$/.test(transactionHash ?? "")) {
    throw new Error("A Starknet activation transaction hash is required.");
  }
  const [transaction, receipt] = await Promise.all([
    provider.getTransactionByHash(transactionHash),
    provider.getTransactionReceipt(transactionHash),
  ]);
  if (
    transaction.type !== "INVOKE"
    || BigInt(transaction.sender_address) !== BigInt(plan.adminAddress)
    || receipt.execution_status !== "SUCCEEDED"
    || !["ACCEPTED_ON_L2", "ACCEPTED_ON_L1"].includes(receipt.finality_status)
  ) {
    throw new Error("The supplied transaction is not a successful Phase 3 admin activation.");
  }
  const selector = hash.getSelectorFromName("VerifierScheduled");
  const scheduled = await provider.getEvents({
    from_block: { block_number: receipt.block_number },
    to_block: { block_number: receipt.block_number },
    address: plan.contracts.policyRegistry.address,
    keys: [[selector]],
    chunk_size: 100,
  });
  const expectedProfiles = [
    { mode: 0n, proofVersion: 2n, bundleAddress: plan.contracts.advancedBundle.address },
    { mode: 2n, proofVersion: 3n, bundleAddress: plan.contracts.claimBundle.address },
    { mode: 3n, proofVersion: 4n, bundleAddress: plan.contracts.remediationBundle.address },
  ];
  const events = scheduled.events.filter((event) =>
    BigInt(event.transaction_hash) === BigInt(transactionHash));
  if (events.length !== expectedProfiles.length) {
    throw new Error("The activation transaction did not emit exactly three verifier schedules.");
  }
  const profiles = await Promise.all(expectedProfiles.map(async (expected) => {
    const event = events.find((candidate) =>
      BigInt(candidate.keys[1] ?? -1) === expected.mode
      && BigInt(candidate.keys[2] ?? -1) === expected.proofVersion);
    if (!event || BigInt(event.data[0] ?? 0) !== BigInt(expected.bundleAddress)) {
      throw new Error(`Activation event mismatch for mode ${expected.mode}, version ${expected.proofVersion}.`);
    }
    const [valid, verifier] = await Promise.all([
      provider.callContract({
        contractAddress: plan.contracts.policyRegistry.address,
        entrypoint: "is_verifier_valid",
        calldata: [expected.mode.toString(), expected.proofVersion.toString()],
      }, "latest"),
      provider.callContract({
        contractAddress: plan.contracts.policyRegistry.address,
        entrypoint: "get_verifier",
        calldata: [expected.mode.toString(), expected.proofVersion.toString()],
      }, "latest"),
    ]);
    if (BigInt(valid[0] ?? 0) === 0n || BigInt(verifier[0] ?? 0) !== BigInt(expected.bundleAddress)) {
      throw new Error(`Verifier profile ${expected.mode}/${expected.proofVersion} is not active.`);
    }
    return {
      mode: expected.mode.toString(),
      proofVersion: expected.proofVersion.toString(),
      bundleAddress: expected.bundleAddress,
      validAfter: BigInt(event.data[1] ?? 0).toString(),
      expiresAt: BigInt(event.data[2] ?? 0).toString(),
      active: true,
    };
  }));
  const activation = {
    passed: true,
    transactionHash,
    blockNumber: receipt.block_number,
    finalityStatus: receipt.finality_status,
    executionStatus: receipt.execution_status,
    profiles,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, activation }));
  process.stdout.write(`${JSON.stringify(activation, null, 2)}\n`);
  process.exit(0);
}

if (action === "estimate-seal") {
  if (!(await classDeclared(plan.declarations.payrollSeal.classHash))) {
    throw new Error("Cannot estimate seal deployment before payrollSeal is declared.");
  }
  const [item] = deploymentPayloads(plan, "seal");
  const actual = await deployedClassHash(item.address);
  if (actual) {
    if (BigInt(actual) !== BigInt(plan.contracts.payrollSeal.classHash)) {
      throw new Error("The planned seal address contains the wrong class.");
    }
    process.stdout.write(`${JSON.stringify({
      alreadyDeployed: true,
      address: item.address,
      feeFri: "0",
    }, null, 2)}\n`);
    process.exit(0);
  }
  const [fee, balanceFri] = await Promise.all([
    account.estimateDeployFee(item.payload),
    readRelayerBalance(plan.deployerAddress),
  ]);
  process.stdout.write(`${JSON.stringify({
    observedAt: new Date().toISOString(),
    address: item.address,
    classHash: plan.contracts.payrollSeal.classHash,
    feeFri: fee.overall_fee.toString(),
    feeStrk: Number(fee.overall_fee) / 1e18,
    balanceFri: balanceFri.toString(),
    balanceStrk: Number(balanceFri) / 1e18,
    currentlyFunded: balanceFri >= BigInt(fee.overall_fee),
  }, null, 2)}\n`);
  process.exit(0);
}

if (action === "estimate") {
  const balanceFri = await readRelayerBalance(plan.deployerAddress);
  const declarations = [];
  for (const name of phase3DeclarationOrder) {
    const declaration = plan.declarations[name];
    if (await classDeclared(declaration.classHash)) {
      declarations.push({ name, classHash: declaration.classHash, declared: true, feeFri: "0" });
      continue;
    }
    const artifact = artifacts[declaration.artifactName];
    const fee = await account.estimateDeclareFee({ contract: artifact.sierra, casm: artifact.casm });
    declarations.push({
      name,
      classHash: declaration.classHash,
      declared: false,
      feeFri: fee.overall_fee.toString(),
      feeStrk: Number(fee.overall_fee) / 1e18,
      currentlyFunded: balanceFri >= BigInt(fee.overall_fee),
    });
  }
  process.stdout.write(`${JSON.stringify({
    observedAt: new Date().toISOString(),
    balanceFri: balanceFri.toString(),
    balanceStrk: Number(balanceFri) / 1e18,
    declarations,
  }, null, 2)}\n`);
  process.exit(0);
}

if (action === "declare") {
  const name = actionArgument;
  if (!phase3DeclarationOrder.includes(name)) {
    throw new Error(`Declaration name must be one of: ${phase3DeclarationOrder.join(", ")}.`);
  }
  const expectedConfirmation = `DECLARE_PAYO_PHASE3_${name.replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase()}_MAINNET`;
  if (process.env.PAYO_PHASE3_MAINNET_CONFIRM !== expectedConfirmation) {
    throw new Error(
      `Refusing Mainnet declaration. Set PAYO_PHASE3_MAINNET_CONFIRM=${expectedConfirmation} `
        + "only after reviewing the plan and this declaration's live fee.",
    );
  }
  const declaration = plan.declarations[name];
  if (await classDeclared(declaration.classHash)) {
    process.stdout.write(`${name} is already declared as ${declaration.classHash}.\n`);
    process.exit(0);
  }
  if (name === "payrollSeal") {
    await recordProofChecks(plan);
  }
  const artifact = artifacts[declaration.artifactName];
  const fee = await account.estimateDeclareFee({ contract: artifact.sierra, casm: artifact.casm });
  const balanceFri = await readRelayerBalance(plan.deployerAddress);
  if (balanceFri < BigInt(fee.overall_fee)) {
    throw new Error(
      `${name} requires a ${fee.overall_fee} FRI resource bound; relayer has ${balanceFri} FRI.`,
    );
  }
  const submitted = await account.declare({ contract: artifact.sierra, casm: artifact.casm });
  process.stdout.write(`${name} submitted transaction: ${submitted.transaction_hash}\n`);
  try {
    await waitFor(submitted.transaction_hash);
  } catch (error) {
    if (!(await classDeclared(declaration.classHash))) throw error;
    process.stderr.write(
      `${name} waiter reported ${normalizeError(error)}, but class read-back succeeded; reconciling receipt.\n`,
    );
  }
  if (BigInt(submitted.class_hash) !== BigInt(declaration.classHash)
    || !(await classDeclared(declaration.classHash))) {
    throw new Error(`${name} declaration did not produce the reviewed class hash.`);
  }
  const recorded = await recordDeclarationEvidence(
    plan,
    name,
    submitted.transaction_hash,
    fee.overall_fee.toString(),
  );
  process.stdout.write(`${JSON.stringify({
    name,
    classHash: declaration.classHash,
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: recorded.actualFeeFri,
    remainingBalanceFri: (await readRelayerBalance(plan.deployerAddress)).toString(),
  }, null, 2)}\n`);
  process.exit(0);
}

if (action === "reconcile-declaration") {
  const name = actionArgument;
  const transactionHash = process.argv[4];
  const simulatedFeeFri = process.argv[5] ?? null;
  if (!phase3DeclarationOrder.includes(name)) {
    throw new Error(`Declaration name must be one of: ${phase3DeclarationOrder.join(", ")}.`);
  }
  if (!/^0x[0-9a-fA-F]+$/.test(transactionHash ?? "")) {
    throw new Error("A Starknet declaration transaction hash is required.");
  }
  if (simulatedFeeFri !== null && !/^[0-9]+$/.test(simulatedFeeFri)) {
    throw new Error("The optional simulated fee must be an unsigned FRI integer.");
  }
  const recorded = await recordDeclarationEvidence(plan, name, transactionHash, simulatedFeeFri);
  process.stdout.write(`${JSON.stringify({ name, ...recorded }, null, 2)}\n`);
  process.exit(0);
}

if (action === "deploy-profile") {
  const profile = actionArgument;
  const profileContracts = {
    advanced: ["advancedVerifier", "advancedBundle"],
    claim: ["claimVerifier", "claimBundle"],
    remediation: ["remediationVerifier", "remediationBundle"],
  };
  const names = profileContracts[profile];
  if (!names) throw new Error("Deployment profile must be advanced, claim, or remediation.");
  const expectedConfirmation = `DEPLOY_PAYO_PHASE3_${profile.toUpperCase()}_MAINNET`;
  if (process.env.PAYO_PHASE3_MAINNET_CONFIRM !== expectedConfirmation) {
    throw new Error(
      `Refusing Mainnet deployment. Set PAYO_PHASE3_MAINNET_CONFIRM=${expectedConfirmation} `
        + "only after the profile classes and fee are reviewed.",
    );
  }
  const requiredDeclarations = profile === "advanced"
    ? ["advancedVerifier", "advancedBundle"]
    : [`${profile}Verifier`];
  for (const name of requiredDeclarations) {
    if (!(await classDeclared(plan.declarations[name].classHash))) {
      throw new Error(`Refusing ${profile} deployment: ${name} is not declared.`);
    }
  }
  const all = deploymentPayloads(plan, "verifiers");
  const pending = [];
  for (const item of all.filter((candidate) => names.includes(candidate.name))) {
    const actual = await deployedClassHash(item.address);
    if (actual) {
      if (BigInt(actual) !== BigInt(plan.contracts[item.name].classHash)) {
        throw new Error(`${item.name} address contains the wrong class.`);
      }
    } else {
      pending.push(item);
    }
  }
  if (pending.length === 0) {
    process.stdout.write(`The ${profile} verifier profile is already deployed.\n`);
    process.exit(0);
  }
  const fee = await account.estimateDeployFee(pending.map((item) => item.payload));
  const balanceFri = await readRelayerBalance(plan.deployerAddress);
  if (balanceFri < BigInt(fee.overall_fee)) {
    throw new Error(`${profile} deployment requires ${fee.overall_fee} FRI; relayer has ${balanceFri} FRI.`);
  }
  const submitted = await account.deployContract(pending.map((item) => item.payload));
  process.stdout.write(`${profile} deployment submitted transaction: ${submitted.transaction_hash}\n`);
  try {
    await waitFor(submitted.transaction_hash);
  } catch (error) {
    const readable = await Promise.all(pending.map((item) => deployedClassHash(item.address)));
    if (readable.some((value, index) => !value
      || BigInt(value) !== BigInt(plan.contracts[pending[index].name].classHash))) throw error;
    process.stderr.write(
      `${profile} waiter reported ${normalizeError(error)}, but every class read-back succeeded; reconciling receipt.\n`,
    );
  }
  for (const item of pending) {
    const actual = await deployedClassHash(item.address);
    if (!actual || BigInt(actual) !== BigInt(plan.contracts[item.name].classHash)) {
      throw new Error(`${item.name} failed post-deployment class-hash verification.`);
    }
  }
  const receipt = await provider.getTransactionReceipt(submitted.transaction_hash);
  const entry = {
    names: pending.map((item) => item.name),
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: BigInt(receipt.actual_fee?.amount ?? 0).toString(),
    blockNumber: receipt.block_number,
    finalityStatus: receipt.finality_status,
    executionStatus: receipt.execution_status,
  };
  await updateEvidence(plan, async (evidence) => ({
    ...evidence,
    deployments: { ...evidence.deployments, [profile]: entry },
  }));
  process.stdout.write(`${JSON.stringify({ profile, ...entry }, null, 2)}\n`);
  process.exit(0);
}

if (action === "deploy-seal") {
  const expectedConfirmation = "DEPLOY_PAYO_PHASE3_SEAL_MAINNET";
  if (process.env.PAYO_PHASE3_MAINNET_CONFIRM !== expectedConfirmation) {
    throw new Error(
      `Refusing Mainnet seal deployment. Set PAYO_PHASE3_MAINNET_CONFIRM=${expectedConfirmation} `
        + "only after the verifier topology, proof checks and fee are reviewed.",
    );
  }
  if (!(await classDeclared(plan.declarations.payrollSeal.classHash))) {
    throw new Error("Refusing seal deployment: payrollSeal is not declared.");
  }
  const verifierProofChecks = await recordProofChecks(plan);
  if (!verifierProofChecks.passed) {
    throw new Error("Refusing seal deployment: verifier proof preflight did not pass.");
  }
  const [item] = deploymentPayloads(plan, "seal");
  const actual = await deployedClassHash(item.address);
  if (actual) {
    if (BigInt(actual) !== BigInt(plan.contracts.payrollSeal.classHash)) {
      throw new Error("The planned seal address contains the wrong class.");
    }
    process.stdout.write(`The Phase 3 payroll seal is already deployed at ${item.address}.\n`);
    process.exit(0);
  }
  const fee = await account.estimateDeployFee(item.payload);
  const balanceFri = await readRelayerBalance(plan.deployerAddress);
  if (balanceFri < BigInt(fee.overall_fee)) {
    throw new Error(`Seal deployment requires ${fee.overall_fee} FRI; relayer has ${balanceFri} FRI.`);
  }
  const submitted = await account.deployContract(item.payload);
  process.stdout.write(`seal deployment submitted transaction: ${submitted.transaction_hash}\n`);
  try {
    await waitFor(submitted.transaction_hash);
  } catch (error) {
    const readable = await deployedClassHash(item.address);
    if (!readable || BigInt(readable) !== BigInt(plan.contracts.payrollSeal.classHash)) throw error;
    process.stderr.write(
      `Seal waiter reported ${normalizeError(error)}, but class read-back succeeded; reconciling receipt.\n`,
    );
  }
  const deployed = await deployedClassHash(item.address);
  if (!deployed || BigInt(deployed) !== BigInt(plan.contracts.payrollSeal.classHash)) {
    throw new Error("The Phase 3 seal failed post-deployment class-hash verification.");
  }
  const receipt = await provider.getTransactionReceipt(submitted.transaction_hash);
  const entry = {
    names: ["payrollSeal"],
    address: item.address,
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: BigInt(receipt.actual_fee?.amount ?? 0).toString(),
    blockNumber: receipt.block_number,
    finalityStatus: receipt.finality_status,
    executionStatus: receipt.execution_status,
  };
  await updateEvidence(plan, async (evidence) => ({
    ...evidence,
    deployments: { ...evidence.deployments, seal: entry },
  }));
  process.stdout.write(`${JSON.stringify({ stage: "seal", ...entry }, null, 2)}\n`);
  process.exit(0);
}

if (action === "deploy-verifiers") {
  const expectedConfirmation = "DEPLOY_PAYO_PHASE3_VERIFIERS_MAINNET";
  if (process.env.PAYO_PHASE3_MAINNET_CONFIRM !== expectedConfirmation) {
    throw new Error(
      `Refusing Mainnet deployment. Set PAYO_PHASE3_MAINNET_CONFIRM=${expectedConfirmation} `
        + "only after every required class is declared and the deployment fee is reviewed.",
    );
  }
  for (const name of phase3DeclarationOrder.filter((value) => value !== "payrollSeal")) {
    if (!(await classDeclared(plan.declarations[name].classHash))) {
      throw new Error(`Refusing verifier deployment: ${name} is not declared.`);
    }
  }
  const planned = deploymentPayloads(plan, "verifiers");
  const pending = [];
  for (const item of planned) {
    const actual = await deployedClassHash(item.address);
    if (actual) {
      if (BigInt(actual) !== BigInt(plan.contracts[item.name].classHash)) {
        throw new Error(`${item.name} address contains the wrong class.`);
      }
    } else {
      pending.push(item);
    }
  }
  if (pending.length === 0) {
    process.stdout.write("All Phase 3 verifier instances are already deployed.\n");
    process.exit(0);
  }
  const fee = await account.estimateDeployFee(pending.map((item) => item.payload));
  const balanceFri = await readRelayerBalance(plan.deployerAddress);
  if (balanceFri < BigInt(fee.overall_fee)) {
    throw new Error(`Verifier deployment requires ${fee.overall_fee} FRI; relayer has ${balanceFri} FRI.`);
  }
  const submitted = await account.deployContract(pending.map((item) => item.payload));
  await waitFor(submitted.transaction_hash);
  for (const item of pending) {
    const actual = await deployedClassHash(item.address);
    if (!actual || BigInt(actual) !== BigInt(plan.contracts[item.name].classHash)) {
      throw new Error(`${item.name} failed post-deployment class-hash verification.`);
    }
  }
  const receipt = await provider.getTransactionReceipt(submitted.transaction_hash);
  await updateEvidence(plan, async (evidence) => ({
    ...evidence,
    deployments: {
      ...evidence.deployments,
      verifiers: {
        names: pending.map((item) => item.name),
        transactionHash: submitted.transaction_hash,
        simulatedFeeFri: fee.overall_fee.toString(),
        actualFeeFri: BigInt(receipt.actual_fee?.amount ?? 0).toString(),
        blockNumber: receipt.block_number,
      },
    },
  }));
  process.stdout.write(`${JSON.stringify({
    stage: "verifiers",
    names: pending.map((item) => item.name),
    transactionHash: submitted.transaction_hash,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: BigInt(receipt.actual_fee?.amount ?? 0).toString(),
  }, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify-verifiers") {
  const status = await liveStatus(plan);
  for (const name of phase3VerifierDeploymentOrder) {
    if (!status.contracts[name].deployed) {
      throw new Error(`${name} is not deployed.`);
    }
  }
  const [advancedBundleArtifact, integrityBundleArtifact] = await Promise.all([
    Promise.resolve(artifacts.advancedBundle),
    Promise.resolve(artifacts.integrityBundle),
  ]);
  const advanced = new Contract({
    abi: advancedBundleArtifact.sierra.abi,
    address: plan.contracts.advancedBundle.address,
    providerOrAccount: provider,
  });
  const claim = new Contract({
    abi: integrityBundleArtifact.sierra.abi,
    address: plan.contracts.claimBundle.address,
    providerOrAccount: provider,
  });
  const remediation = new Contract({
    abi: integrityBundleArtifact.sierra.abi,
    address: plan.contracts.remediationBundle.address,
    providerOrAccount: provider,
  });
  const topology = {
    advancedBaseVerifier: num.toHex(BigInt(await advanced.call("get_base_verifier"))),
    advancedVerifier: num.toHex(BigInt(await advanced.call("get_advanced_verifier"))),
    claimVerifier: num.toHex(BigInt(await claim.call("get_underlying_verifier"))),
    remediationVerifier: num.toHex(BigInt(await remediation.call("get_underlying_verifier"))),
  };
  const expected = {
    advancedBaseVerifier: plan.contracts.baseVerifier.address,
    advancedVerifier: plan.contracts.advancedVerifier.address,
    claimVerifier: plan.contracts.claimVerifier.address,
    remediationVerifier: plan.contracts.remediationVerifier.address,
  };
  for (const name of Object.keys(expected)) {
    if (BigInt(topology[name]) !== BigInt(expected[name])) {
      throw new Error(`Verifier topology mismatch at ${name}.`);
    }
  }
  process.stdout.write(`${JSON.stringify({ passed: true, topology, status }, null, 2)}\n`);
}
