import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Account,
  RpcProvider,
  constants,
  hash,
  num,
  shortString,
  uint256,
  validateAndParseAddress,
} from "starknet";
import {
  assertFreshPayoVestingBookDeployArtifacts,
  readAllPayoVestingBookDeployArtifacts,
  repositoryRoot,
} from "./lib/payo-contract-artifacts.mjs";
import {
  assertPayoVestingBookMainnetPlan,
  buildPayoVestingBookMainnetPlan,
  vestingBookDeploymentPayloads,
} from "./lib/payo-vesting-book-mainnet.mjs";

const DEFAULT_RPC_URL = "https://api.cartridge.gg/x/starknet/mainnet";
const STRK_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const LIVE_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-multitenant-mainnet-deployment.json",
);
const V2_EVIDENCE_PATH = resolve(repositoryRoot, "evidence/phase3-v2-mainnet-upgrade.json");
const EXCEPTION_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "evidence/phase3-wage-claim-mainnet.json",
);
const PLAN_PATH = resolve(
  repositoryRoot,
  "circuits/vesting_transition/target/payo-vesting-book-mainnet-plan.json",
);
const EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/vesting_transition/target/payo-vesting-book-mainnet-deployment.json",
);
const PUBLIC_EVIDENCE_PATH = resolve(repositoryRoot, "evidence/vesting-tax-mainnet.json");
const PUBLIC_PLAN_PATH = resolve(repositoryRoot, "evidence/vesting-tax-mainnet-plan.json");
const PROOF_DIRECTORY = resolve(repositoryRoot, "contracts/vesting_verifier_v3/tests");
const CONTRACT_NAMES = Object.freeze(["vestingVerifier", "vestingBundle", "vestingBookSeal"]);
const ACTIONS = new Set([
  "plan",
  "status",
  "estimate",
  "declare",
  "deploy",
  "activate",
  "verify",
  "verify-canary",
]);
const action = process.argv[2];
if (!ACTIONS.has(action)) {
  throw new Error(
    "Usage: node scripts/payo-vesting-book-mainnet.mjs "
      + "<plan|status|estimate|declare|deploy|activate|verify|verify-canary [canary.json]>",
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

function sameHex(left, right) {
  return BigInt(left) === BigInt(right);
}

function canonicalAddress(value, label) {
  if (!value) throw new Error(`${label} is required.`);
  try {
    const parsed = validateAndParseAddress(value);
    if (BigInt(parsed) === 0n) throw new Error();
    return num.toHex(BigInt(parsed));
  } catch {
    throw new Error(`${label} must be a non-zero Starknet address.`);
  }
}

function mutationTip() {
  const value = process.env.PAYO_VESTING_MAINNET_TIP ?? "1";
  if (!/^\d+$/.test(value) || BigInt(value) < 1n || BigInt(value) > 1_000_000n) {
    throw new Error("PAYO_VESTING_MAINNET_TIP must be an integer from 1 through 1000000.");
  }
  return BigInt(value);
}

function isMissingClass(error) {
  return /class hash not found|undeclared class|class_hash_not_found/i.test(normalizeError(error));
}

function isMissingContract(error) {
  return /contract not found|contract_address_not_found|uninitialized contract/i
    .test(normalizeError(error));
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
      plan: { ...next.plan, source: "circuits/vesting_transition/target/payo-vesting-book-mainnet-plan.json" },
    }),
  ]);
}

async function requireMainnet() {
  const chainId = await provider.getChainId();
  if (BigInt(chainId) !== BigInt(constants.StarknetChainId.SN_MAIN)) {
    throw new Error(`Refusing VestingBook action: RPC reports non-Mainnet chain ${chainId}.`);
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
    throw new Error("The configured deployment account differs from the reviewed Mainnet plan.");
  }
  const privateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error("PAYO_PROOF_RELAYER_PRIVATE_KEY is required for simulation or mutation.");
  }
  return new Account({ provider, address, signer: privateKey, cairoVersion: "1" });
}

async function waitFor(transactionHash) {
  return provider.waitForTransaction(transactionHash, { retries: 400, retryInterval: 3_000 });
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
          // Some RPC nodes expose the deterministic state before the receipt.
        }
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 3_000));
    }
    throw new Error(`${label} did not reach its read-back state: ${normalizeError(waitError)}`);
  }
}

function actualFee(receipt) {
  return BigInt(receipt.actual_fee?.amount ?? 0).toString();
}

async function loadContext() {
  await assertFreshPayoVestingBookDeployArtifacts();
  const [liveEvidence, v2UpgradeEvidence, exceptionEvidence, artifacts] = await Promise.all([
    readJson(LIVE_EVIDENCE_PATH),
    readJson(V2_EVIDENCE_PATH),
    readJson(EXCEPTION_EVIDENCE_PATH),
    readAllPayoVestingBookDeployArtifacts(),
  ]);
  if (!liveEvidence.plan || liveEvidence.verification?.passed !== true) {
    throw new Error("The tenant-aware Mainnet topology lacks passing read-back evidence.");
  }
  return {
    livePlan: liveEvidence.plan,
    liveVerification: liveEvidence.verification,
    v2UpgradeEvidence,
    exceptionEvidence,
    vestingVerifierArtifact: artifacts.vestingVerifier,
    vestingBundleArtifact: artifacts.vestingBundle,
    vestingBookSealArtifact: artifacts.vestingBookSeal,
    artifacts,
  };
}

async function loadReviewedPlan(context) {
  const plan = await readJson(PLAN_PATH);
  assertPayoVestingBookMainnetPlan(plan, context);
  return plan;
}

async function readVerifierProfile(plan, blockIdentifier = "latest") {
  const registry = plan.reusedTopology.policyRegistry.address;
  const activeResult = await provider.callContract({
    contractAddress: registry,
    entrypoint: "is_verifier_valid",
    calldata: [plan.verifierProfile.mode, plan.verifierProfile.proofVersion],
  }, blockIdentifier);
  const active = BigInt(activeResult[0] ?? 0) !== 0n;
  let address = null;
  if (active) {
    const result = await provider.callContract({
      contractAddress: registry,
      entrypoint: "get_verifier",
      calldata: [plan.verifierProfile.mode, plan.verifierProfile.proofVersion],
    }, blockIdentifier);
    address = num.toHex(BigInt(result[0] ?? 0));
  }
  return {
    ...plan.verifierProfile,
    active,
    address,
    matches: active && sameHex(address, plan.verifierProfile.address),
  };
}

async function assertLiveDependencies(plan, blockIdentifier = "latest") {
  const chainId = await requireMainnet();
  const checks = [];
  checks.push({ code: "chain", passed: sameHex(chainId, plan.chainId) });
  for (const name of ["policyRegistry", "obligationRegistry", "exceptionSeal"]) {
    const expected = plan.reusedTopology[name];
    const actual = await deployedClassHash(expected.address, blockIdentifier);
    checks.push({
      code: `${name}.class_hash`,
      expected: expected.classHash,
      actual,
      passed: Boolean(actual && sameHex(actual, expected.classHash)),
    });
  }
  const poolClassHash = await deployedClassHash(plan.poolAddress, blockIdentifier);
  checks.push({ code: "pool.deployed", actual: poolClassHash, passed: Boolean(poolClassHash) });
  const [admin, v2Active, v2Address] = await Promise.all([
    provider.callContract({
      contractAddress: plan.reusedTopology.policyRegistry.address,
      entrypoint: "get_admin",
      calldata: [],
    }, blockIdentifier),
    provider.callContract({
      contractAddress: plan.reusedTopology.policyRegistry.address,
      entrypoint: "is_verifier_valid",
      calldata: [0, 2],
    }, blockIdentifier),
    provider.callContract({
      contractAddress: plan.reusedTopology.policyRegistry.address,
      entrypoint: "get_verifier",
      calldata: [0, 2],
    }, blockIdentifier),
  ]);
  checks.push({ code: "policy.admin", passed: sameHex(admin[0] ?? 0, plan.deployerAddress) });
  checks.push({
    code: "payroll_v2.active",
    passed: BigInt(v2Active[0] ?? 0) !== 0n
      && sameHex(v2Address[0] ?? 0, plan.reusedTopology.payrollV2Bundle),
  });
  if (!checks.every(({ passed }) => passed)) {
    throw new Error(`A Mainnet dependency failed read-back: ${JSON.stringify(checks)}`);
  }
  return checks;
}

async function liveStatus(plan, blockIdentifier = "latest") {
  const declarations = {};
  const contracts = {};
  for (const name of CONTRACT_NAMES) {
    declarations[name] = await classDeclared(plan.contracts[name].classHash);
    const actualClassHash = await deployedClassHash(plan.contracts[name].address, blockIdentifier);
    contracts[name] = {
      address: plan.contracts[name].address,
      expectedClassHash: plan.contracts[name].classHash,
      actualClassHash,
      deployed: Boolean(actualClassHash && sameHex(actualClassHash, plan.contracts[name].classHash)),
    };
  }
  const profile = await readVerifierProfile(plan, blockIdentifier);
  const wiring = { checked: false, passed: false };
  if (contracts.vestingBundle.deployed && contracts.vestingBookSeal.deployed) {
    const [underlying, pool, catalog, obligations, exceptionSeal] = await Promise.all([
      provider.callContract({
        contractAddress: plan.contracts.vestingBundle.address,
        entrypoint: "get_underlying_verifier",
        calldata: [],
      }, blockIdentifier),
      provider.callContract({
        contractAddress: plan.contracts.vestingBookSeal.address,
        entrypoint: "get_pool",
        calldata: [],
      }, blockIdentifier),
      provider.callContract({
        contractAddress: plan.contracts.vestingBookSeal.address,
        entrypoint: "get_catalog_registry",
        calldata: [],
      }, blockIdentifier),
      provider.callContract({
        contractAddress: plan.contracts.vestingBookSeal.address,
        entrypoint: "get_obligation_registry",
        calldata: [],
      }, blockIdentifier),
      provider.callContract({
        contractAddress: plan.contracts.vestingBookSeal.address,
        entrypoint: "get_exception_seal",
        calldata: [],
      }, blockIdentifier),
    ]);
    Object.assign(wiring, {
      checked: true,
      underlyingVerifier: num.toHex(BigInt(underlying[0] ?? 0)),
      pool: num.toHex(BigInt(pool[0] ?? 0)),
      policyRegistry: num.toHex(BigInt(catalog[0] ?? 0)),
      obligationRegistry: num.toHex(BigInt(obligations[0] ?? 0)),
      exceptionSeal: num.toHex(BigInt(exceptionSeal[0] ?? 0)),
      passed: sameHex(underlying[0] ?? 0, plan.contracts.vestingVerifier.address)
        && sameHex(pool[0] ?? 0, plan.poolAddress)
        && sameHex(catalog[0] ?? 0, plan.reusedTopology.policyRegistry.address)
        && sameHex(obligations[0] ?? 0, plan.reusedTopology.obligationRegistry.address)
        && sameHex(exceptionSeal[0] ?? 0, plan.reusedTopology.exceptionSeal.address),
    });
  }
  return { declarations, contracts, profile, wiring };
}

async function activationWindow() {
  const block = await provider.getBlock("latest");
  const validAfter = Number(BigInt(block.timestamp));
  return { validAfter, expiresAt: validAfter + 365 * 24 * 60 * 60 };
}

function activationCall(plan, window) {
  return {
    contractAddress: plan.reusedTopology.policyRegistry.address,
    entrypoint: "schedule_verifier",
    calldata: [
      plan.verifierProfile.mode,
      plan.verifierProfile.proofVersion,
      plan.verifierProfile.address,
      window.validAfter,
      window.expiresAt,
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
    estimates.push({ label: `declare.${name}`, feeFri: fee.overall_fee.toString() });
  }
  const pending = vestingBookDeploymentPayloads(plan)
    .filter(({ name }) => !status.contracts[name].deployed);
  for (const item of pending) {
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
    estimates.push({ label: `deploy.${item.name}`, feeFri: fee.overall_fee.toString() });
  }
  let activation = null;
  if (!status.profile.matches) {
    activation = await activationWindow();
    const fee = await account.estimateInvokeFee(activationCall(plan, activation), { tip });
    estimates.push({ label: "activate.verifier.0.3", feeFri: fee.overall_fee.toString() });
  }
  const totalFeeFri = estimates.reduce((sum, item) => sum + BigInt(item.feeFri), 0n);
  const balance = await readBalance(plan.deployerAddress);
  return {
    observedAt: new Date().toISOString(),
    status,
    pendingDeployments: pending.map(({ name }) => name),
    activationWindow: activation,
    estimates: estimates.map((item) => ({
      ...item,
      feeStrk: Number(item.feeFri) / 1e18,
    })),
    totalFeeFri: totalFeeFri.toString(),
    totalFeeStrk: Number(totalFeeFri) / 1e18,
    balanceFri: balance.toString(),
    balanceStrk: Number(balance) / 1e18,
    currentlyFunded: balance >= totalFeeFri,
    mutationTip: tip.toString(),
  };
}

async function verifyRealProofPair(plan) {
  const fixture = await readJson(resolve(PROOF_DIRECTORY, "proof_fixture_manifest.json"));
  const proofs = await Promise.all([0, 1].map(async (index) => {
    const text = await readFile(resolve(PROOF_DIRECTORY, `proof_calldata_${index}.txt`), "utf8");
    const values = text.trim().split(/\s+/).filter(Boolean);
    if (values.length !== plan.circuit.measuredProofCalldataFelts
      || values.some((value) => !/^0x[0-9a-fA-F]+$/.test(value))) {
      throw new Error(`The committed v3 shard ${index} fixture is malformed.`);
    }
    return values;
  }));
  const call = async (left, right) => provider.callContract({
    contractAddress: plan.contracts.vestingBundle.address,
    entrypoint: "verify_payroll_integrity_bundle",
    calldata: [left.length, ...left, right.length, ...right],
  }, "latest");
  const result = await call(proofs[0], proofs[1]);
  const combinedInputCount = plan.circuit.publicInputCount * 2;
  if (
    BigInt(result[0] ?? 1) !== 0n
    || BigInt(result[1] ?? 0) !== BigInt(combinedInputCount)
    || result.length !== 2 + combinedInputCount * 2
  ) {
    throw new Error("The deployed v3 bundle rejected its real ordered proof pair.");
  }
  const publicInputs = Array.from({ length: combinedInputCount }, (_, index) =>
    BigInt(result[2 + index * 2]) + (BigInt(result[3 + index * 2]) << 128n));
  const [attestationHigh, attestationLow] = commitmentLimbs(
    fixture.attestationRoot,
    "Fixture attestation root",
  );
  for (const offset of [0, plan.circuit.publicInputCount]) {
    if (
      publicInputs[offset + 24] !== attestationHigh
      || publicInputs[offset + 25] !== attestationLow
    ) {
      throw new Error("The real v3 proof is not bound to the reviewed attestation catalog root.");
    }
  }
  let reversedRejected = false;
  try {
    const reversed = await call(proofs[1], proofs[0]);
    reversedRejected = BigInt(reversed[0] ?? 0) !== 0n;
  } catch {
    reversedRejected = true;
  }
  if (!reversedRejected) throw new Error("The deployed v3 bundle accepted reversed shards.");
  return {
    passed: true,
    proofCalldataFelts: proofs.map((proof) => proof.length),
    reversedShardsRejected: true,
    fixtureSealBinding: "0x456",
    attestationRoot: fixture.attestationRoot,
  };
}

function commitmentLimbs(value, label) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${label} must be 32 bytes.`);
  const parsed = BigInt(value);
  return [parsed >> 128n, parsed & ((1n << 128n) - 1n)];
}

function parseCanary(input, plan) {
  const canary = {
    transactionHash: input.transactionHash,
    ownerAddress: canonicalAddress(input.ownerAddress, "Canary ownerAddress"),
    periodStart: BigInt(input.periodStart),
    periodEnd: BigInt(input.periodEnd),
    scheduleId: input.scheduleId,
    nextStateCommitment: input.nextStateCommitment,
    releaseNullifier: input.releaseNullifier,
    bookEntryCommitment: input.bookEntryCommitment,
  };
  if (!/^0x[0-9a-fA-F]{64}$/.test(canary.transactionHash)) {
    throw new Error("Canary transactionHash must be 32 bytes.");
  }
  for (const [name, value] of [
    ["scheduleId", canary.scheduleId],
    ["nextStateCommitment", canary.nextStateCommitment],
    ["releaseNullifier", canary.releaseNullifier],
    ["bookEntryCommitment", canary.bookEntryCommitment],
  ]) commitmentLimbs(value, `Canary ${name}`);
  if (canary.periodStart < 0n || canary.periodEnd <= canary.periodStart
    || BigInt(plan.contracts.vestingBookSeal.address) === 0n) {
    throw new Error("Canary period or seal is invalid.");
  }
  return canary;
}

async function verifyCanary(plan, input) {
  const canary = parseCanary(input, plan);
  const receipt = await provider.getTransactionReceipt(canary.transactionHash);
  if (receipt.isReverted?.() || receipt.execution_status === "REVERTED") {
    throw new Error("The vesting canary transaction reverted.");
  }
  const seal = plan.contracts.vestingBookSeal.address;
  const [scheduleHigh, scheduleLow] = commitmentLimbs(canary.scheduleId, "scheduleId");
  const [stateHigh, stateLow] = commitmentLimbs(canary.nextStateCommitment, "nextStateCommitment");
  const [releaseHigh, releaseLow] = commitmentLimbs(canary.releaseNullifier, "releaseNullifier");
  const [entryHigh, entryLow] = commitmentLimbs(canary.bookEntryCommitment, "bookEntryCommitment");
  const [state, consumed, book] = await Promise.all([
    provider.callContract({
      contractAddress: seal,
      entrypoint: "get_vesting_state",
      calldata: [scheduleHigh, scheduleLow],
    }, "latest"),
    provider.callContract({
      contractAddress: seal,
      entrypoint: "is_release_consumed",
      calldata: [releaseHigh, releaseLow],
    }, "latest"),
    provider.callContract({
      contractAddress: seal,
      entrypoint: "get_payroll_book",
      calldata: [canary.ownerAddress, canary.periodStart, canary.periodEnd],
    }, "latest"),
  ]);
  if (BigInt(state[0] ?? 0) !== 1n || !sameHex(state[1] ?? 0, canary.ownerAddress)
    || BigInt(state[2] ?? 0) !== stateHigh || BigInt(state[3] ?? 0) !== stateLow) {
    throw new Error("The Mainnet vesting state does not match the canary proof.");
  }
  if (BigInt(consumed[0] ?? 0) !== 1n || BigInt(book[0] ?? 0) !== 1n) {
    throw new Error("The canary release or payroll book is not finalized.");
  }
  const count = Number(BigInt(book[1] ?? 0));
  if (!Number.isSafeInteger(count) || count < 1 || count > 10_000) {
    throw new Error("The Mainnet payroll-book count is outside the verifier bound.");
  }
  let accumulator = BigInt(hash.computePoseidonHashOnElements([
    shortString.encodeShortString("PAYO_BOOK_V1"),
    BigInt(plan.chainId),
    BigInt(seal),
    BigInt(canary.ownerAddress),
    canary.periodStart,
    canary.periodEnd,
  ]));
  let canaryIndex = -1;
  const entries = [];
  for (let index = 0; index < count; index += 1) {
    const raw = await provider.callContract({
      contractAddress: seal,
      entrypoint: "get_payroll_book_entry",
      calldata: [canary.ownerAddress, canary.periodStart, canary.periodEnd, index],
    }, "latest");
    const low = BigInt(raw[0] ?? 0);
    const high = BigInt(raw[1] ?? 0);
    entries.push(num.toHex((high << 128n) | low));
    if (high === entryHigh && low === entryLow) canaryIndex = index;
    accumulator = BigInt(hash.computePoseidonHashOnElements([
      shortString.encodeShortString("PAYO_BOOK_ADD_V1"),
      accumulator,
      high,
      low,
      BigInt(index),
    ]));
  }
  if (canaryIndex < 0 || accumulator !== BigInt(book[2] ?? 0)) {
    throw new Error("The canary entry is absent or the complete Mainnet book accumulator is invalid.");
  }
  return {
    passed: true,
    observedAt: new Date().toISOString(),
    transactionHash: canary.transactionHash,
    blockNumber: receipt.block_number,
    scheduleId: canary.scheduleId,
    nextStateCommitment: canary.nextStateCommitment,
    releaseNullifier: canary.releaseNullifier,
    bookEntryCommitment: canary.bookEntryCommitment,
    bookEntryIndex: canaryIndex,
    bookEntryCount: count,
    bookAccumulatorRoot: num.toHex(accumulator),
    allBookEntries: entries,
  };
}

const context = await loadContext();
await requireMainnet();

if (action === "plan") {
  const plan = buildPayoVestingBookMainnetPlan(context);
  assertPayoVestingBookMainnetPlan(plan, context);
  await assertLiveDependencies(plan);
  await Promise.all([
    saveJson(PLAN_PATH, plan),
    saveJson(PUBLIC_PLAN_PATH, {
      ...plan,
      source: "circuits/vesting_transition/target/payo-vesting-book-mainnet-plan.json",
      mutationSubmitted: false,
    }),
  ]);
  process.stdout.write(`${JSON.stringify({ planPath: PLAN_PATH, publicPlanPath: PUBLIC_PLAN_PATH, plan }, null, 2)}\n`);
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
    balanceStrk: Number(balance) / 1e18,
    status,
  }, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify-canary") {
  const inputPath = process.argv[3];
  if (!inputPath) throw new Error("verify-canary requires the exported canary JSON path.");
  const canary = await verifyCanary(plan, await readJson(resolve(inputPath)));
  await updateEvidence(plan, async (evidence) => ({ ...evidence, canary }));
  process.stdout.write(`${JSON.stringify(canary, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify") {
  const blockNumber = await provider.getBlockNumber();
  const [dependencies, status, proofVerification, balance] = await Promise.all([
    assertLiveDependencies(plan, blockNumber),
    liveStatus(plan, blockNumber),
    verifyRealProofPair(plan),
    readBalance(plan.deployerAddress),
  ]);
  if (!Object.values(status.declarations).every(Boolean)
    || !Object.values(status.contracts).every(({ deployed }) => deployed)
    || !status.wiring.passed || !status.profile.matches) {
    throw new Error("The VestingBook Mainnet topology is not fully deployed, wired and active.");
  }
  const verification = {
    passed: true,
    observedAt: new Date().toISOString(),
    blockNumber,
    dependencies,
    status,
    proofVerification,
    balanceFri: balance.toString(),
    canaryRequired: true,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, verification }));
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
  process.exit(0);
}

const account = accountFromEnvironment(plan.deployerAddress);

if (action === "estimate") {
  const estimate = await estimateAll(plan, context, account);
  await saveJson(PUBLIC_PLAN_PATH, {
    ...plan,
    source: "circuits/vesting_transition/target/payo-vesting-book-mainnet-plan.json",
    mutationSubmitted: false,
    feeEstimate: estimate,
  });
  process.stdout.write(`${JSON.stringify(estimate, null, 2)}\n`);
  process.exit(0);
}

if (action === "declare") {
  if (process.env.PAYO_VESTING_MAINNET_CONFIRM !== "DECLARE_PAYO_VESTING_MAINNET") {
    throw new Error(
      "Refusing declarations without PAYO_VESTING_MAINNET_CONFIRM=DECLARE_PAYO_VESTING_MAINNET.",
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
    const fee = await account.estimateDeclareFee(payload, { nonce, skipValidate: false, tip });
    const balance = await readBalance(plan.deployerAddress);
    if (balance < BigInt(fee.overall_fee)) {
      throw new Error(`${name} declaration requires ${fee.overall_fee} FRI; balance is ${balance}.`);
    }
    let submitted;
    try {
      submitted = await account.declare(payload, { nonce, resourceBounds: fee.resourceBounds, tip });
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
  const pending = vestingBookDeploymentPayloads(plan)
    .filter(({ name }) => !status.contracts[name].deployed);
  if (pending.length === 0) {
    process.stdout.write(`${JSON.stringify({ alreadyDeployed: true })}\n`);
    process.exit(0);
  }
  if (process.env.PAYO_VESTING_MAINNET_CONFIRM !== "DEPLOY_PAYO_VESTING_MAINNET") {
    throw new Error(
      "Refusing deployment without PAYO_VESTING_MAINNET_CONFIRM=DEPLOY_PAYO_VESTING_MAINNET.",
    );
  }
  const tip = mutationTip();
  const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
  const fee = await account.estimateDeployFee(pending.map(({ payload }) => payload), {
    nonce,
    skipValidate: false,
    tip,
  });
  const balance = await readBalance(plan.deployerAddress);
  if (balance < BigInt(fee.overall_fee)) {
    throw new Error(`Deployment requires ${fee.overall_fee} FRI; balance is ${balance}.`);
  }
  const submitted = await account.deploy(pending.map(({ payload }) => payload), {
    nonce,
    resourceBounds: fee.resourceBounds,
    tip,
  });
  const confirmation = await waitForPostcondition(
    submitted.transaction_hash,
    "VestingBook deployment",
    async () => {
      for (const item of pending) {
        const actual = await deployedClassHash(item.address);
        if (!actual || !sameHex(actual, plan.contracts[item.name].classHash)) return false;
      }
      return true;
    },
  );
  const after = await liveStatus(plan);
  if (!pending.every(({ name }) => after.contracts[name].deployed) || !after.wiring.passed) {
    throw new Error("The VestingBook deployment failed immutable wiring read-back.");
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
    wiring: after.wiring,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, deployment }));
  process.stdout.write(`${JSON.stringify(deployment, null, 2)}\n`);
  process.exit(0);
}

if (action === "activate") {
  const status = await liveStatus(plan);
  if (!Object.values(status.contracts).every(({ deployed }) => deployed) || !status.wiring.passed) {
    throw new Error("Deploy and verify all three VestingBook contracts before activation.");
  }
  if (status.profile.matches) {
    process.stdout.write(`${JSON.stringify({ alreadyActive: true, profile: status.profile })}\n`);
    process.exit(0);
  }
  if (process.env.PAYO_VESTING_MAINNET_CONFIRM !== "ACTIVATE_PAYO_VESTING_MAINNET") {
    throw new Error(
      "Refusing activation without PAYO_VESTING_MAINNET_CONFIRM=ACTIVATE_PAYO_VESTING_MAINNET.",
    );
  }
  const window = await activationWindow();
  const call = activationCall(plan, window);
  const tip = mutationTip();
  const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
  const fee = await account.estimateInvokeFee(call, { nonce, skipValidate: false, tip });
  const balance = await readBalance(plan.deployerAddress);
  if (balance < BigInt(fee.overall_fee)) {
    throw new Error(`Activation requires ${fee.overall_fee} FRI; balance is ${balance}.`);
  }
  const submitted = await account.execute(call, {
    nonce,
    resourceBounds: fee.resourceBounds,
    tip,
  });
  const confirmation = await waitForPostcondition(
    submitted.transaction_hash,
    "VestingBook verifier activation",
    async () => (await readVerifierProfile(plan)).matches,
  );
  const profile = await readVerifierProfile(plan);
  if (!profile.matches) throw new Error("The v3 verifier failed registry read-back.");
  const activation = {
    transactionHash: submitted.transaction_hash,
    nonce: num.toHex(BigInt(nonce)),
    tip: tip.toString(),
    recoveredFromWaitError: confirmation.recoveredFromWaitError,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: actualFee(confirmation.receipt),
    blockNumber: confirmation.receipt.block_number,
    ...window,
    profile,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, activation }));
  process.stdout.write(`${JSON.stringify(activation, null, 2)}\n`);
}
