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
  PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH,
  PAYO_PRIVATE_EXIT_MAINNET_CHAIN_ID,
  assertPayoAnonymizerAbi,
  assertPayoPrivateExitMainnetPlan,
  buildPayoPrivateExitMainnetPlan,
  privateExitDeploymentPayload,
} from "./lib/payo-private-exit-mainnet.mjs";

const DEFAULT_RPC_URL = "https://api.cartridge.gg/x/starknet/mainnet";
const STRK_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const ROOT = resolve(import.meta.dirname, "..");
const UPSTREAM_EVIDENCE_PATH = resolve(ROOT, "evidence/block5-private-exit-upstream.json");
const PLAN_PATH = resolve(ROOT, "evidence/private-exit-mainnet-plan.json");
const DEPLOYMENT_EVIDENCE_PATH = resolve(ROOT, "evidence/private-exit-mainnet.json");
const ACTIONS = new Set(["plan", "status", "estimate", "deploy", "verify"]);
const action = process.argv[2];
if (!ACTIONS.has(action)) {
  throw new Error(
    "Usage: node scripts/payo-private-exit-mainnet.mjs <plan|status|estimate|deploy|verify>",
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

function serializeJson(value) {
  return JSON.stringify(value, (_, item) => typeof item === "bigint" ? item.toString() : item, 2);
}

function sameFelt(left, right) {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

function canonicalAddress(value, label) {
  try {
    const parsed = validateAndParseAddress(value);
    if (BigInt(parsed) === 0n) throw new Error("zero");
    return num.toHex(BigInt(parsed));
  } catch {
    throw new Error(`${label} must be a non-zero Starknet address.`);
  }
}

function isMissingContract(error) {
  return /contract not found|contract_address_not_found|uninitialized contract/i
    .test(normalizeError(error));
}

function mutationTip() {
  const raw = process.env.PAYO_PRIVATE_EXIT_MAINNET_TIP ?? "1";
  if (!/^\d+$/.test(raw) || BigInt(raw) < 1n || BigInt(raw) > 1_000_000n) {
    throw new Error("PAYO_PRIVATE_EXIT_MAINNET_TIP must be an integer from 1 through 1000000.");
  }
  return BigInt(raw);
}

function formatStrk(fri) {
  const whole = fri / 10n ** 18n;
  const fraction = (fri % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
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
  await writeFile(path, `${serializeJson(value, null, 2)}\n`, { mode: 0o600 });
}

async function requireMainnet() {
  const chainId = await provider.getChainId();
  if (!sameFelt(chainId, constants.StarknetChainId.SN_MAIN)
    || !sameFelt(chainId, PAYO_PRIVATE_EXIT_MAINNET_CHAIN_ID)) {
    throw new Error(`Refusing private-exit action: RPC reports non-Mainnet chain ${chainId}.`);
  }
  return num.toHex(BigInt(chainId));
}

async function readReviewedClass(blockIdentifier = "latest") {
  const contractClass = await provider.getClass(
    PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH,
    blockIdentifier,
  );
  assertPayoAnonymizerAbi(contractClass.abi);
  return {
    classHash: PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH,
    contractClassVersion: contractClass.contract_class_version ?? null,
    emptyConstructor: true,
    exactPrivacyInvokeAbi: true,
  };
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
  const raw = await provider.callContract({
    contractAddress: STRK_ADDRESS,
    entrypoint: "balance_of",
    calldata: [address],
  }, "latest");
  return uint256.uint256ToBN({ low: raw[0], high: raw[1] });
}

function accountFromEnvironment(expectedAddress) {
  const address = canonicalAddress(
    process.env.PAYO_PROOF_RELAYER_ADDRESS,
    "PAYO_PROOF_RELAYER_ADDRESS",
  );
  if (!sameFelt(address, expectedAddress)) {
    throw new Error("The configured private-exit deployer differs from the reviewed plan.");
  }
  const privateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error("PAYO_PROOF_RELAYER_PRIVATE_KEY is required for fee simulation or deployment.");
  }
  return new Account({ provider, address, signer: privateKey, cairoVersion: "1" });
}

async function contextFromEnvironment() {
  return {
    deployerAddress: canonicalAddress(
      process.env.PAYO_PROOF_RELAYER_ADDRESS,
      "PAYO_PROOF_RELAYER_ADDRESS",
    ),
    upstreamEvidence: await readJson(UPSTREAM_EVIDENCE_PATH),
  };
}

async function loadReviewedPlan(context) {
  const record = await readJson(PLAN_PATH);
  if (!record?.plan) throw new Error("Generate and review the private-exit Mainnet plan first.");
  return { record, plan: assertPayoPrivateExitMainnetPlan(record.plan, context) };
}

async function liveStatus(plan, blockIdentifier = "latest") {
  const [reviewedClass, actualClassHash] = await Promise.all([
    readReviewedClass(blockIdentifier),
    deployedClassHash(plan.deployment.address, blockIdentifier),
  ]);
  return {
    reviewedClass,
    deployment: {
      address: plan.deployment.address,
      expectedClassHash: plan.deployment.classHash,
      actualClassHash,
      deployed: actualClassHash !== null,
      classHashMatches: actualClassHash !== null
        && sameFelt(actualClassHash, plan.deployment.classHash),
    },
  };
}

async function writePlanRecord(record) {
  await saveJson(PLAN_PATH, { ...record, mutationSubmitted: record.mutationSubmitted === true });
}

async function waitForPostcondition(transactionHash, plan) {
  try {
    return {
      receipt: await provider.waitForTransaction(transactionHash, {
        retries: 400,
        retryInterval: 3_000,
      }),
      recoveredFromWaitError: false,
    };
  } catch (waitError) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const classHash = await deployedClassHash(plan.deployment.address);
      if (classHash && sameFelt(classHash, plan.deployment.classHash)) {
        return {
          receipt: await provider.getTransactionReceipt(transactionHash),
          recoveredFromWaitError: true,
        };
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 3_000));
    }
    throw new Error(`Private-exit deployment did not reach read-back: ${normalizeError(waitError)}`);
  }
}

const context = await contextFromEnvironment();
await requireMainnet();

if (action === "plan") {
  const blockNumber = await provider.getBlockNumber();
  const reviewedClass = await readReviewedClass(blockNumber);
  const plan = buildPayoPrivateExitMainnetPlan(context);
  assertPayoPrivateExitMainnetPlan(plan, context);
  await writePlanRecord({
    plan,
    observedAtBlock: blockNumber,
    reviewedClass,
    mutationSubmitted: false,
    feeEstimate: null,
  });
  process.stdout.write(`${serializeJson({ planPath: PLAN_PATH, plan, reviewedClass }, null, 2)}\n`);
  process.exit(0);
}

const { record, plan } = await loadReviewedPlan(context);

if (action === "status") {
  const blockNumber = await provider.getBlockNumber();
  const [status, balance] = await Promise.all([
    liveStatus(plan, blockNumber),
    readBalance(plan.deployerAddress),
  ]);
  process.stdout.write(`${serializeJson({
    blockNumber,
    balanceFri: balance.toString(),
    balanceStrk: formatStrk(balance),
    status,
  }, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify") {
  const blockNumber = await provider.getBlockNumber();
  const status = await liveStatus(plan, blockNumber);
  if (!status.deployment.deployed || !status.deployment.classHashMatches) {
    throw new Error("The reviewed private-exit instance is not deployed with the exact class hash.");
  }
  const verification = {
    passed: true,
    observedAt: new Date().toISOString(),
    blockNumber,
    chainId: plan.chainId,
    ...status,
    canaryRequired: true,
  };
  await saveJson(DEPLOYMENT_EVIDENCE_PATH, {
    schemaVersion: "payo-private-exit-mainnet-evidence-v1",
    plan,
    deployment: (await readJsonIfExists(DEPLOYMENT_EVIDENCE_PATH, {})).deployment ?? null,
    verification,
  });
  process.stdout.write(`${serializeJson(verification, null, 2)}\n`);
  process.exit(0);
}

const status = await liveStatus(plan);
if (status.deployment.deployed && !status.deployment.classHashMatches) {
  throw new Error("The deterministic private-exit address is occupied by another class.");
}

if (action === "estimate") {
  let feeFri = 0n;
  let nonce = null;
  let resourceBounds = null;
  if (!status.deployment.deployed) {
    const account = accountFromEnvironment(plan.deployerAddress);
    nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
    const fee = await account.estimateDeployFee(privateExitDeploymentPayload(plan), {
      nonce,
      skipValidate: false,
      tip: mutationTip(),
    });
    feeFri = BigInt(fee.overall_fee);
    resourceBounds = fee.resourceBounds;
  }
  const balance = await readBalance(plan.deployerAddress);
  const estimate = {
    observedAt: new Date().toISOString(),
    alreadyDeployed: status.deployment.deployed,
    nonce: nonce === null ? null : num.toHex(BigInt(nonce)),
    feeFri: feeFri.toString(),
    feeStrk: formatStrk(feeFri),
    balanceFri: balance.toString(),
    balanceStrk: formatStrk(balance),
    currentlyFunded: balance >= feeFri,
    resourceBounds,
    mutationSubmitted: false,
  };
  await writePlanRecord({ ...record, feeEstimate: estimate, mutationSubmitted: false });
  process.stdout.write(`${serializeJson(estimate, null, 2)}\n`);
  process.exit(0);
}

if (status.deployment.deployed) {
  process.stdout.write(`${serializeJson({ alreadyDeployed: true, status }, null, 2)}\n`);
  process.exit(0);
}
if (process.env.PAYO_PRIVATE_EXIT_MAINNET_CONFIRM !== "DEPLOY_PAYO_PRIVATE_EXIT_MAINNET") {
  throw new Error(
    "Refusing deployment without PAYO_PRIVATE_EXIT_MAINNET_CONFIRM=DEPLOY_PAYO_PRIVATE_EXIT_MAINNET.",
  );
}
const account = accountFromEnvironment(plan.deployerAddress);
const tip = mutationTip();
const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
const payload = privateExitDeploymentPayload(plan);
const fee = await account.estimateDeployFee(payload, { nonce, skipValidate: false, tip });
const balance = await readBalance(plan.deployerAddress);
if (balance < BigInt(fee.overall_fee)) {
  throw new Error(`Private-exit deployment requires ${fee.overall_fee} FRI; balance is ${balance}.`);
}
const submitted = await account.deploy(payload, {
  nonce,
  resourceBounds: fee.resourceBounds,
  tip,
});
const confirmation = await waitForPostcondition(submitted.transaction_hash, plan);
const after = await liveStatus(plan, confirmation.receipt.block_number ?? "latest");
if (!after.deployment.deployed || !after.deployment.classHashMatches) {
  throw new Error("Private-exit deployment failed exact class-hash read-back.");
}
const deployment = {
  transactionHash: submitted.transaction_hash,
  contractAddress: plan.deployment.address,
  classHash: plan.deployment.classHash,
  nonce: num.toHex(BigInt(nonce)),
  tip: tip.toString(),
  simulatedFeeFri: fee.overall_fee.toString(),
  actualFeeFri: BigInt(confirmation.receipt.actual_fee?.amount ?? 0).toString(),
  blockNumber: confirmation.receipt.block_number,
  recoveredFromWaitError: confirmation.recoveredFromWaitError,
  readback: after,
};
await Promise.all([
  writePlanRecord({ ...record, mutationSubmitted: true }),
  saveJson(DEPLOYMENT_EVIDENCE_PATH, {
    schemaVersion: "payo-private-exit-mainnet-evidence-v1",
    plan,
    deployment,
    verification: null,
  }),
]);
process.stdout.write(`${serializeJson(deployment, null, 2)}\n`);
