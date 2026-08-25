import { num } from "starknet";

export const PAYO_STRK_EVIDENCE_VERSION = "payo-proof-bound-strk-mainnet-v1";
export const STRK_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
export const STRK20_MAINNET_POOL_ADDRESS =
  "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a";
export const PAYO_GENERATED_VERIFIER_ADDRESS =
  "0x475cc47caf5d8b5b3a719915ceef5ae3e959f8754f2c0faa634d2e8c73d06db";
export const PAYO_BUNDLE_VERIFIER_ADDRESS =
  "0x2755c2260220f44c319249402887ca50c8b968ab43364e90de54f5afd66759";
export const PAYO_PAYROLL_SEAL_ADDRESS =
  "0x4bde3263ff117f245f9ebea20670b363550951f61cf54f236c449f70181c01f";

function normalized(value) {
  return num.toHex(num.toBigInt(value)).toLowerCase();
}

function assertFelt(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
    throw new Error(`${label} must be a canonical-sized 0x-prefixed Starknet value.`);
  }
  normalized(value);
}

function assertAddress(actual, expected, label) {
  assertFelt(actual, label);
  if (normalized(actual) !== normalized(expected)) throw new Error(`${label} is not the reviewed Mainnet address.`);
}

function versionAtLeast(version, minimum) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
    return false;
  }
  const parts = (value) => value.split(/[+-]/, 1)[0].split(".").map(Number);
  const left = parts(version);
  const right = parts(minimum);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    if ((left[index] ?? 0) !== (right[index] ?? 0)) return (left[index] ?? 0) > (right[index] ?? 0);
  }
  return true;
}

function assertAcceptedRecord(record, label) {
  assertFelt(record?.transactionHash, `${label} transaction hash`);
  if (!Number.isSafeInteger(record?.blockNumber) || record.blockNumber <= 0) {
    throw new Error(`${label} must include a positive safe block number.`);
  }
  if (record.executionStatus !== "SUCCEEDED") throw new Error(`${label} did not succeed.`);
  if (!["ACCEPTED_ON_L2", "ACCEPTED_ON_L1"].includes(record.finalityStatus)) {
    throw new Error(`${label} is not accepted on Starknet.`);
  }
}

export function validatePayoStrkEvidence(evidence) {
  if (evidence?.evidenceVersion !== PAYO_STRK_EVIDENCE_VERSION) {
    throw new Error("Unsupported PAYO STRK evidence version.");
  }
  if (evidence.network !== "SN_MAIN") throw new Error("PAYO STRK evidence must use Starknet Mainnet.");
  if (evidence.wallet?.name !== "Ready" || !versionAtLeast(evidence.wallet.walletApiVersion, "0.10.3")) {
    throw new Error("Evidence requires Ready Wallet API 0.10.3 or newer.");
  }
  if (evidence.token?.symbol !== "STRK" || evidence.token.decimals !== 18) {
    throw new Error("Evidence must describe 18-decimal STRK.");
  }
  assertAddress(evidence.token.address, STRK_ADDRESS, "STRK token address");
  assertAddress(evidence.contracts?.pool, STRK20_MAINNET_POOL_ADDRESS, "STRK20 pool address");
  assertAddress(
    evidence.contracts?.generatedVerifier,
    PAYO_GENERATED_VERIFIER_ADDRESS,
    "Generated verifier address",
  );
  assertAddress(
    evidence.contracts?.bundleVerifier,
    PAYO_BUNDLE_VERIFIER_ADDRESS,
    "Bundle verifier address",
  );
  assertAddress(evidence.contracts?.payrollSeal, PAYO_PAYROLL_SEAL_ADDRESS, "Payroll seal address");

  assertAcceptedRecord(evidence.payroll, "Payroll transaction");
  assertFelt(evidence.run?.nullifierHigh, "Run nullifier high limb");
  assertFelt(evidence.run?.nullifierLow, "Run nullifier low limb");
  if (
    evidence.run.onchainStatus !== 2
    || evidence.run.onchainStatusLabel !== "proven"
    || !Array.isArray(evidence.run.shardVerified)
    || evidence.run.shardVerified.length !== 2
    || evidence.run.shardVerified.some((value) => value !== true)
  ) {
    throw new Error("Evidence must record proven status and both verified proof shards.");
  }

  if (!Array.isArray(evidence.verifierShards) || evidence.verifierShards.length !== 2) {
    throw new Error("Evidence must contain exactly two verifier-shard transactions.");
  }
  const orderedShards = [...evidence.verifierShards].sort((left, right) => left.index - right.index);
  if (orderedShards[0]?.index !== 0 || orderedShards[1]?.index !== 1) {
    throw new Error("Verifier-shard indices must be exactly 0 and 1.");
  }
  orderedShards.forEach((shard) => assertAcceptedRecord(shard, `Verifier shard ${shard.index}`));
  const transactionHashes = [
    evidence.payroll.transactionHash,
    ...orderedShards.map((shard) => shard.transactionHash),
  ].map(normalized);
  if (new Set(transactionHashes).size !== transactionHashes.length) {
    throw new Error("Payroll and verifier-shard transaction hashes must be distinct.");
  }
  if (
    orderedShards[0].blockNumber < evidence.payroll.blockNumber
    || orderedShards[1].blockNumber < orderedShards[0].blockNumber
  ) {
    throw new Error("Verifier-shard blocks must not precede payroll or each other.");
  }

  const attestation = evidence.recipientAttestation;
  if (
    attestation?.source !== "employee_ready_wallet_and_user_confirmation"
    || attestation.asset !== "STRK"
    || attestation.recipientRelationship !== "external_employee_wallet"
    || attestation.publicSettlementProof !== "unavailable_by_design"
  ) {
    throw new Error("Evidence requires the privacy-bounded employee receipt attestation.");
  }
  if (evidence.privacy?.recipient !== "withheld" || evidence.privacy?.salaryAmount !== "withheld") {
    throw new Error("Private recipient and salary evidence must remain withheld.");
  }
  if (!evidence.topologyVerification?.passed || !Number.isSafeInteger(evidence.topologyVerification.blockNumber)) {
    throw new Error("Evidence requires a passed Mainnet topology verification block.");
  }
  for (const [value, label] of [
    [evidence.topologyVerification.verifiedAt, "Topology verifiedAt"],
    [evidence.observedAt, "Evidence observedAt"],
  ]) {
    if (!Number.isFinite(Date.parse(value))) throw new Error(`${label} is invalid.`);
  }
  return { orderedShards };
}

export function assertAcceptedReceipt(receipt, expected, label) {
  if (receipt?.execution_status !== "SUCCEEDED") throw new Error(`${label} did not succeed.`);
  if (!["ACCEPTED_ON_L2", "ACCEPTED_ON_L1"].includes(receipt.finality_status)) {
    throw new Error(`${label} is not accepted on Starknet.`);
  }
  if (receipt.transaction_hash && normalized(receipt.transaction_hash) !== normalized(expected.transactionHash)) {
    throw new Error(`${label} returned a different transaction hash.`);
  }
  if (receipt.block_number !== expected.blockNumber) throw new Error(`${label} block number differs from evidence.`);
  if (receipt.execution_status !== expected.executionStatus) throw new Error(`${label} execution status differs from evidence.`);
  if (receipt.finality_status !== expected.finalityStatus) throw new Error(`${label} finality status differs from evidence.`);
}

export function receiptHasEmitter(receipt, address) {
  return (receipt.events ?? []).some(
    (event) => normalized(event.from_address) === normalized(address),
  );
}
