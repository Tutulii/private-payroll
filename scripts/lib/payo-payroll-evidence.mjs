import { num } from "starknet";

export const PAYO_PAYROLL_EVIDENCE_VERSION = "payo-proof-bound-payroll-mainnet-v1";
export const STRK20_MAINNET_POOL_ADDRESS =
  "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a";
export const PAYO_GENERATED_VERIFIER_ADDRESS =
  "0x475cc47caf5d8b5b3a719915ceef5ae3e959f8754f2c0faa634d2e8c73d06db";
export const PAYO_BUNDLE_VERIFIER_ADDRESS =
  "0x2755c2260220f44c319249402887ca50c8b968ab43364e90de54f5afd66759";
export const PAYO_PAYROLL_SEAL_ADDRESS =
  "0x4bde3263ff117f245f9ebea20670b363550951f61cf54f236c449f70181c01f";

const reviewedTokens = {
  STRK: {
    address: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
    decimals: 18,
  },
  USDC: {
    address: "0x033068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb",
    decimals: 6,
  },
};

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
  if (normalized(actual) !== normalized(expected)) {
    throw new Error(`${label} is not the reviewed Mainnet address.`);
  }
}

function versionAtLeast(version, minimum) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
    return false;
  }
  const parts = (value) => value.split(/[+-]/, 1)[0].split(".").map(Number);
  const left = parts(version);
  const right = parts(minimum);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    if ((left[index] ?? 0) !== (right[index] ?? 0)) {
      return (left[index] ?? 0) > (right[index] ?? 0);
    }
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

function expectedSymbols(kind) {
  if (kind === "usdc-only") return ["USDC"];
  if (kind === "mixed-strk-usdc") return ["STRK", "USDC"];
  throw new Error("Evidence batch kind must be usdc-only or mixed-strk-usdc.");
}

export function validatePayoPayrollEvidence(evidence) {
  if (evidence?.evidenceVersion !== PAYO_PAYROLL_EVIDENCE_VERSION) {
    throw new Error("Unsupported PAYO payroll evidence version.");
  }
  if (evidence.network !== "SN_MAIN") throw new Error("PAYO payroll evidence must use Starknet Mainnet.");
  if (evidence.wallet?.name !== "Ready" || !versionAtLeast(evidence.wallet.walletApiVersion, "0.10.3")) {
    throw new Error("Evidence requires Ready Wallet API 0.10.3 or newer.");
  }

  const symbols = expectedSymbols(evidence.batch?.kind);
  if (!Array.isArray(evidence.batch?.tokens) || evidence.batch.tokens.length !== symbols.length) {
    throw new Error("Evidence token descriptors do not match the batch kind.");
  }
  symbols.forEach((symbol, index) => {
    const actual = evidence.batch.tokens[index];
    const reviewed = reviewedTokens[symbol];
    if (actual?.symbol !== symbol || actual.decimals !== reviewed.decimals) {
      throw new Error(`${symbol} descriptor has the wrong symbol or decimals.`);
    }
    assertAddress(actual.address, reviewed.address, `${symbol} token address`);
  });

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
    || evidence.run.durableState !== "confirmed"
    || evidence.run.proofVerificationState !== "onchain_verified"
    || evidence.run.proofJobState !== "complete"
    || !Array.isArray(evidence.run.shardVerified)
    || evidence.run.shardVerified.length !== 2
    || evidence.run.shardVerified.some((value) => value !== true)
  ) {
    throw new Error("Evidence must record a confirmed run, proven seal, and completed proof verification.");
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

  const attestation = evidence.privateFlowAttestation;
  const allowedAttestationSources = new Set([
    "authorized_ready_operator_confirmation",
    "authorized_ready_operator_and_recipient_wallet_observation",
  ]);
  if (
    !allowedAttestationSources.has(attestation?.source)
    || JSON.stringify(attestation.assets) !== JSON.stringify(symbols)
    || attestation.recipientRelationship !== "registered_recipient_wallet"
    || attestation.publicSettlementProof !== "unavailable_by_design"
    || !["confirmed", "awaiting_user_report"].includes(attestation.recipientBalanceObservation)
  ) {
    throw new Error("Evidence requires a privacy-bounded Ready operator attestation and an explicit recipient-observation state.");
  }
  if (
    attestation.source === "authorized_ready_operator_and_recipient_wallet_observation"
    && attestation.recipientBalanceObservation !== "confirmed"
  ) throw new Error("A recipient-wallet observation must be recorded as confirmed.");
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
  return { orderedShards, symbols };
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
  const acceptedFinality = receipt.finality_status === expected.finalityStatus
    || (expected.finalityStatus === "ACCEPTED_ON_L2" && receipt.finality_status === "ACCEPTED_ON_L1");
  if (!acceptedFinality) throw new Error(`${label} finality status regressed or differs from evidence.`);
}

export function receiptHasEmitter(receipt, address) {
  return (receipt.events ?? []).some((event) => normalized(event.from_address) === normalized(address));
}
