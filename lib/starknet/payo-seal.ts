import { num, validateAndParseAddress, type Call, type STRK20_INVOKE_ACTION } from "starknet";
import type {
  PayrollIntegrityPublicInputs,
  PayrollIntegrityShardProof,
} from "@/lib/proof/protocol";
import {
  hashProofCalldata,
  orderedPayrollPublicInputs,
} from "@/lib/proof/starknet-calldata";

export const PAYO_PROOF_MODE_PRECOMMIT = 0;
export const PAYO_PROOF_MODE_FINALIZE = 1;
export const PAYO_PROOF_MODE_CLAIM = 2;
export const PAYO_PROOF_MODE_REMEDIATE = 3;
export const PAYO_MAX_PROOF_VALIDITY_SECONDS = 3_600n;
export type PayoProofMode = 0 | 1 | 2 | 3;

const U8_LIMIT = 1n << 8n;
const U32_LIMIT = 1n << 32n;
const U64_LIMIT = 1n << 64n;
const U128_LIMIT = 1n << 128n;

type LinkedProofs = readonly [PayrollIntegrityShardProof, PayrollIntegrityShardProof];

export type PayoSealedPayroll = {
  invokeAction: STRK20_INVOKE_ACTION;
  proofVersion: number;
  schemaVersion: number;
  runNullifierHigh: string;
  runNullifierLow: string;
  manifestRootHigh: string;
  manifestRootLow: string;
  validityStart: bigint;
  validityExpiry: bigint;
  shardHashes: readonly [string, string];
};

const PROOF_VERSIONS_BY_MODE: Readonly<Record<PayoProofMode, readonly number[]>> = {
  [PAYO_PROOF_MODE_PRECOMMIT]: [1, 2],
  [PAYO_PROOF_MODE_FINALIZE]: [5],
  [PAYO_PROOF_MODE_CLAIM]: [3],
  [PAYO_PROOF_MODE_REMEDIATE]: [4],
};

function parseBounded(value: string, label: string, limit: bigint): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label} is not an integer.`);
  }
  if (parsed < 0n || parsed >= limit) throw new Error(`${label} is outside its canonical range.`);
  return parsed;
}

function canonicalAddress(value: string, label: string): string {
  try {
    return validateAndParseAddress(value);
  } catch {
    throw new Error(`${label} is not a canonical Starknet address.`);
  }
}

function assertSameLinkedInputs(
  shardZero: PayrollIntegrityPublicInputs,
  shardOne: PayrollIntegrityPublicInputs,
) {
  const zeroValues = orderedPayrollPublicInputs(shardZero);
  const oneValues = orderedPayrollPublicInputs(shardOne);
  for (let index = 0; index < 16; index += 1) {
    if (BigInt(zeroValues[index]) !== BigInt(oneValues[index])) {
      throw new Error(`PayrollIntegrity shard public input ${index} does not match.`);
    }
  }
  if (BigInt(shardZero.shardIndex) !== 0n || BigInt(shardOne.shardIndex) !== 1n) {
    throw new Error("PayrollIntegrity shards must be ordered 0 then 1.");
  }
}

function assertProofHash(shard: PayrollIntegrityShardProof): string {
  const calculated = hashProofCalldata(shard.proofCalldata);
  if (BigInt(calculated) !== BigInt(shard.calldataHash)) {
    throw new Error(`PayrollIntegrity shard ${shard.shardIndex} calldata hash does not match.`);
  }
  return calculated;
}

/**
 * Builds the pool-owned `privacy_invoke` fallback action. The STRK20 protocol
 * calls that fixed selector, so this action intentionally contains no selector.
 */
export function buildPayoSealedAction(input: {
  sealAddress: string;
  chainId: string;
  shards: LinkedProofs;
  mode: PayoProofMode;
  nowUnixSeconds?: bigint;
}): PayoSealedPayroll {
  const sealAddress = canonicalAddress(input.sealAddress, "PAYO seal address");
  const [shardZero, shardOne] = input.shards;
  if (shardZero.shardIndex !== 0 || shardOne.shardIndex !== 1) {
    throw new Error("PayrollIntegrity shards must be ordered 0 then 1.");
  }
  assertSameLinkedInputs(shardZero.publicInputs, shardOne.publicInputs);
  const proof = shardZero.publicInputs;
  if (BigInt(proof.sealAddress) !== BigInt(sealAddress)) {
    throw new Error("PayrollIntegrity is bound to a different PAYO seal address.");
  }
  if (BigInt(proof.chainId) !== BigInt(input.chainId)) {
    throw new Error("PayrollIntegrity is bound to a different Starknet chain.");
  }

  const proofVersion = parseBounded(proof.proofVersion, "Proof version", U32_LIMIT);
  const schemaVersion = parseBounded(proof.schemaVersion, "Schema version", U32_LIMIT);
  if (proofVersion === 0n || schemaVersion !== 1n) {
    throw new Error("PAYO requires a non-zero proof version and schema version 1.");
  }
  if (!PROOF_VERSIONS_BY_MODE[input.mode].includes(Number(proofVersion))) {
    throw new Error(`PAYO proof version ${proofVersion} is invalid for mode ${input.mode}.`);
  }
  const agreementRootHigh = parseBounded(proof.agreementRootHigh, "Agreement root high", U128_LIMIT);
  const agreementRootLow = parseBounded(proof.agreementRootLow, "Agreement root low", U128_LIMIT);
  const manifestRootHigh = parseBounded(proof.manifestRootHigh, "Manifest root high", U128_LIMIT);
  const manifestRootLow = parseBounded(proof.manifestRootLow, "Manifest root low", U128_LIMIT);
  const policyRootHigh = parseBounded(proof.policyRootHigh, "Policy root high", U128_LIMIT);
  const policyRootLow = parseBounded(proof.policyRootLow, "Policy root low", U128_LIMIT);
  const fxRootHigh = parseBounded(proof.fxRootHigh, "FX root high", U128_LIMIT);
  const fxRootLow = parseBounded(proof.fxRootLow, "FX root low", U128_LIMIT);
  const runNullifierHigh = parseBounded(proof.runNullifierHigh, "Run nullifier high", U128_LIMIT);
  const runNullifierLow = parseBounded(proof.runNullifierLow, "Run nullifier low", U128_LIMIT);
  const validityStart = parseBounded(proof.validityStart, "Validity start", U64_LIMIT);
  const validityExpiry = parseBounded(proof.validityExpiry, "Validity expiry", U64_LIMIT);
  if (
    validityExpiry < validityStart
    || validityExpiry - validityStart > PAYO_MAX_PROOF_VALIDITY_SECONDS
  ) {
    throw new Error("PayrollIntegrity validity must be ordered and no longer than one hour.");
  }
  const now = input.nowUnixSeconds ?? BigInt(Math.floor(Date.now() / 1_000));
  if (now < validityStart || now > validityExpiry) {
    throw new Error("PayrollIntegrity is not valid at the current time.");
  }

  const shardHashes = [assertProofHash(shardZero), assertProofHash(shardOne)] as const;
  const calldata = [
    input.mode,
    proofVersion,
    schemaVersion,
    agreementRootHigh,
    agreementRootLow,
    manifestRootHigh,
    manifestRootLow,
    policyRootHigh,
    policyRootLow,
    fxRootHigh,
    fxRootLow,
    runNullifierHigh,
    runNullifierLow,
    validityStart,
    validityExpiry,
    shardHashes[0],
    shardHashes[1],
    0,
    0,
  ].map((value) => num.toHex(value));

  return {
    invokeAction: { type: "invoke", contract: sealAddress, calldata },
    proofVersion: Number(proofVersion),
    schemaVersion: Number(schemaVersion),
    runNullifierHigh: num.toHex(runNullifierHigh),
    runNullifierLow: num.toHex(runNullifierLow),
    manifestRootHigh: num.toHex(manifestRootHigh),
    manifestRootLow: num.toHex(manifestRootLow),
    validityStart,
    validityExpiry,
    shardHashes,
  };
}

export function buildPayoSealedPayroll(input: {
  sealAddress: string;
  chainId: string;
  shards: LinkedProofs;
  nowUnixSeconds?: bigint;
}): PayoSealedPayroll {
  return buildPayoSealedAction({ ...input, mode: PAYO_PROOF_MODE_PRECOMMIT });
}

export function buildVerifySealedShardCall(input: {
  sealAddress: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  shard: PayrollIntegrityShardProof;
}): Call {
  return buildVerifySealedShardCalldataCall({
    sealAddress: input.sealAddress,
    runNullifierHigh: input.runNullifierHigh,
    runNullifierLow: input.runNullifierLow,
    shardIndex: input.shard.shardIndex,
    proofCalldata: input.shard.proofCalldata,
    calldataHash: input.shard.calldataHash,
  });
}

/**
 * Server-side relayers intentionally load only the public proof calldata and
 * its committed hash. They never need the encrypted raw proof or witness.
 */
export function buildVerifySealedShardCalldataCall(input: {
  sealAddress: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  shardIndex: 0 | 1;
  proofCalldata: readonly string[];
  calldataHash: string;
}): Call {
  const sealAddress = canonicalAddress(input.sealAddress, "PAYO seal address");
  const shardIndex = parseBounded(String(input.shardIndex), "Shard index", U8_LIMIT);
  if (shardIndex > 1n) throw new Error("PayrollIntegrity shard index must be 0 or 1.");
  const runNullifierHigh = parseBounded(input.runNullifierHigh, "Run nullifier high", U128_LIMIT);
  const runNullifierLow = parseBounded(input.runNullifierLow, "Run nullifier low", U128_LIMIT);
  const actualHash = hashProofCalldata(input.proofCalldata);
  if (BigInt(actualHash) !== BigInt(input.calldataHash)) {
    throw new Error(`PayrollIntegrity shard ${input.shardIndex} calldata hash does not match.`);
  }
  return {
    contractAddress: sealAddress,
    entrypoint: "verify_sealed_shard",
    calldata: [
      num.toHex(runNullifierHigh),
      num.toHex(runNullifierLow),
      num.toHex(shardIndex),
      num.toHex(input.proofCalldata.length),
      ...input.proofCalldata,
    ],
  };
}
