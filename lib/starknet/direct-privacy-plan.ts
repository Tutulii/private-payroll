import { num, validateAndParseAddress, type Call } from "starknet";
import type {
  DirectPrivacyAccountConfig,
  DirectPrivacyRunMaterial,
} from "@/lib/domain/direct-privacy";
import {
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  STARKNET_MAX_INVOKE_CALLDATA_FELTS,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { buildPayoSealedPayroll, type PayoSealedPayroll } from "./payo-seal";

type PrivacyActions = {
  createNotes: Array<{ recipient: bigint; token: bigint; amount: bigint }>;
  surpluses: Array<{ recipient: bigint; token: bigint; withdraw: false }>;
};

export type DirectPrivacyPlan = {
  actions: PrivacyActions;
  sealedPayroll: PayoSealedPayroll;
  tokenAddresses: readonly string[];
};

type SdkExecuteResult = {
  callAndProof: {
    call: { contractAddress: string; entrypoint: string; calldata?: readonly string[] };
    proof: {
      data: string;
      output: readonly string[];
      proofFacts: readonly string[];
      additionalData?: unknown;
    };
  };
  warnings: readonly { code: string; message: string }[];
};

const U128_MASK = (1n << 128n) - 1n;
// Relayer account calldata, execute_from_outside_v2 fields, the one Call
// wrapper and the session signature sit outside execute_policy_intent.
const DIRECT_POLICY_OUTER_OVERHEAD_FELTS = 96;

function canonicalAddress(value: string, label: string): string {
  try {
    return validateAndParseAddress(value);
  } catch {
    throw new Error(`${label} is not a canonical Starknet address.`);
  }
}

function canonicalFelt(value: string, label: string): `0x${string}` {
  let parsed: bigint;
  try { parsed = BigInt(value); } catch { throw new Error(`${label} is not a felt.`); }
  if (parsed < 0n || parsed >= (1n << 251n) + 17n * (1n << 192n) + 1n) {
    throw new Error(`${label} is outside the Starknet field.`);
  }
  return num.toHex(parsed) as `0x${string}`;
}

function rootFromLimbs(high: string, low: string): `0x${string}` {
  const highValue = BigInt(high);
  const lowValue = BigInt(low);
  if (highValue < 0n || highValue > U128_MASK || lowValue < 0n || lowValue > U128_MASK) {
    throw new Error("PAYO proof root limbs are outside u128.");
  }
  return `0x${((highValue << 128n) | lowValue).toString(16).padStart(64, "0")}`;
}

export function splitDirectPrivacyRoot(value: string): readonly [`0x${string}`, `0x${string}`] {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("Direct private policy roots must be exactly 32 bytes.");
  }
  const root = BigInt(value);
  return [num.toHex(root >> 128n) as `0x${string}`, num.toHex(root & U128_MASK) as `0x${string}`];
}

function assertRoot(label: string, actual: string, expected: string): void {
  if (BigInt(actual) !== BigInt(expected)) {
    throw new Error(`The proved ${label} does not match the owner-authorized run.`);
  }
}

/**
 * Converts only PostgreSQL-authoritative PaymentIntents into SDK actions. No
 * target, calldata, call array, proof, or signer value is accepted here.
 */
export function buildDirectPrivacyPlan(input: {
  config: DirectPrivacyAccountConfig;
  material: DirectPrivacyRunMaterial;
  payrollProof: ProofWorkerSuccess;
  nowUnixSeconds?: bigint;
}): DirectPrivacyPlan {
  if (input.config.sealMode !== 0) {
    throw new Error("SettlementMatch FINALIZE requires the Phase 4 direct-finalization driver.");
  }
  const sealedPayroll = buildPayoSealedPayroll({
    sealAddress: input.config.sealAddress,
    chainId: input.config.chainId,
    shards: input.payrollProof.shards,
    nowUnixSeconds: input.nowUnixSeconds,
  });
  const publicInputs = input.payrollProof.shards[0].publicInputs;
  if (sealedPayroll.proofVersion !== input.config.proofVersion || sealedPayroll.schemaVersion !== input.config.schemaVersion) {
    throw new Error("The PAYO proof profile does not match the owner-configured policy account.");
  }
  assertRoot(
    "agreement root",
    rootFromLimbs(publicInputs.agreementRootHigh, publicInputs.agreementRootLow),
    input.material.policyRun.agreementRoot,
  );
  assertRoot(
    "manifest root",
    rootFromLimbs(publicInputs.manifestRootHigh, publicInputs.manifestRootLow),
    input.material.policyRun.manifestRoot,
  );
  assertRoot(
    "run nullifier",
    rootFromLimbs(publicInputs.runNullifierHigh, publicInputs.runNullifierLow),
    input.material.policyRun.runNullifier,
  );

  assertRoot(
    "payroll policy root",
    rootFromLimbs(publicInputs.policyRootHigh, publicInputs.policyRootLow),
    input.config.payrollPolicyRoot,
  );

  const policyAccount = canonicalAddress(input.config.policyAccountAddress, "Policy account");
  const createNotes = input.material.authoritativeRequest.intents.map((intent) => ({
    recipient: BigInt(canonicalAddress(intent.recipientAddress, "Private recipient")),
    token: BigInt(canonicalAddress(input.config.tokenAddresses[intent.token], `${intent.token} token`)),
    amount: BigInt(intent.amountAtomic),
  }));
  if (createNotes.some(({ amount }) => amount <= 0n)) {
    throw new Error("Direct private payroll amounts must be positive.");
  }
  const tokenAddresses = [...new Set(createNotes.map(({ token }) => num.toHex(token)))]
    .sort((left, right) => BigInt(left) < BigInt(right) ? -1 : 1);
  return {
    actions: {
      createNotes,
      surpluses: tokenAddresses.map((token) => ({
        recipient: BigInt(policyAccount),
        token: BigInt(token),
        withdraw: false as const,
      })),
    },
    sealedPayroll,
    tokenAddresses,
  };
}

/**
 * Validates the SDK target, action/output binding, proof facts and warnings.
 * This diagnostic layer does not authorize submission without the stricter
 * transaction-proof assertion below.
 */
export function assertDirectPrivacySdkResultBindings(input: {
  result: SdkExecuteResult;
  poolAddress: string;
}): void {
  const { call, proof } = input.result.callAndProof;
  if (BigInt(canonicalAddress(call.contractAddress, "SDK pool target")) !== BigInt(input.poolAddress)) {
    throw new Error("The Privacy SDK returned a substituted pool target.");
  }
  if (call.entrypoint !== "apply_actions") {
    throw new Error("The Privacy SDK returned a forbidden pool selector.");
  }
  if (!Array.isArray(call.calldata) || call.calldata.length < 2) {
    throw new Error("The Privacy SDK returned empty pool actions.");
  }
  const canonicalCalldata = call.calldata.map((value, index) =>
    canonicalFelt(value, `SDK pool calldata ${index}`));
  const canonicalOutput = proof.output.map((value, index) =>
    canonicalFelt(value, `SDK proof output ${index}`));
  if (canonicalOutput.length < 2) throw new Error("The Privacy SDK proof has no committed actions.");
  if (proof.additionalData !== undefined) {
    throw new Error("Autonomous private payroll forbids deposit screening data.");
  }
  const expectedCalldata = [...canonicalOutput.slice(1), "0x1"];
  if (
    expectedCalldata.length !== canonicalCalldata.length
    || expectedCalldata.some((value, index) => BigInt(value) !== BigInt(canonicalCalldata[index]))
  ) throw new Error("The SDK pool calldata is not bound to the prover output.");
  if (!Array.isArray(proof.proofFacts) || proof.proofFacts.length < 1) {
    throw new Error("The Privacy SDK did not return proof facts.");
  }
  proof.proofFacts.forEach((value, index) => canonicalFelt(value, `SDK proof fact ${index}`));
  if (input.result.warnings.length > 0) {
    throw new Error("The Privacy SDK reported a privacy warning; execution failed closed.");
  }
}

/** Rejects any SDK/prover substitution before a production policy-account signature exists. */
export function assertDirectPrivacySdkResult(input: {
  result: SdkExecuteResult;
  poolAddress: string;
}): void {
  assertDirectPrivacySdkResultBindings(input);
  const proof = input.result.callAndProof.proof;
  if (typeof proof.data !== "string" || proof.data.length < 16) {
    throw new Error("The Privacy SDK did not return a transaction proof.");
  }
}

/** The policy account accepts exactly this one self-call through SNIP-9 V2. */
export function buildDirectPrivacyPolicyCall(input: {
  config: DirectPrivacyAccountConfig;
  material: DirectPrivacyRunMaterial;
  poolCalldata: readonly string[];
  settlementProofChunks: readonly {
    chunkIndex: number;
    chunkCount: number;
    proofCalldata: readonly string[];
  }[];
}): Call {
  if (input.poolCalldata.length < 2 || input.poolCalldata.length > 12_000) {
    throw new Error("Direct private pool calldata is outside PAYO's bounded size.");
  }
  const [agreementHigh, agreementLow] = splitDirectPrivacyRoot(input.material.policyRun.agreementRoot);
  const [manifestHigh, manifestLow] = splitDirectPrivacyRoot(input.material.policyRun.manifestRoot);
  const [nullifierHigh, nullifierLow] = splitDirectPrivacyRoot(input.material.policyRun.runNullifier);
  const siblings = input.material.policyRun.siblings.map((value, index) =>
    canonicalFelt(value, `Run sibling ${index}`));
  const poolCalldata = input.poolCalldata.map((value, index) =>
    canonicalFelt(value, `Pool calldata ${index}`));
  // A direct autonomous run is deliberately capped at one three-line
  // SettlementMatch chunk.  Garaga proofs are ~3.2k felts and Starknet caps an
  // invoke at 5k felts, so multi-chunk atomic verification is impossible.  A
  // larger payroll must be split into separately authorized runs or use Ready.
  if (
    input.settlementProofChunks.length !== 1
    || input.settlementProofChunks[0].chunkIndex !== 0
    || input.settlementProofChunks[0].chunkCount !== 1
  ) {
    throw new Error("Autonomous private payroll supports exactly one atomic SettlementMatch chunk.");
  }
  const settlementProofCalldata = input.settlementProofChunks[0].proofCalldata
    .map((value, index) => canonicalFelt(value, `Settlement proof calldata ${index}`));
  if (
    settlementProofCalldata.length < 1
    || settlementProofCalldata.length > PAYO_MAX_PROOF_CALLDATA_FELTS
  ) {
    throw new Error("Settlement proof calldata is outside PAYO's bounded size.");
  }
  const policyCalldataLength = 10 + siblings.length
    + poolCalldata.length + settlementProofCalldata.length;
  if (
    policyCalldataLength
      > STARKNET_MAX_INVOKE_CALLDATA_FELTS - DIRECT_POLICY_OUTER_OVERHEAD_FELTS
  ) {
    throw new Error("The atomic private payroll exceeds Starknet's invoke calldata limit.");
  }
  return {
    contractAddress: canonicalAddress(input.config.policyAccountAddress, "Policy account"),
    entrypoint: "execute_policy_intent",
    calldata: [
      canonicalFelt(input.config.policyId, "Policy ID"),
      agreementHigh,
      agreementLow,
      manifestHigh,
      manifestLow,
      nullifierHigh,
      nullifierLow,
      num.toHex(input.material.policyRun.pathBits),
      num.toHex(siblings.length),
      ...siblings,
      num.toHex(poolCalldata.length),
      ...poolCalldata,
      num.toHex(settlementProofCalldata.length),
      ...settlementProofCalldata,
    ],
  };
}
