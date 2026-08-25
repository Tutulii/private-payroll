import type { InputMap } from "@noir-lang/noir_js";
import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import type { SerializedPayrollIntegrityBuildRequest } from "./input-builder";

export const PAYROLL_INTEGRITY_CIRCUIT_URL = "/circuits/payroll_integrity-v1.json";
export const PAYROLL_INTEGRITY_CIRCUIT_SHA256 =
  "0x3c739cc5bc376bfc3a9c46d316118107e9c97acd4e37e938de116c841b678f78";
export const PAYROLL_INTEGRITY_VERIFICATION_KEY_URL =
  "/circuits/payroll_integrity-v1.vk.hex";
export const PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256 =
  "0xd622dff7f86da80f1b9e2fae58d4aee071d2fdec5ae018bcec353a6ce8941d96";
export const PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT = 17;
// The pinned 2^20-domain circuit peaks below 2 GiB in the one-thread WASM
// benchmark. Android Chrome can reject bb.js' 4 GiB default reservation even
// when the circuit never consumes it, so mobile workers use a measured 2.25
// GiB ceiling with headroom instead.
export const PAYROLL_MOBILE_WASM_MAXIMUM_PAGES = 36_864;

export function payrollProverBackendOptions(input: {
  userAgent: string;
  crossOriginIsolated: boolean;
  hardwareConcurrency: number;
}): { threads: number; memory?: { maximum: number } } {
  const mobile = /Android|iPad|iPhone|Mobile/i.test(input.userAgent);
  return {
    threads: mobile || !input.crossOriginIsolated
      ? 1
      : Math.max(1, Math.min(4, input.hardwareConcurrency || 1)),
    ...(mobile ? { memory: { maximum: PAYROLL_MOBILE_WASM_MAXIMUM_PAGES } } : {}),
  };
}

export type EncryptedPayrollWitness = {
  circuitInputs: [InputMap, InputMap];
} | {
  buildInput: SerializedPayrollIntegrityBuildRequest;
};

export type ProofWorkerRequest = {
  version: 1;
  type: "prove-payroll-integrity";
  requestId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
};

export type PayrollIntegrityPublicInputs = {
  chainId: string;
  sealAddress: string;
  proofVersion: string;
  schemaVersion: string;
  agreementRootHigh: string;
  agreementRootLow: string;
  manifestRootHigh: string;
  manifestRootLow: string;
  policyRootHigh: string;
  policyRootLow: string;
  fxRootHigh: string;
  fxRootLow: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  validityStart: string;
  validityExpiry: string;
  shardIndex: string;
};

export type PayrollIntegrityShardProof = {
  shardIndex: 0 | 1;
  proof: Uint8Array;
  proofCalldata: string[];
  calldataHash: string;
  publicInputs: PayrollIntegrityPublicInputs;
};

export type ProofWorkerProgress = {
  version: 1;
  type: "proof-progress";
  requestId: string;
  stage: "loading" | "executing" | "proving" | "verifying" | "encoding";
};

export type ProofWorkerSuccess = {
  version: 1;
  type: "proof-complete";
  requestId: string;
  scheme: "ultra_keccak_zk_honk";
  shards: [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  circuitSha256: string;
  provingTimeMs: number;
};

export type ProofWorkerFailure = {
  version: 1;
  type: "proof-failed";
  requestId: string;
  code:
    | "INVALID_REQUEST"
    | "CIRCUIT_LOAD_FAILED"
    | "VERIFICATION_KEY_LOAD_FAILED"
    | "WITNESS_INVALID"
    | "PROVING_FAILED"
    | "PROVING_RESOURCE_EXHAUSTED"
    | "SELF_VERIFY_FAILED"
    | "CALLDATA_GENERATION_FAILED";
  message: string;
};

export type ProofWorkerResponse = ProofWorkerProgress | ProofWorkerSuccess | ProofWorkerFailure;

export function mapPayrollPublicInputs(values: readonly string[]): PayrollIntegrityPublicInputs {
  if (values.length !== PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT) {
    throw new Error(`Expected ${PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT} public inputs; received ${values.length}.`);
  }
  return {
    chainId: values[0],
    sealAddress: values[1],
    proofVersion: values[2],
    schemaVersion: values[3],
    agreementRootHigh: values[4],
    agreementRootLow: values[5],
    manifestRootHigh: values[6],
    manifestRootLow: values[7],
    policyRootHigh: values[8],
    policyRootLow: values[9],
    fxRootHigh: values[10],
    fxRootLow: values[11],
    runNullifierHigh: values[12],
    runNullifierLow: values[13],
    validityStart: values[14],
    validityExpiry: values[15],
    shardIndex: values[16],
  };
}

export function safeProofFailure(
  requestId: string,
  code: ProofWorkerFailure["code"],
): ProofWorkerFailure {
  const messages: Record<ProofWorkerFailure["code"], string> = {
    INVALID_REQUEST: "The encrypted proof request is invalid.",
    CIRCUIT_LOAD_FAILED: "The pinned PayrollIntegrity circuit could not be loaded.",
    VERIFICATION_KEY_LOAD_FAILED: "The pinned PayrollIntegrity verification key could not be loaded.",
    WITNESS_INVALID: "The encrypted payroll witness did not satisfy PayrollIntegrity.",
    PROVING_FAILED: "The local proof could not be generated.",
    PROVING_RESOURCE_EXHAUSTED: "This device ran out of browser memory while generating the local proof. Close other tabs and apps, then retry; if it repeats, use a desktop browser with at least 4 GB available.",
    SELF_VERIFY_FAILED: "The generated proof failed local verification.",
    CALLDATA_GENERATION_FAILED: "The verified proof could not be encoded for the Starknet verifier.",
  };
  return { version: 1, type: "proof-failed", requestId, code, message: messages[code] };
}

export function classifyProofFailure(
  error: unknown,
  fallback: ProofWorkerFailure["code"],
): ProofWorkerFailure["code"] {
  if (fallback !== "PROVING_FAILED") return fallback;
  const description = error instanceof Error ? `${error.name} ${error.message}` : String(error);
  return /out of memory|memory access|cannot enlarge|could not allocate|allocation failed|bad alloc|array buffer|wasm.*memory|unreachable/i.test(description)
    ? "PROVING_RESOURCE_EXHAUSTED"
    : fallback;
}
