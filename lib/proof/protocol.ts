import type { InputMap } from "@noir-lang/noir_js";
import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import type { SerializedPayrollIntegrityBuildRequest } from "./input-builder";
import type { EmploymentAgreement } from "@/lib/domain/obligations";
import type { ExceptionPublicInputsV2 } from "@/lib/domain/exception-protocol";

export const PAYROLL_INTEGRITY_CIRCUIT_URL = "/circuits/payroll_integrity-v1.json";
export const PAYROLL_INTEGRITY_CIRCUIT_SHA256 =
  "0x3c739cc5bc376bfc3a9c46d316118107e9c97acd4e37e938de116c841b678f78";
export const PAYROLL_INTEGRITY_VERIFICATION_KEY_URL =
  "/circuits/payroll_integrity-v1.vk.hex";
export const PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256 =
  "0xd622dff7f86da80f1b9e2fae58d4aee071d2fdec5ae018bcec353a6ce8941d96";
export const ADVANCED_OBLIGATION_CIRCUIT_URL = "/circuits/advanced_obligation-v2.json";
export const ADVANCED_OBLIGATION_CIRCUIT_SHA256 =
  "0x755bb9374c9cfc72cbd36b1a3e1d8c5e2792b11b8b08e190d2743dc508ebbe41";
export const ADVANCED_OBLIGATION_VERIFICATION_KEY_URL = "/circuits/advanced_obligation-v2.vk.hex";
export const ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256 =
  "0x50063de39c922bf1fe1089ff8b5e6839a56387da99e82e9071f067b9f72c90d7";
export const WAGE_CLAIM_CIRCUIT_SHA256 =
  "0x00dc2ef57f65d12d5d7c3ad8c1fefd2835c5474bbef5df9400b9e73d4f940287";
export const WAGE_CLAIM_CIRCUIT_URL = "/circuits/wage_claim-v3.json";
export const WAGE_CLAIM_VERIFICATION_KEY_URL = "/circuits/wage_claim-v3.vk.hex";
export const WAGE_CLAIM_VERIFICATION_KEY_SHA256 =
  "0x5e5f5ec0d36b41000470cbc7641a4312faabadf3f8e9da4f2c7d8db273db42d9";
export const WAGE_REMEDIATION_CIRCUIT_SHA256 =
  "0xd82738ad7db9867f4f86a8edcac02e72ee6d5fbbaa7d68bf9a521a23540e1d0c";
export const WAGE_REMEDIATION_CIRCUIT_URL = "/circuits/wage_remediation-v4.json";
export const WAGE_REMEDIATION_VERIFICATION_KEY_URL = "/circuits/wage_remediation-v4.vk.hex";
export const WAGE_REMEDIATION_VERIFICATION_KEY_SHA256 =
  "0x09c496d66bbf803a92b617840e12a403c8036a05e7e6437acd59d01d87910045";
export const OBLIGATION_SNAPSHOT_LINK_CIRCUIT_URL = "/circuits/obligation_snapshot_link-v5.json";
export const OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256 =
  "0x0ab9ec30937c59911dc57b70e5cb1a3f837a06ea0b9fd8aebdcc90221663707d";
export const OBLIGATION_SNAPSHOT_LINK_VERIFICATION_KEY_URL = "/circuits/obligation_snapshot_link-v5.vk.hex";
export const OBLIGATION_SNAPSHOT_LINK_VERIFICATION_KEY_SHA256 =
  "0xf93551c79f62cebab72ef651e0ebf1c230e7e5f56481ef20bfcd2a6b6698626a";
export const WAGE_CLAIM_VNEXT_CIRCUIT_URL = "/circuits/wage_claim-v6.json";
export const WAGE_CLAIM_VNEXT_CIRCUIT_SHA256 =
  "0xcc85586de2e3ea273e6769cdefcab96df4d781e7fee9da303c353c34b749c2bf";
export const WAGE_CLAIM_VNEXT_VERIFICATION_KEY_URL = "/circuits/wage_claim-v6.vk.hex";
export const WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256 =
  "0xd957476608ea70eaabb5e10d3706b6e2edb06abbf7c409cef8085ec7c21f3fc0";
export const WAGE_REMEDIATION_VNEXT_CIRCUIT_URL = "/circuits/wage_remediation-v7.json";
export const WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256 =
  "0x18c0c90caaf5e3caf412acce0c197a13e3d90f79e2166308dd08a6ae299ade54";
export const WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_URL = "/circuits/wage_remediation-v7.vk.hex";
export const WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256 =
  "0xc31a0a4455735625f55bcc94d2f4ef366627872d09fc0fd5f91ffd4eba152525";
export const PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT = 17;
export const PAYO_EXCEPTION_PUBLIC_INPUT_COUNT = 23;
// Starknet Mainnet accepts at most 5,000 invoke calldata felts. PAYO's
// account + seal wrapper contributes eight felts around each raw Garaga proof,
// so every generated or accepted proof must fit this fail-closed budget.
export const STARKNET_MAX_INVOKE_CALLDATA_FELTS = 5_000;
export const PAYO_PROOF_SUBMISSION_OVERHEAD_FELTS = 8;
export const PAYO_MAX_PROOF_CALLDATA_FELTS =
  STARKNET_MAX_INVOKE_CALLDATA_FELTS - PAYO_PROOF_SUBMISSION_OVERHEAD_FELTS;
// The pinned 2^20-domain circuit peaks below 2 GiB in the one-thread WASM
// benchmark. Android Chrome can reject bb.js' 4 GiB default reservation even
// when the circuit never consumes it, so mobile workers use a measured 2.25
// GiB ceiling with headroom instead.
export const PAYROLL_MOBILE_WASM_MAXIMUM_PAGES = 36_864;
// The 32 GiB self-hosted prover can reserve the full WebAssembly address
// space required by the merged v2 proving key. Do not reuse the mobile cap.
export const PAYROLL_SERVER_WASM_MAXIMUM_PAGES = 65_536;

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
} | {
  advancedBuildInput: {
    payroll: SerializedPayrollIntegrityBuildRequest;
    agreements: EmploymentAgreement[];
  };
} | {
  circuitProfile: "wage_claim" | "wage_remediation";
  circuitInputs: [InputMap, InputMap];
} | {
  exceptionCircuitProfile: ExceptionCircuitProfile;
  circuitInput: InputMap;
};

export type ExceptionCircuitProfile =
  | "obligation_snapshot_v5"
  | "wage_claim_v6"
  | "wage_remediation_v7";

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

export type ExceptionCircuitProof = {
  proof: Uint8Array;
  proofCalldata: string[];
  calldataHash: string;
  publicInputs: ExceptionPublicInputsV2;
};

export type ExceptionProofWorkerSuccess = {
  version: 2;
  type: "exception-proof-complete";
  requestId: string;
  profile: ExceptionCircuitProfile;
  scheme: "ultra_keccak_zk_honk";
  proof: ExceptionCircuitProof;
  circuitSha256: string;
  provingTimeMs: number;
};

export type PayoProofWorkerSuccess = ProofWorkerSuccess | ExceptionProofWorkerSuccess;

export type ExceptionProofWorkerRequest = {
  version: 2;
  type: "prove-payo-exception";
  requestId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
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
    | "CALLDATA_GENERATION_FAILED"
    | "CALLDATA_LIMIT_EXCEEDED";
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
    CALLDATA_LIMIT_EXCEEDED: "The verified proof exceeds Starknet's transaction calldata limit.",
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
