import type { InputMap } from "@noir-lang/noir_js";
import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";

export const PAYROLL_INTEGRITY_CIRCUIT_URL = "/circuits/payroll_integrity-v1.json";
export const PAYROLL_INTEGRITY_CIRCUIT_SHA256 =
  "0x3c739cc5bc376bfc3a9c46d316118107e9c97acd4e37e938de116c841b678f78";
export const PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT = 17;

export type EncryptedPayrollWitness = {
  circuitInputs: [InputMap, InputMap];
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
  publicInputs: PayrollIntegrityPublicInputs;
};

export type ProofWorkerProgress = {
  version: 1;
  type: "proof-progress";
  requestId: string;
  stage: "loading" | "executing" | "proving" | "verifying";
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
  code: "INVALID_REQUEST" | "CIRCUIT_LOAD_FAILED" | "WITNESS_INVALID" | "PROVING_FAILED" | "SELF_VERIFY_FAILED";
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
    WITNESS_INVALID: "The encrypted payroll witness did not satisfy PayrollIntegrity.",
    PROVING_FAILED: "The local proof could not be generated.",
    SELF_VERIFY_FAILED: "The generated proof failed local verification.",
  };
  return { version: 1, type: "proof-failed", requestId, code, message: messages[code] };
}
