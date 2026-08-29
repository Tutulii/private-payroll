import { z } from "zod";
import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { starknetFeltSchema } from "@/lib/domain/proof-bundle";
import {
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  type ExceptionProofWorkerSuccess,
  type PayoProofWorkerSuccess,
  type ProofWorkerSuccess,
} from "./protocol";

const publicInputsSchema = z.object({
  chainId: z.string(),
  sealAddress: z.string(),
  proofVersion: z.string(),
  schemaVersion: z.string(),
  agreementRootHigh: z.string(),
  agreementRootLow: z.string(),
  manifestRootHigh: z.string(),
  manifestRootLow: z.string(),
  policyRootHigh: z.string(),
  policyRootLow: z.string(),
  fxRootHigh: z.string(),
  fxRootLow: z.string(),
  runNullifierHigh: z.string(),
  runNullifierLow: z.string(),
  validityStart: z.string(),
  validityExpiry: z.string(),
  shardIndex: z.string(),
}).strict();

export const remotePayrollProofResponseSchema = z.object({
  version: z.literal(1),
  type: z.literal("proof-complete"),
  requestId: z.string().min(1).max(160),
  scheme: z.literal("ultra_keccak_zk_honk"),
  circuitSha256: z.string().regex(/^0x[0-9a-f]{64}$/),
  provingTimeMs: z.number().int().nonnegative(),
  shards: z.tuple([
    z.object({
      shardIndex: z.literal(0),
      proofBase64: z.string().min(1).max(100_000),
      proofCalldata: z.array(starknetFeltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
      calldataHash: starknetFeltSchema,
      publicInputs: publicInputsSchema,
    }).strict(),
    z.object({
      shardIndex: z.literal(1),
      proofBase64: z.string().min(1).max(100_000),
      proofCalldata: z.array(starknetFeltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
      calldataHash: starknetFeltSchema,
      publicInputs: publicInputsSchema,
    }).strict(),
  ]),
}).strict();

const exceptionPublicInputsSchema = z.object({
  chainId: z.string(),
  sealAddress: z.string(),
  proofVersion: z.string(),
  schemaVersion: z.string(),
  agreementRootHigh: z.string(),
  agreementRootLow: z.string(),
  manifestRootHigh: z.string(),
  manifestRootLow: z.string(),
  policyRootHigh: z.string(),
  policyRootLow: z.string(),
  fxRootHigh: z.string(),
  fxRootLow: z.string(),
  subjectNullifierHigh: z.string(),
  subjectNullifierLow: z.string(),
  parentNullifierHigh: z.string(),
  parentNullifierLow: z.string(),
  factCommitmentHigh: z.string(),
  factCommitmentLow: z.string(),
  parentFactCommitmentHigh: z.string(),
  parentFactCommitmentLow: z.string(),
  validityStart: z.string(),
  validityExpiry: z.string(),
  shardIndex: z.string(),
}).strict();

export const remoteExceptionProofResponseSchema = z.object({
  version: z.literal(2),
  type: z.literal("exception-proof-complete"),
  requestId: z.string().min(1).max(160),
  profile: z.enum(["obligation_snapshot_v5", "wage_claim_v6", "wage_remediation_v7"]),
  scheme: z.literal("ultra_keccak_zk_honk"),
  circuitSha256: z.string().regex(/^0x[0-9a-f]{64}$/),
  provingTimeMs: z.number().int().nonnegative(),
  proof: z.object({
    proofBase64: z.string().min(1).max(100_000),
    proofCalldata: z.array(starknetFeltSchema).min(35).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    calldataHash: starknetFeltSchema,
    publicInputs: exceptionPublicInputsSchema,
  }).strict(),
}).strict();

export const remoteProofResponseSchema = z.union([
  remotePayrollProofResponseSchema,
  remoteExceptionProofResponseSchema,
]);

export type RemoteProofResponse = z.infer<typeof remoteProofResponseSchema>;

export const remoteProofJobResponseSchema = z.object({
  version: z.literal(2),
  type: z.literal("proof-job"),
  requestId: z.string().uuid(),
  state: z.enum(["queued", "processing"]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
}).strict();

export type RemoteProofJobResponse = z.infer<typeof remoteProofJobResponseSchema>;

export function decodeRemoteProofJobResponse(input: unknown): RemoteProofJobResponse {
  return remoteProofJobResponseSchema.parse(input);
}

export type RemoteProofRequest = {
  version: 1;
  requestId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
  claimAccessGrantId?: string;
};

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function decodeRemoteProofResponse(input: unknown): PayoProofWorkerSuccess {
  const response = remoteProofResponseSchema.parse(input);
  if (response.type === "exception-proof-complete") {
    return {
      version: 2,
      type: "exception-proof-complete",
      requestId: response.requestId,
      profile: response.profile,
      scheme: response.scheme,
      circuitSha256: response.circuitSha256,
      provingTimeMs: response.provingTimeMs,
      proof: {
        proof: decodeBase64(response.proof.proofBase64),
        proofCalldata: response.proof.proofCalldata,
        calldataHash: response.proof.calldataHash,
        publicInputs: response.proof.publicInputs,
      },
    } satisfies ExceptionProofWorkerSuccess;
  }
  return {
    version: 1,
    type: "proof-complete",
    requestId: response.requestId,
    scheme: response.scheme,
    circuitSha256: response.circuitSha256,
    provingTimeMs: response.provingTimeMs,
    shards: response.shards.map((shard) => ({
      shardIndex: shard.shardIndex,
      proof: decodeBase64(shard.proofBase64),
      proofCalldata: shard.proofCalldata,
      calldataHash: shard.calldataHash,
      publicInputs: shard.publicInputs,
    })) as ProofWorkerSuccess["shards"],
  };
}
