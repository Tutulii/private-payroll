import { z } from "zod";
import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { starknetFeltSchema } from "@/lib/domain/proof-bundle";
import { PAYO_MAX_PROOF_CALLDATA_FELTS, type ProofWorkerSuccess } from "./protocol";

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

export const remoteProofResponseSchema = z.object({
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

export type RemoteProofResponse = z.infer<typeof remoteProofResponseSchema>;

export type RemoteProofRequest = {
  version: 1;
  requestId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
};

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function decodeRemoteProofResponse(input: unknown): ProofWorkerSuccess {
  const response = remoteProofResponseSchema.parse(input);
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
