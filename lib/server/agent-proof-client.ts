import "server-only";

import { z } from "zod";
import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { splitHashToU128 } from "@/lib/crypto/commitments";
import {
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  SETTLEMENT_MATCH_CIRCUIT_SHA256,
  SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
  type ProofWorkerSuccess,
  type SettlementMatchProofWorkerSuccess,
} from "@/lib/proof/protocol";
import {
  decodeRemoteProofResponse,
  remotePayrollProofResponseSchema,
} from "@/lib/proof/remote-prover";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";

const feltSchema = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/);
const digestSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const unsignedSchema = z.string().regex(/^(?:0|[1-9]\d*)$/);

const settlementPublicInputsSchema = z.object({
  proofVersion: unsignedSchema,
  manifestRootHigh: unsignedSchema,
  manifestRootLow: unsignedSchema,
  runNullifierHigh: unsignedSchema,
  runNullifierLow: unsignedSchema,
  transactionReferenceHigh: unsignedSchema,
  transactionReferenceLow: unsignedSchema,
  settlementRootHigh: unsignedSchema,
  settlementRootLow: unsignedSchema,
  chunkIndex: unsignedSchema,
  chunkCount: unsignedSchema,
}).strict();

const settlementResponseSchema = z.object({
  version: z.literal(8),
  type: z.literal("settlement-proof-complete"),
  requestId: z.string().uuid(),
  scheme: z.literal("ultra_keccak_zk_honk"),
  circuitSha256: digestSchema,
  verificationKeySha256: digestSchema,
  settlementRoot: digestSchema,
  transactionReference: digestSchema,
  provingTimeMs: z.number().int().nonnegative(),
  chunks: z.array(z.object({
    chunkIndex: z.number().int().nonnegative().max(16),
    chunkCount: z.number().int().min(1).max(17),
    proofCalldata: z.array(feltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    calldataHash: feltSchema,
    publicInputs: settlementPublicInputsSchema,
  }).strict()).min(1).max(17),
}).strict();

const pendingSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent-proof-job"),
  requestId: z.string().uuid(),
  state: z.enum(["queued", "processing"]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
}).strict();

function rootFromLimbs(high: string, low: string): string {
  return "0x" + ((BigInt(high) << 128n) | BigInt(low))
    .toString(16)
    .padStart(64, "0");
}

function assertSettlementResult(
  result: z.infer<typeof settlementResponseSchema>,
): SettlementMatchProofWorkerSuccess {
  if (
    result.circuitSha256 !== SETTLEMENT_MATCH_CIRCUIT_SHA256
    || result.verificationKeySha256 !== SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256
    || result.chunks.length !== result.chunks[0].chunkCount
  ) {
    throw new Error("AGENT_SETTLEMENT_PROOF_PROFILE_INVALID");
  }
  const root = splitHashToU128(result.settlementRoot);
  const reference = splitHashToU128(result.transactionReference);
  result.chunks.forEach((chunk, index) => {
    const inputs = chunk.publicInputs;
    if (
      chunk.chunkIndex !== index
      || chunk.chunkCount !== result.chunks.length
      || BigInt(inputs.proofVersion) !== 8n
      || BigInt(inputs.chunkIndex) !== BigInt(index)
      || BigInt(inputs.chunkCount) !== BigInt(result.chunks.length)
      || BigInt(inputs.settlementRootHigh) !== root.high
      || BigInt(inputs.settlementRootLow) !== root.low
      || BigInt(inputs.transactionReferenceHigh) !== reference.high
      || BigInt(inputs.transactionReferenceLow) !== reference.low
      || BigInt(chunk.calldataHash) !== BigInt(hashProofCalldata(chunk.proofCalldata))
      || rootFromLimbs(inputs.settlementRootHigh, inputs.settlementRootLow)
        !== result.settlementRoot.toLowerCase()
      || rootFromLimbs(
        inputs.transactionReferenceHigh,
        inputs.transactionReferenceLow,
      ) !== result.transactionReference.toLowerCase()
    ) {
      throw new Error("AGENT_SETTLEMENT_PROOF_BINDING_INVALID");
    }
  });
  return result as SettlementMatchProofWorkerSuccess;
}

async function body(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new Error("AGENT_PROVER_RESPONSE_INVALID");
  }
}

export class AgentProofClient {
  private readonly endpoint: URL;

  constructor(
    baseUrl: string,
    private readonly workerSecret: string,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    this.endpoint = new URL("/api/internal/agent-proofs", baseUrl);
    if (
      this.endpoint.protocol !== "https:"
      && this.endpoint.hostname !== "localhost"
      && this.endpoint.hostname !== "127.0.0.1"
    ) {
      throw new Error("PAYO_AGENT_PROVER_URL must use HTTPS.");
    }
    if (workerSecret.length < 32) {
      throw new Error("PAYO_WORKER_SECRET must authorize the agent prover.");
    }
  }

  private async post(payload: unknown): Promise<Response> {
    try {
      return await this.fetcher(this.endpoint, {
        method: "POST",
        headers: {
          authorization: "Bearer " + this.workerSecret,
          accept: "application/json",
          "content-type": "application/json",
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30_000),
      });
    } catch {
      throw new Error("AGENT_PROVER_UNREACHABLE");
    }
  }

  async payroll(input: {
    requestId: string;
    encryptedWitness: EncryptedVaultRecord;
    principal: VaultPrincipalKeyPair;
  }): Promise<ProofWorkerSuccess | null> {
    const response = await this.post({
      version: 1,
      type: "agent-payroll-proof",
      ...input,
    });
    const payload = await body(response);
    if (response.status === 202) {
      pendingSchema.parse(payload);
      return null;
    }
    if (!response.ok) {
      throw new Error(response.status === 422
        ? "AGENT_PAYROLL_PROOF_FAILED"
        : "AGENT_PROVER_REQUEST_FAILED");
    }
    const decoded = remotePayrollProofResponseSchema.parse(payload);
    const result = decodeRemoteProofResponse(decoded);
    if (result.type !== "proof-complete") throw new Error("AGENT_PAYROLL_PROOF_TYPE_INVALID");
    return result;
  }

  async settlement(input: {
    requestId: string;
    encryptedPayrollWitness: EncryptedVaultRecord;
    encryptedSettlementWitness: EncryptedVaultRecord;
    principal: VaultPrincipalKeyPair;
  }): Promise<SettlementMatchProofWorkerSuccess | null> {
    const response = await this.post({
      version: 8,
      type: "agent-settlement-proof",
      ...input,
    });
    const payload = await body(response);
    if (response.status === 202) {
      pendingSchema.parse(payload);
      return null;
    }
    if (!response.ok) {
      throw new Error(response.status === 422
        ? "AGENT_SETTLEMENT_PROOF_FAILED"
        : "AGENT_PROVER_REQUEST_FAILED");
    }
    return assertSettlementResult(settlementResponseSchema.parse(payload));
  }
}
