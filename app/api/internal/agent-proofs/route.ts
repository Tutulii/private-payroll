import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import {
  provePayrollOnSelfHostedNode,
  proveSettlementMatchOnSelfHostedNode,
} from "@/lib/proof/server-prover";
import {
  enqueueProverJob,
  getProverJob,
  agentProofJobNamespace,
  type ProverJobSnapshot,
} from "@/lib/proof/prover-job-store";
import { authorizeInternalWorker } from "@/lib/server/internal-auth";
import { readJson } from "@/lib/server/http";

export const runtime = "nodejs";
export const maxDuration = 3_600;

const principalSchema = z.object({
  principalId: z.string().min(1).max(160),
  publicKey: z.string().min(16).max(256),
  secretKey: z.string().min(16).max(256),
}).strict();

const payrollRequestSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent-payroll-proof"),
  requestId: z.string().uuid(),
  encryptedWitness: encryptedVaultRecordSchema,
  principal: principalSchema,
}).strict();

const settlementRequestSchema = z.object({
  version: z.literal(8),
  type: z.literal("agent-settlement-proof"),
  requestId: z.string().uuid(),
  encryptedPayrollWitness: encryptedVaultRecordSchema,
  encryptedSettlementWitness: encryptedVaultRecordSchema,
  principal: principalSchema,
}).strict();

const requestSchema = z.discriminatedUnion("type", [
  payrollRequestSchema,
  settlementRequestSchema,
]).superRefine((input, context) => {
  const records = input.type === "agent-payroll-proof"
    ? [input.encryptedWitness]
    : [input.encryptedPayrollWitness, input.encryptedSettlementWitness];
  records.forEach((record, index) => {
    if (!record.wrappedKeys.some(({ principalId }) =>
      principalId === input.principal.principalId)) {
      context.addIssue({
        code: "custom",
        path: ["encryptedWitness", index],
        message: "The agent proof envelope is not encrypted to its proof principal.",
      });
    }
  });
  if (
    input.type === "agent-settlement-proof"
    && (
      input.encryptedPayrollWitness.aad.organizationId
        !== input.encryptedSettlementWitness.aad.organizationId
      || input.encryptedSettlementWitness.aad.recordType
        !== "settlement-match-proof-request"
    )
  ) {
    context.addIssue({
      code: "custom",
      path: ["encryptedSettlementWitness"],
      message: "Settlement proof envelopes cross an organization or record boundary.",
    });
  }
});

function safeJobResponse(job: ProverJobSnapshot): Response {
  if (job.state === "complete" && job.result) {
    if (job.result.type === "proof-complete") {
      return Response.json({
        ...job.result,
        shards: job.result.shards.map(({ proof, ...shard }) => ({
          ...shard,
          proofBase64: Buffer.from(proof).toString("base64"),
        })),
      }, { headers: { "cache-control": "private, no-store" } });
    }
    if (job.result.type === "settlement-proof-complete") {
      return Response.json(job.result, {
        headers: { "cache-control": "private, no-store" },
      });
    }
    return Response.json({
      error: {
        code: "AGENT_PROOF_TYPE_INVALID",
        message: "The prover returned a forbidden proof profile.",
      },
    }, { status: 500 });
  }
  if (job.state === "failed") {
    return Response.json({
      error: job.error ?? {
        code: "AGENT_PROOF_FAILED",
        message: "The remote ZK prover could not generate this proof.",
      },
    }, { status: 422, headers: { "cache-control": "private, no-store" } });
  }
  return Response.json({
    version: 1,
    type: "agent-proof-job",
    requestId: job.requestId,
    state: job.state,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
  }, { status: 202, headers: { "cache-control": "private, no-store" } });
}

export async function POST(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json({
      error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." },
    }, { status: 401 });
  }
  if (process.env.PAYO_SELF_HOSTED_PROVER_ENABLED !== "true") {
    return Response.json({
      error: { code: "PROVER_DISABLED", message: "The self-hosted prover is disabled." },
    }, { status: 503 });
  }
  try {
    const input = requestSchema.parse(await readJson(request));
    // PayrollIntegrity and SettlementMatch intentionally share the execution
    // UUID, but they are independent durable jobs with different encrypted
    // inputs. Keep their replay/idempotency namespaces disjoint.
    const principalId = agentProofJobNamespace(input.type, input.principal.principalId);
    const job = input.type === "agent-payroll-proof"
      ? enqueueProverJob({
        principalId,
        request: {
          version: 1,
          requestId: input.requestId,
          encryptedWitness: input.encryptedWitness,
          principal: input.principal,
        },
        run: () => provePayrollOnSelfHostedNode(input),
      })
      : enqueueProverJob({
        principalId,
        request: {
          version: 8,
          requestId: input.requestId,
          encryptedPayrollWitness: input.encryptedPayrollWitness,
          encryptedSettlementWitness: input.encryptedSettlementWitness,
          principal: input.principal,
        },
        run: () => proveSettlementMatchOnSelfHostedNode(input),
      });
    return safeJobResponse(job);
  } catch (error) {
    const code = error instanceof Error ? error.message : "AGENT_PROVER_REQUEST_INVALID";
    const status = code === "PROVER_QUEUE_FULL" ? 429
      : code === "PROVER_REQUEST_ID_REUSED" ? 409
        : 400;
    return Response.json({
      error: {
        code: /^[A-Z0-9_]+$/.test(code) ? code : "AGENT_PROVER_REQUEST_INVALID",
        message: status === 429
          ? "The prover queue is full."
          : status === 409
            ? "This proof request ID was reused with different encrypted input."
            : "The encrypted agent proof request is invalid.",
      },
    }, { status, headers: { "cache-control": "private, no-store" } });
  }
}

export async function GET(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json({
      error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." },
    }, { status: 401 });
  }
  try {
    const url = new URL(request.url);
    const requestId = z.string().uuid().parse(url.searchParams.get("requestId"));
    const proofPrincipalId = z.string().min(1).max(160)
      .parse(url.searchParams.get("proofPrincipalId"));
    const proofType = z.enum(["agent-payroll-proof", "agent-settlement-proof"])
      .parse(url.searchParams.get("proofType"));
    const job = getProverJob(
      agentProofJobNamespace(proofType, proofPrincipalId),
      requestId,
    );
    if (!job) {
      return Response.json({
        error: {
          code: "AGENT_PROVER_JOB_NOT_FOUND",
          message: "The proof job is unavailable and must be re-enqueued.",
        },
      }, { status: 404 });
    }
    return safeJobResponse(job);
  } catch {
    return Response.json({
      error: {
        code: "AGENT_PROVER_QUERY_INVALID",
        message: "The agent proof query is invalid.",
      },
    }, { status: 400 });
  }
}
