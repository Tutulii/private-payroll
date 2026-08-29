import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { provePayoOnSelfHostedNode } from "@/lib/proof/server-prover";
import type { PayoProofWorkerSuccess } from "@/lib/proof/protocol";
import { enqueueProverJob, getProverJob, waitForProverJob, type ProverJobSnapshot } from "@/lib/proof/prover-job-store";
import { getObligationClaimAccessGrant } from "@/lib/persistence/obligation-snapshot-plan-repository";
import { requireOrganizationRole } from "@/lib/persistence/repository";

export const runtime = "nodejs";

const requestSchema = z.object({
  version: z.union([z.literal(1), z.literal(2)]),
  requestId: z.string().uuid(),
  encryptedWitness: encryptedVaultRecordSchema,
  principal: z.object({
    principalId: z.string().min(1).max(160),
    publicKey: z.string().min(16).max(256),
    secretKey: z.string().min(16).max(256),
  }).strict(),
  claimAccessGrantId: z.string().uuid().optional(),
}).strict().superRefine((input, context) => {
  if (input.encryptedWitness.ciphertext.length > 2_000_000) {
    context.addIssue({ code: "custom", message: "The encrypted proof request is too large." });
  }
  if (input.encryptedWitness.aad.recordType !== "payroll-proof-request") {
    context.addIssue({ code: "custom", message: "The encrypted record is not a payroll proof request." });
  }
});

function allowedOrigin(request: Request): string | null {
  const origin = request.headers.get("origin");
  if (!origin) return null;
  const configured = (process.env.PAYO_PROVER_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (!configured.includes(origin)) {
    throw new ApiError(403, "This browser origin cannot use the self-hosted prover.", "PROVER_ORIGIN_FORBIDDEN");
  }
  return origin;
}

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    "cache-control": "private, no-store, max-age=0",
    ...(origin ? {
      "access-control-allow-origin": origin,
      "access-control-allow-credentials": "true",
      vary: "Origin",
    } : {}),
  };
}

function proofResponse(proof: PayoProofWorkerSuccess, origin: string | null) {
  if (proof.type === "exception-proof-complete") {
    const { proof: proofBytes, ...exceptionProof } = proof.proof;
    return Response.json({
      ...proof,
      proof: {
        ...exceptionProof,
        proofBase64: Buffer.from(proofBytes).toString("base64"),
      },
    }, { headers: corsHeaders(origin) });
  }
  return Response.json({
    ...proof,
    shards: proof.shards.map(({ proof: proofBytes, ...shard }) => ({
      ...shard,
      proofBase64: Buffer.from(proofBytes).toString("base64"),
    })),
  }, { headers: corsHeaders(origin) });
}

function jobResponse(job: ProverJobSnapshot, origin: string | null) {
  if (job.state === "complete" && job.result) {
    return proofResponse(job.result, origin);
  }
  if (job.state === "failed") {
    return Response.json({ error: job.error }, { status: 422, headers: corsHeaders(origin) });
  }
  return Response.json({
    version: 2,
    type: "proof-job",
    requestId: job.requestId,
    state: job.state,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
  }, { status: 202, headers: corsHeaders(origin) });
}
export async function OPTIONS(request: Request) {
  try {
    const origin = allowedOrigin(request);
    return new Response(null, {
      status: 204,
      headers: {
        ...corsHeaders(origin),
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "authorization, content-type",
        "access-control-max-age": "600",
      },
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  let origin: string | null = null;
  try {
    origin = allowedOrigin(request);
    if (process.env.PAYO_SELF_HOSTED_PROVER_ENABLED !== "true") {
      throw new ApiError(404, "The self-hosted prover is disabled.", "PROVER_DISABLED");
    }
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > 2_500_000) {
      throw new ApiError(413, "The encrypted proof request is too large.", "PROVER_REQUEST_TOO_LARGE");
    }
    const authenticated = await requirePrincipal(request);
    const input = requestSchema.parse(await readJson(request));
    let expectedExceptionProfile: "wage_claim_v6" | undefined;
    if (input.claimAccessGrantId) {
      const grant = await getObligationClaimAccessGrant(input.claimAccessGrantId, authenticated);
      if (grant.organizationId !== input.encryptedWitness.aad.organizationId) {
        throw new ApiError(403, "The worker proof request does not match its claim access.", "CLAIM_ACCESS_MISMATCH");
      }
      expectedExceptionProfile = "wage_claim_v6";
    } else {
      await requireOrganizationRole(
        input.encryptedWitness.aad.organizationId,
        authenticated,
        ["admin", "operator"],
      );
    }
    if (input.principal.principalId !== authenticated.principalId) {
      throw new ApiError(403, "The proof key does not belong to the authenticated principal.", "PROVER_KEY_FORBIDDEN");
    }
    if (!input.encryptedWitness.wrappedKeys.some(({ principalId }) => principalId === authenticated.principalId)) {
      throw new ApiError(403, "The proof request is not encrypted to the authenticated principal.", "PROVER_ENVELOPE_FORBIDDEN");
    }
    // Both protocol versions use one queue so concurrent WASM provers cannot exhaust RAM.
    // Version 1 keeps its long-lived response only for a safe rolling deployment.
    let job: ProverJobSnapshot;
    try {
      job = enqueueProverJob({
        principalId: authenticated.principalId,
        request: { ...input, version: 1 },
        run: () => provePayoOnSelfHostedNode(input, { expectedExceptionProfile }),
      });
    } catch (error) {
      if (error instanceof Error && error.message === "PROVER_REQUEST_ID_REUSED") {
        throw new ApiError(409, "This proof request ID was already used for different encrypted input.", "PROVER_REQUEST_ID_REUSED");
      }
      if (error instanceof Error && error.message === "PROVER_QUEUE_FULL") {
        throw new ApiError(429, "The prover queue is full. Retry after an active proof finishes.", "PROVER_QUEUE_FULL");
      }
      throw error;
    }
    if (input.version === 1) {
      return jobResponse(await waitForProverJob(authenticated.principalId, input.requestId), origin);
    }
    return jobResponse(job, origin);
  } catch (error) {
    const response = apiFailure(error);
    for (const [key, value] of Object.entries(corsHeaders(origin))) {
      response.headers.set(key, String(value));
    }
    return response;
  }
}

export async function GET(request: Request) {
  let origin: string | null = null;
  try {
    origin = allowedOrigin(request);
    if (process.env.PAYO_SELF_HOSTED_PROVER_ENABLED !== "true") {
      throw new ApiError(404, "The self-hosted prover is disabled.", "PROVER_DISABLED");
    }
    const authenticated = await requirePrincipal(request);
    const requestId = z.string().uuid().parse(new URL(request.url).searchParams.get("requestId"));
    const job = getProverJob(authenticated.principalId, requestId);
    if (!job) {
      throw new ApiError(404, "This proof job is not available. Resubmit the encrypted request to resume safely.", "PROVER_JOB_NOT_FOUND");
    }
    return jobResponse(job, origin);
  } catch (error) {
    const response = apiFailure(error);
    for (const [key, value] of Object.entries(corsHeaders(origin))) {
      response.headers.set(key, String(value));
    }
    return response;
  }
}
