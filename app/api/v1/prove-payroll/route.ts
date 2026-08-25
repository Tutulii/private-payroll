import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { provePayrollOnSelfHostedNode } from "@/lib/proof/server-prover";

export const runtime = "nodejs";

const requestSchema = z.object({
  version: z.literal(1),
  requestId: z.string().uuid(),
  encryptedWitness: encryptedVaultRecordSchema,
  principal: z.object({
    principalId: z.string().min(1).max(160),
    publicKey: z.string().min(16).max(256),
    secretKey: z.string().min(16).max(256),
  }).strict(),
}).strict().superRefine((input, context) => {
  if (input.encryptedWitness.ciphertext.length > 2_000_000) {
    context.addIssue({ code: "custom", message: "The encrypted proof request is too large." });
  }
  if (input.encryptedWitness.aad.recordType !== "payroll-proof-request") {
    context.addIssue({ code: "custom", message: "The encrypted record is not a payroll proof request." });
  }
});

let proverBusy = false;

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

export async function OPTIONS(request: Request) {
  try {
    const origin = allowedOrigin(request);
    return new Response(null, {
      status: 204,
      headers: {
        ...corsHeaders(origin),
        "access-control-allow-methods": "POST, OPTIONS",
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
    const allowedPrincipal = process.env.PAYO_PROVER_ALLOWED_PRINCIPAL_ID;
    if (!allowedPrincipal || authenticated.principalId !== allowedPrincipal) {
      throw new ApiError(403, "This principal cannot use the self-hosted prover.", "PROVER_PRINCIPAL_FORBIDDEN");
    }
    const input = requestSchema.parse(await readJson(request));
    if (input.principal.principalId !== authenticated.principalId) {
      throw new ApiError(403, "The proof key does not belong to the authenticated principal.", "PROVER_KEY_FORBIDDEN");
    }
    if (!input.encryptedWitness.wrappedKeys.some(({ principalId }) => principalId === authenticated.principalId)) {
      throw new ApiError(403, "The proof request is not encrypted to the authenticated principal.", "PROVER_ENVELOPE_FORBIDDEN");
    }
    if (proverBusy) {
      throw new ApiError(429, "The self-hosted prover is processing another proof. Retry after it finishes.", "PROVER_BUSY");
    }
    proverBusy = true;
    try {
      const proof = await provePayrollOnSelfHostedNode(input);
      return Response.json({
        ...proof,
        shards: proof.shards.map(({ proof: proofBytes, ...shard }) => ({
          ...shard,
          proofBase64: Buffer.from(proofBytes).toString("base64"),
        })),
      }, { headers: corsHeaders(origin) });
    } finally {
      proverBusy = false;
    }
  } catch (error) {
    const response = apiFailure(error);
    for (const [key, value] of Object.entries(corsHeaders(origin))) {
      response.headers.set(key, String(value));
    }
    return response;
  }
}
