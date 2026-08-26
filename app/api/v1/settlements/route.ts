import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { commitmentSchema, uuidV7Schema } from "@/lib/domain/records";
import { settlementWorkflowSchema } from "@/lib/domain/settlement";
import { createSettlementIntent, listSettlements } from "@/lib/persistence/settlement-repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const settlementIntentSchema = z.object({
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  workflowType: settlementWorkflowSchema,
  subjectRecordId: uuidV7Schema,
  walletRequestId: uuidV7Schema,
  tokenTotalsCommitment: commitmentSchema,
  envelope: encryptedVaultRecordSchema,
}).strict();

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const search = new URL(request.url).searchParams;
    const organizationId = uuidV7Schema.parse(search.get("organizationId"));
    const limit = search.get("limit") === null ? 50 : Number(search.get("limit"));
    return Response.json({ settlements: await listSettlements(organizationId, principal, limit) });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const idempotencyKey = request.headers.get("idempotency-key");
    if (!idempotencyKey) {
      throw new ApiError(400, "Idempotency-Key is required.", "IDEMPOTENCY_KEY_REQUIRED");
    }
    const input = settlementIntentSchema.parse(await readJson(request));
    if (
      input.envelope.aad.organizationId !== input.organizationId
      || input.envelope.aad.recordId !== input.id
      || input.envelope.aad.recordType !== "settlement"
      || input.envelope.aad.revision !== 1
    ) {
      throw new ApiError(400, "Encrypted settlement AAD does not match its storage identity.", "AAD_MISMATCH");
    }
    const settlement = await createSettlementIntent({ ...input, idempotencyKey, principal });
    return Response.json({ settlement }, { status: settlement.replayed ? 200 : 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
