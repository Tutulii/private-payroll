import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { commitmentSchema, uuidV7Schema, vaultPrincipalIdSchema } from "@/lib/domain/records";
import { createEncryptedReceipt, listEncryptedReceipts } from "@/lib/persistence/receipt-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const createReceiptSchema = z.object({
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  settlementId: uuidV7Schema,
  scope: z.enum(["employer", "worker", "auditor", "tax"]),
  granteePrincipalId: vaultPrincipalIdSchema,
  packageCommitment: commitmentSchema,
  expiresAt: z.string().datetime().optional(),
  envelope: encryptedVaultRecordSchema,
}).strict();

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const organizationId = uuidV7Schema.parse(new URL(request.url).searchParams.get("organizationId"));
    return Response.json({ receipts: await listEncryptedReceipts(organizationId, principal) });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = createReceiptSchema.parse(await readJson(request));
    const { expiresAt, ...receiptInput } = input;
    const receipt = await createEncryptedReceipt({
      ...receiptInput,
      ...(expiresAt ? { expiresAt: new Date(expiresAt) } : {}),
      principal,
    });
    return Response.json({ receipt }, { status: receipt.replayed ? 200 : 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
