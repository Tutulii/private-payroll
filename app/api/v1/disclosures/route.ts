import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { uuidV7Schema } from "@/lib/domain/records";
import { createDisclosureGrant, revokeDisclosureGrant } from "@/lib/persistence/receipt-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const fieldScopeSchema = z.array(z.enum([
  "identity", "gross", "deductions", "net", "token", "schedule",
  "classification", "aggregate", "settlement",
])).min(1);

const createDisclosureSchema = z.object({
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  granteePrincipalId: uuidV7Schema,
  fieldScope: fieldScopeSchema,
  validAfter: z.string().datetime(),
  expiresAt: z.string().datetime(),
  envelope: encryptedVaultRecordSchema,
}).strict();

const revokeDisclosureSchema = z.object({
  organizationId: uuidV7Schema,
  grantId: uuidV7Schema,
}).strict();

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = createDisclosureSchema.parse(await readJson(request));
    const grant = await createDisclosureGrant({
      ...input,
      validAfter: new Date(input.validAfter),
      expiresAt: new Date(input.expiresAt),
      principal,
    });
    return Response.json({ grant }, { status: grant.replayed ? 200 : 201 });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function DELETE(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = revokeDisclosureSchema.parse(await readJson(request));
    return Response.json({ grant: await revokeDisclosureGrant({ ...input, principal }) });
  } catch (error) {
    return apiFailure(error);
  }
}
