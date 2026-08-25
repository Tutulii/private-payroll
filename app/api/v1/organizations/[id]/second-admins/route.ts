import { z } from "zod";
import { fromBase64 } from "@/lib/crypto/encoding";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { uuidV7Schema } from "@/lib/domain/records";
import { addSecondAdministrator } from "@/lib/persistence/vault-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const grantSchema = z.object({
  grantId: uuidV7Schema,
  granteePrincipalId: z.string().min(1).max(160),
  vaultPublicKey: z.string().min(16).refine((value) => {
    try { return fromBase64(value).length === 32; } catch { return false; }
  }, "A 32-byte base64 X25519 public key is required."),
  keyVersion: z.number().int().positive(),
  envelope: encryptedVaultRecordSchema,
  encryptedProfile: encryptedVaultRecordSchema,
}).strict();

type Context = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: Context) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const input = grantSchema.parse(await readJson(request));
    const grant = await addSecondAdministrator({
      ...input,
      organizationId: uuidV7Schema.parse(id),
      principal,
    });
    return Response.json({ grant }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
