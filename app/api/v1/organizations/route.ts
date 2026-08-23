import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { createOrganization } from "@/lib/persistence/repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const createOrganizationSchema = z.object({
  organizationId: z.string().min(8).max(128),
  encryptedProfile: encryptedVaultRecordSchema,
  vaultPublicKey: z.string().min(16),
}).strict();

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = createOrganizationSchema.parse(await readJson(request));
    if (
      input.encryptedProfile.aad.organizationId !== input.organizationId
      || input.encryptedProfile.aad.recordId !== input.organizationId
      || input.encryptedProfile.aad.recordType !== "organization-profile"
    ) {
      return Response.json(
        { error: { code: "AAD_MISMATCH", message: "Encrypted profile AAD does not match its organization." } },
        { status: 400 },
      );
    }
    const organization = await createOrganization({ ...input, principal });
    return Response.json({ organization }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
