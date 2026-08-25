import { z } from "zod";
import { fromBase64 } from "@/lib/crypto/encoding";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { uuidV7Schema } from "@/lib/domain/records";
import { createOrganization, listOrganizations } from "@/lib/persistence/repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const createOrganizationSchema = z.object({
  organizationId: uuidV7Schema,
  encryptedProfile: encryptedVaultRecordSchema,
  vaultPublicKey: z.string().min(16).refine((value) => {
    try {
      return fromBase64(value).length === 32;
    } catch {
      return false;
    }
  }, "A 32-byte base64 X25519 public key is required."),
  initialPrincipal: z.object({
    recordId: uuidV7Schema,
    envelope: encryptedVaultRecordSchema,
  }).strict(),
}).strict();

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    return Response.json({ organizations: await listOrganizations(principal) });
  } catch (error) {
    return apiFailure(error);
  }
}

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
    if (
      input.initialPrincipal.envelope.aad.organizationId !== input.organizationId
      || input.initialPrincipal.envelope.aad.recordId !== input.initialPrincipal.recordId
      || input.initialPrincipal.envelope.aad.recordType !== "principal"
      || input.initialPrincipal.envelope.aad.revision !== 1
      || !input.initialPrincipal.envelope.wrappedKeys.some(({ principalId }) => principalId === principal.principalId)
    ) {
      return Response.json(
        { error: { code: "PRINCIPAL_AAD_MISMATCH", message: "The initial encrypted principal does not match its authenticated administrator." } },
        { status: 400 },
      );
    }
    if (
      !input.encryptedProfile.wrappedKeys.some(({ principalId }) => principalId === principal.principalId)
    ) {
      return Response.json(
        { error: { code: "VAULT_ADMIN_KEY_INVALID", message: "The authenticated administrator must have a valid wrapped vault key." } },
        { status: 400 },
      );
    }
    const organization = await createOrganization({ ...input, principal });
    return Response.json({ organization }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
