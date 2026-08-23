import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { encryptedRunCreateSchema } from "@/lib/domain/payroll";
import { createEncryptedRun, listPayrollRuns } from "@/lib/persistence/repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const organizationId = new URL(request.url).searchParams.get("organizationId");
    if (!organizationId) throw new ApiError(400, "organizationId is required.", "ORG_REQUIRED");
    const runs = await listPayrollRuns(organizationId, principal);
    return Response.json({ runs });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = encryptedRunCreateSchema.parse(await readJson(request));
    const envelope = encryptedVaultRecordSchema.parse(input.envelope);
    if (
      envelope.ciphertext !== input.ciphertext
      || envelope.aad.organizationId !== input.organizationId
      || envelope.aad.recordId !== input.id
      || envelope.aad.revision !== input.revision
      || envelope.aad.recordType !== "payroll-run"
    ) {
      throw new ApiError(400, "Encrypted envelope AAD does not match the payroll run.", "AAD_MISMATCH");
    }
    const run = await createEncryptedRun({ ...input, envelope }, principal);
    return Response.json({ run }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
