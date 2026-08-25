import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { signedCapabilitySchema, verifySignedCapability } from "@/lib/domain/capability";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  getAgentCapability,
  registerAgentCapability,
  revokeAgentCapability,
} from "@/lib/persistence/repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const encryptedCapabilityCreateSchema = z.object({
  signedCapability: signedCapabilitySchema,
  recordId: uuidV7Schema,
  revision: z.literal(1),
  envelope: encryptedVaultRecordSchema,
}).strict();
const revokeSchema = z.object({
  capabilityId: uuidV7Schema,
  organizationId: uuidV7Schema,
  revision: z.number().int().min(2),
  envelope: encryptedVaultRecordSchema,
}).strict();

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const capabilityId = new URL(request.url).searchParams.get("capabilityId");
    if (!capabilityId) throw new ApiError(400, "capabilityId is required.", "CAPABILITY_ID_REQUIRED");
    return Response.json({ capability: await getAgentCapability(capabilityId, principal) });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const parsed = encryptedCapabilityCreateSchema.parse(await readJson(request));
    const signedCapability = verifySignedCapability(parsed.signedCapability);
    const capability = await registerAgentCapability({ ...parsed, signedCapability }, principal);
    return Response.json({ capability }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function DELETE(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = revokeSchema.parse(await readJson(request));
    return Response.json({ capability: await revokeAgentCapability(input, principal) });
  } catch (error) {
    return apiFailure(error);
  }
}
