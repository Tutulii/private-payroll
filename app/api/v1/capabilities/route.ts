import { z } from "zod";
import { signedCapabilitySchema, verifySignedCapability } from "@/lib/domain/capability";
import {
  getAgentCapability,
  registerAgentCapability,
  revokeAgentCapability,
} from "@/lib/persistence/repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const revokeSchema = z.object({ capabilityId: z.string().min(8).max(128) }).strict();

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
    const parsed = signedCapabilitySchema.parse(await readJson(request));
    const signedCapability = verifySignedCapability(parsed);
    const capability = await registerAgentCapability(signedCapability, principal);
    return Response.json({ capability }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function DELETE(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const { capabilityId } = revokeSchema.parse(await readJson(request));
    return Response.json({ capability: await revokeAgentCapability(capabilityId, principal) });
  } catch (error) {
    return apiFailure(error);
  }
}
