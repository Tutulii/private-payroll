import { z } from "zod";
import {
  issueAgentAccessToken,
  listAgentAccessTokens,
  revokeAgentAccessTokens,
} from "@/lib/server/agent-access-token";
import { requireReadyPrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const issueSchema = z.object({
  ttlSeconds: z.number().int().min(300).max(86_400).optional(),
}).strict();

type AccessTokenContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: AccessTokenContext) {
  try {
    const principal = await requireReadyPrincipal(request);
    const { id: capabilityId } = await context.params;
    return Response.json({
      tokens: await listAgentAccessTokens({ capabilityId, principal }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request, context: AccessTokenContext) {
  try {
    const principal = await requireReadyPrincipal(request);
    const { id: capabilityId } = await context.params;
    const input = issueSchema.parse(await readJson(request));
    return Response.json({
      connection: await issueAgentAccessToken({
        capabilityId,
        principal,
        ttlSeconds: input.ttlSeconds,
      }),
    }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function DELETE(request: Request, context: AccessTokenContext) {
  try {
    const principal = await requireReadyPrincipal(request);
    const { id: capabilityId } = await context.params;
    return Response.json({
      revocation: await revokeAgentAccessTokens({ capabilityId, principal }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
