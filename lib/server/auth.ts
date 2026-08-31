import "server-only";

import { createHash } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { authorizeAgentAction, type AgentAction } from "@/lib/domain/capability";
import { getDatabase } from "@/lib/persistence/db";
import { agentAccessTokens, agentCapabilities, readyAuthSessions } from "@/lib/persistence/schema";
import { decryptCapabilityPolicy } from "@/lib/server/capability-policy-crypto";

export type AuthenticatedPrincipal = {
  principalId: string;
  sessionId: string;
  walletAddress?: string;
  chainId?: string;
  authKind?: "ready" | "agent_capability";
  capabilityId?: string;
  capabilityOrganizationId?: string;
  capabilityPrincipalId?: string;
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code: string,
  ) {
    super(message);
  }
}

export function hashReadySessionToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function tokenFromRequest(request: Request): string | undefined {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return undefined;
  const token = authorization.slice(7).trim();
  return token.length >= 32 && token.length <= 512 ? token : undefined;
}

export async function requireReadyPrincipal(request: Request): Promise<AuthenticatedPrincipal> {
  const accessToken = tokenFromRequest(request);
  if (!accessToken) {
    throw new ApiError(401, "Authorize a PAYO session with Ready first.", "AUTH_REQUIRED");
  }

  const now = new Date();
  const [session] = await getDatabase()
    .select({
      principalId: readyAuthSessions.principalId,
      sessionId: readyAuthSessions.id,
      walletAddress: readyAuthSessions.walletAddress,
      chainId: readyAuthSessions.chainId,
    })
    .from(readyAuthSessions)
    .where(and(
      eq(readyAuthSessions.tokenHash, hashReadySessionToken(accessToken)),
      isNull(readyAuthSessions.revokedAt),
      gt(readyAuthSessions.expiresAt, now),
    ))
    .limit(1);

  if (!session) {
    throw new ApiError(
      401,
      "The Ready-authorized PAYO session is invalid or expired. Authorize it again without resubmitting any private transaction.",
      "AUTH_INVALID",
    );
  }
  return session;
}
type AgentRouteScope = {
  actions: AgentAction[];
  capabilityId?: string;
};

function scopedAgentRoute(request: Request): AgentRouteScope | null {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  if (method === "GET" && url.pathname === "/api/v1/capabilities") {
    const capabilityId = url.searchParams.get("capabilityId");
    return capabilityId ? { actions: [], capabilityId } : null;
  }
  if (url.pathname === "/api/v1/runs") {
    if (method === "GET") return { actions: ["list_due_obligations"] };
    if (method === "POST") return { actions: ["draft_run"] };
    return null;
  }
  if (method === "GET" && /^\/api\/v1\/runs\/[^/]+$/.test(url.pathname)) {
    return { actions: ["get_run_status", "get_receipt"] };
  }
  const executionMatch = /^\/api\/v1\/capabilities\/([^/]+)\/executions$/.exec(url.pathname);
  if (executionMatch) {
    let capabilityId: string;
    try {
      capabilityId = decodeURIComponent(executionMatch[1]);
    } catch {
      return null;
    }
    if (method === "POST") return { actions: ["request_execution"], capabilityId };
    if (method === "GET") return { actions: ["get_receipt"], capabilityId };
    return null;
  }
  if (method === "POST" && url.pathname === "/api/v1/disclosures") {
    return { actions: ["create_disclosure"] };
  }
  return null;
}

async function authenticateAgentCapability(
  request: Request,
  accessToken: string,
  now: Date,
): Promise<AuthenticatedPrincipal | null> {
  const database = getDatabase();
  const [stored] = await database
    .select({
      tokenId: agentAccessTokens.id,
      capabilityId: agentCapabilities.id,
      organizationId: agentCapabilities.organizationId,
      principalId: agentCapabilities.principalId,
      capabilityHash: agentCapabilities.capabilityHash,
      policy: agentCapabilities.policy,
    })
    .from(agentAccessTokens)
    .innerJoin(agentCapabilities, eq(agentCapabilities.id, agentAccessTokens.capabilityId))
    .where(and(
      eq(agentAccessTokens.tokenHash, hashReadySessionToken(accessToken)),
      isNull(agentAccessTokens.revokedAt),
      gt(agentAccessTokens.expiresAt, now),
      isNull(agentCapabilities.revokedAt),
      gt(agentCapabilities.expiresAt, now),
    ))
    .limit(1);
  if (!stored) return null;

  const scope = scopedAgentRoute(request);
  if (!scope) {
    throw new ApiError(
      403,
      "This MCP credential cannot access the requested PAYO service.",
      "AGENT_TOKEN_SCOPE_DENIED",
    );
  }
  if (scope.capabilityId && scope.capabilityId !== stored.capabilityId) {
    throw new ApiError(403, "The MCP credential is bound to another capability.", "AGENT_TOKEN_CAPABILITY_MISMATCH");
  }
  const requestedOrganization = new URL(request.url).searchParams.get("organizationId");
  if (requestedOrganization && requestedOrganization !== stored.organizationId) {
    throw new ApiError(403, "The MCP credential is bound to another organization.", "AGENT_TOKEN_ORG_MISMATCH");
  }

  const signed = decryptCapabilityPolicy(stored.policy, {
    capabilityId: stored.capabilityId,
    organizationId: stored.organizationId,
    principalId: stored.principalId,
    capabilityHash: stored.capabilityHash,
  });
  const capability = signed.capability;
  if (
    capability.id !== stored.capabilityId
    || capability.organizationId !== stored.organizationId
    || capability.principalId !== stored.principalId
    || new Date(capability.validAfter).getTime() > now.getTime()
  ) {
    throw new ApiError(401, "The MCP capability binding is invalid or inactive.", "AGENT_TOKEN_INVALID");
  }
  if (
    scope.actions.length > 0
    && !scope.actions.some((action) => authorizeAgentAction(capability, action, now).allowed)
  ) {
    throw new ApiError(403, "The signed capability denies this MCP action.", "AGENT_TOKEN_ACTION_DENIED");
  }

  await database
    .update(agentAccessTokens)
    .set({ lastSeenAt: now })
    .where(and(
      eq(agentAccessTokens.id, stored.tokenId),
      isNull(agentAccessTokens.revokedAt),
    ));
  return {
    principalId: stored.principalId,
    sessionId: "agent-token:" + stored.tokenId,
    authKind: "agent_capability",
    capabilityId: stored.capabilityId,
    capabilityOrganizationId: stored.organizationId,
    capabilityPrincipalId: stored.principalId,
  };
}

export async function requirePrincipal(request: Request): Promise<AuthenticatedPrincipal> {
  const accessToken = tokenFromRequest(request);
  if (!accessToken) {
    throw new ApiError(401, "Authorize a PAYO session with Ready first.", "AUTH_REQUIRED");
  }
  if (accessToken.startsWith("payo_agent_")) {
    const agentPrincipal = await authenticateAgentCapability(request, accessToken, new Date());
    if (!agentPrincipal) {
      throw new ApiError(401, "The MCP credential is invalid, revoked, or expired.", "AGENT_TOKEN_INVALID");
    }
    return agentPrincipal;
  }
  return requireReadyPrincipal(request);
}
