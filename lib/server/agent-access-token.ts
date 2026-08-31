import "server-only";

import { randomBytes } from "node:crypto";
import { and, desc, eq, isNull } from "drizzle-orm";
import { generateUuidV7 } from "@/lib/domain/records";
import { getDatabase } from "@/lib/persistence/db";
import {
  agentAccessTokens,
  agentCapabilities,
  auditEvents,
} from "@/lib/persistence/schema";
import {
  ApiError,
  hashReadySessionToken,
  type AuthenticatedPrincipal,
} from "@/lib/server/auth";
import { decryptCapabilityPolicy } from "@/lib/server/capability-policy-crypto";
import { requireOrganizationRoleWith } from "@/lib/persistence/repository";

const MIN_AGENT_TOKEN_TTL_SECONDS = 5 * 60;
const MAX_AGENT_TOKEN_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_AGENT_TOKEN_TTL_SECONDS = 4 * 60 * 60;

function checkedTtlSeconds(value: number | undefined): number {
  const ttl = value ?? DEFAULT_AGENT_TOKEN_TTL_SECONDS;
  if (
    !Number.isInteger(ttl)
    || ttl < MIN_AGENT_TOKEN_TTL_SECONDS
    || ttl > MAX_AGENT_TOKEN_TTL_SECONDS
  ) {
    throw new ApiError(
      400,
      "MCP credential lifetime must be between 5 minutes and 24 hours.",
      "AGENT_TOKEN_TTL_INVALID",
    );
  }
  return ttl;
}

function publicToken(row: {
  id: string;
  capabilityId: string;
  expiresAt: Date;
  revokedAt: Date | null;
  lastSeenAt: Date | null;
  createdAt: Date;
}) {
  return {
    tokenId: row.id,
    capabilityId: row.capabilityId,
    expiresAt: row.expiresAt.toISOString(),
    revokedAt: row.revokedAt?.toISOString() ?? null,
    lastSeenAt: row.lastSeenAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
  };
}

export async function issueAgentAccessToken(input: {
  capabilityId: string;
  principal: AuthenticatedPrincipal;
  ttlSeconds?: number;
  now?: Date;
}) {
  const ttlSeconds = checkedTtlSeconds(input.ttlSeconds);
  const now = input.now ?? new Date();
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [stored] = await transaction
      .select()
      .from(agentCapabilities)
      .where(eq(agentCapabilities.id, input.capabilityId))
      .limit(1)
      .for("update");
    if (!stored) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, stored.organizationId, input.principal, ["admin"]);
    if (stored.revokedAt) throw new ApiError(410, "Agent capability was revoked.", "CAPABILITY_REVOKED");
    if (stored.expiresAt <= now) throw new ApiError(410, "Agent capability expired.", "CAPABILITY_EXPIRED");

    const signed = decryptCapabilityPolicy(stored.policy, {
      capabilityId: stored.id,
      organizationId: stored.organizationId,
      principalId: stored.principalId,
      capabilityHash: stored.capabilityHash,
    });
    if (new Date(signed.capability.validAfter) > now) {
      throw new ApiError(409, "Agent capability is not active yet.", "CAPABILITY_NOT_YET_VALID");
    }

    await transaction
      .update(agentAccessTokens)
      .set({ revokedAt: now })
      .where(and(
        eq(agentAccessTokens.capabilityId, stored.id),
        isNull(agentAccessTokens.revokedAt),
      ));

    const expiresAt = new Date(Math.min(
      stored.expiresAt.getTime(),
      now.getTime() + ttlSeconds * 1_000,
    ));
    const accessToken = "payo_agent_" + randomBytes(32).toString("base64url");
    const [created] = await transaction
      .insert(agentAccessTokens)
      .values({
        id: generateUuidV7(now.getTime()),
        capabilityId: stored.id,
        organizationId: stored.organizationId,
        principalId: stored.principalId,
        tokenHash: hashReadySessionToken(accessToken),
        expiresAt,
        createdBy: input.principal.principalId,
        createdAt: now,
      })
      .returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(now.getTime() + 1),
      organizationId: stored.organizationId,
      actorId: input.principal.principalId,
      action: "agent_access_token.rotated",
      subjectId: created.id,
      metadata: {
        capabilityId: stored.id,
        principalId: stored.principalId,
        expiresAt: expiresAt.toISOString(),
      },
    });
    return {
      ...publicToken(created),
      accessToken,
      organizationId: stored.organizationId,
      principalId: stored.principalId,
      issuerPublicKey: signed.issuerPublicKey,
    };
  });
}

export async function listAgentAccessTokens(input: {
  capabilityId: string;
  principal: AuthenticatedPrincipal;
}) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [capability] = await transaction
      .select({ organizationId: agentCapabilities.organizationId })
      .from(agentCapabilities)
      .where(eq(agentCapabilities.id, input.capabilityId))
      .limit(1);
    if (!capability) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, capability.organizationId, input.principal, ["admin"]);
    const tokens = await transaction
      .select()
      .from(agentAccessTokens)
      .where(eq(agentAccessTokens.capabilityId, input.capabilityId))
      .orderBy(desc(agentAccessTokens.createdAt))
      .limit(20);
    return tokens.map(publicToken);
  });
}

export async function revokeAgentAccessTokens(input: {
  capabilityId: string;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [capability] = await transaction
      .select({ organizationId: agentCapabilities.organizationId })
      .from(agentCapabilities)
      .where(eq(agentCapabilities.id, input.capabilityId))
      .limit(1)
      .for("update");
    if (!capability) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, capability.organizationId, input.principal, ["admin"]);
    const revoked = await transaction
      .update(agentAccessTokens)
      .set({ revokedAt: now })
      .where(and(
        eq(agentAccessTokens.capabilityId, input.capabilityId),
        isNull(agentAccessTokens.revokedAt),
      ))
      .returning({ id: agentAccessTokens.id });
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(now.getTime()),
      organizationId: capability.organizationId,
      actorId: input.principal.principalId,
      action: "agent_access_token.revoked",
      subjectId: input.capabilityId,
      metadata: { revokedCount: revoked.length },
    });
    return { capabilityId: input.capabilityId, revokedCount: revoked.length };
  });
}
