import "server-only";

import { createHash } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { getDatabase } from "@/lib/persistence/db";
import { readyAuthSessions } from "@/lib/persistence/schema";

export type AuthenticatedPrincipal = {
  principalId: string;
  sessionId: string;
  walletAddress?: string;
  chainId?: string;
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

export async function requirePrincipal(request: Request): Promise<AuthenticatedPrincipal> {
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
