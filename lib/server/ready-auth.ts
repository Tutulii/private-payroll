import "server-only";

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { and, eq, gt, isNull, lt, sql } from "drizzle-orm";
import { RpcProvider } from "starknet";
import {
  buildReadyAuthTypedData,
  READY_AUTH_CHAIN_ID,
  READY_AUTH_CHALLENGE_TTL_SECONDS,
  readyWalletPrincipalId,
  type ReadySessionPayload,
} from "@/lib/auth/ready-session";
import { encryptVaultRecord, type EncryptedVaultRecord } from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import { getDatabase } from "@/lib/persistence/db";
import {
  organizationMembers,
  readyAuthChallenges,
  readyAuthSessions,
  readyPrincipalLinks,
  readyRecoveryLinkChallenges,
} from "@/lib/persistence/schema";
import { ApiError, hashReadySessionToken, type AuthenticatedPrincipal } from "./auth";

const MAX_ACTIVE_CHALLENGES = 5;
const MAX_VERIFICATION_ATTEMPTS = 5;
const RECOVERY_LINK_TTL_SECONDS = 10 * 60;

function authAudience(request: Request): string {
  const configured = process.env.PAYO_AUTH_AUDIENCE?.trim();
  if (configured) return configured.replace(/\/$/, "");
  const origin = new URL(request.url).origin;
  if (process.env.NODE_ENV === "production") {
    throw new ApiError(503, "Ready authentication audience is not configured.", "AUTH_NOT_CONFIGURED");
  }
  return origin;
}

function authProvider(): RpcProvider {
  const nodeUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  if (!nodeUrl) {
    throw new ApiError(503, "The server-side Starknet RPC is not configured.", "AUTH_NOT_CONFIGURED");
  }
  return new RpcProvider({ nodeUrl });
}

function sessionLifetimeMilliseconds(): number {
  const configuredHours = Number(process.env.PAYO_READY_SESSION_HOURS ?? "12");
  const hours = Number.isFinite(configuredHours)
    ? Math.min(168, Math.max(1, configuredHours))
    : 12;
  return hours * 60 * 60 * 1_000;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function secureEqualHex(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function issueSessionValues(input: {
  walletAddress: string;
  chainId: typeof READY_AUTH_CHAIN_ID;
  principalId: string;
  now: Date;
}) {
  const accessToken = randomBytes(32).toString("base64url");
  const expiresAt = new Date(input.now.getTime() + sessionLifetimeMilliseconds());
  return {
    row: {
      id: generateUuidV7(input.now.getTime()),
      tokenHash: hashReadySessionToken(accessToken),
      walletAddress: input.walletAddress,
      chainId: input.chainId,
      principalId: input.principalId,
      expiresAt,
      createdAt: input.now,
      lastSeenAt: input.now,
    },
    payload: {
      accessToken,
      principalId: input.principalId,
      walletAddress: input.walletAddress,
      chainId: input.chainId,
      expiresAt: expiresAt.toISOString(),
    } satisfies ReadySessionPayload,
  };
}

export async function createReadyAuthenticationChallenge(
  request: Request,
  input: { walletAddress: string; chainId: typeof READY_AUTH_CHAIN_ID },
) {
  const now = new Date();
  const database = getDatabase();
  const active = await database
    .select({ id: readyAuthChallenges.id })
    .from(readyAuthChallenges)
    .where(and(
      eq(readyAuthChallenges.walletAddress, input.walletAddress),
      eq(readyAuthChallenges.chainId, input.chainId),
      isNull(readyAuthChallenges.consumedAt),
      gt(readyAuthChallenges.expiresAt, now),
    ))
    .limit(MAX_ACTIVE_CHALLENGES);
  if (active.length >= MAX_ACTIVE_CHALLENGES) {
    throw new ApiError(429, "Too many active Ready sign-in requests. Wait five minutes and retry.", "AUTH_RATE_LIMITED");
  }

  const id = generateUuidV7(now.getTime());
  const issuedAt = Math.floor(now.getTime() / 1_000);
  const expiresAt = new Date(now.getTime() + READY_AUTH_CHALLENGE_TTL_SECONDS * 1_000);
  const nonce = `0x${randomBytes(31).toString("hex")}`;
  const audience = authAudience(request);
  await database.insert(readyAuthChallenges).values({
    id,
    walletAddress: input.walletAddress,
    chainId: input.chainId,
    audience,
    nonce,
    issuedAt: now,
    expiresAt,
  });
  return {
    challengeId: id,
    expiresAt: expiresAt.toISOString(),
    typedData: buildReadyAuthTypedData({
      walletAddress: input.walletAddress,
      nonce,
      audience,
      issuedAt,
      expiresAt: Math.floor(expiresAt.getTime() / 1_000),
    }),
  };
}

export async function verifyReadyAuthenticationChallenge(input: {
  challengeId: string;
  signature: string[];
}, verifySignature: (input: {
  typedData: ReturnType<typeof buildReadyAuthTypedData>;
  signature: string[];
  walletAddress: string;
}) => Promise<boolean> = async ({ typedData, signature, walletAddress }) => authProvider().verifyMessageInStarknet(
  typedData,
  signature,
  walletAddress,
)): Promise<ReadySessionPayload> {
  const database = getDatabase();
  const now = new Date();
  const [challenge] = await database
    .select()
    .from(readyAuthChallenges)
    .where(eq(readyAuthChallenges.id, input.challengeId))
    .limit(1);
  if (
    !challenge
    || challenge.consumedAt
    || challenge.expiresAt <= now
    || challenge.attempts >= MAX_VERIFICATION_ATTEMPTS
  ) {
    throw new ApiError(401, "This Ready sign-in request is expired or already used.", "AUTH_CHALLENGE_INVALID");
  }

  const typedData = buildReadyAuthTypedData({
    walletAddress: challenge.walletAddress,
    nonce: challenge.nonce,
    audience: challenge.audience,
    issuedAt: Math.floor(challenge.issuedAt.getTime() / 1_000),
    expiresAt: Math.floor(challenge.expiresAt.getTime() / 1_000),
  });
  let verified = false;
  try {
    verified = await verifySignature({
      typedData,
      signature: input.signature,
      walletAddress: challenge.walletAddress,
    });
  } catch {
    throw new ApiError(503, "Ready signature verification is temporarily unavailable.", "AUTH_RPC_UNAVAILABLE");
  }
  if (!verified) {
    await database
      .update(readyAuthChallenges)
      .set({ attempts: sql`${readyAuthChallenges.attempts} + 1` })
      .where(eq(readyAuthChallenges.id, challenge.id));
    throw new ApiError(401, "Ready did not return a valid signature for this PAYO session.", "AUTH_SIGNATURE_INVALID");
  }

  return database.transaction(async (transaction) => {
    const [consumed] = await transaction
      .update(readyAuthChallenges)
      .set({ consumedAt: now })
      .where(and(
        eq(readyAuthChallenges.id, challenge.id),
        isNull(readyAuthChallenges.consumedAt),
        gt(readyAuthChallenges.expiresAt, now),
        lt(readyAuthChallenges.attempts, MAX_VERIFICATION_ATTEMPTS),
      ))
      .returning({ id: readyAuthChallenges.id });
    if (!consumed) {
      throw new ApiError(409, "This Ready sign-in request was already completed.", "AUTH_CHALLENGE_REPLAYED");
    }
    const [link] = await transaction
      .select({ principalId: readyPrincipalLinks.principalId })
      .from(readyPrincipalLinks)
      .where(and(
        eq(readyPrincipalLinks.walletAddress, challenge.walletAddress),
        eq(readyPrincipalLinks.chainId, challenge.chainId),
      ))
      .limit(1);
    const principalId = link?.principalId
      ?? readyWalletPrincipalId(challenge.chainId, challenge.walletAddress);
    const issued = issueSessionValues({
      walletAddress: challenge.walletAddress,
      chainId: READY_AUTH_CHAIN_ID,
      principalId,
      now,
    });
    await transaction.insert(readyAuthSessions).values(issued.row);
    return issued.payload;
  });
}

export async function revokeReadySession(principal: AuthenticatedPrincipal): Promise<void> {
  await getDatabase()
    .update(readyAuthSessions)
    .set({ revokedAt: new Date() })
    .where(and(
      eq(readyAuthSessions.id, principal.sessionId),
      isNull(readyAuthSessions.revokedAt),
    ));
}

export async function createReadyRecoveryLink(
  principal: AuthenticatedPrincipal,
  input: { organizationId: string; legacyPrincipalId: string },
): Promise<{ challengeId: string; expiresAt: string; envelope: EncryptedVaultRecord }> {
  const walletAddress = principal.walletAddress;
  const chainId = principal.chainId;
  if (!walletAddress || !chainId) {
    throw new ApiError(401, "A Ready-authorized PAYO session is required.", "AUTH_REQUIRED");
  }
  const database = getDatabase();
  const now = new Date();
  const walletPrincipal = readyWalletPrincipalId(chainId, walletAddress);
  if (principal.principalId !== walletPrincipal) {
    throw new ApiError(409, "This Ready wallet is already linked to a PAYO identity.", "AUTH_ALREADY_LINKED");
  }
  const [currentMembership] = await database
    .select({ organizationId: organizationMembers.organizationId })
    .from(organizationMembers)
    .where(and(
      eq(organizationMembers.principalId, principal.principalId),
      isNull(organizationMembers.revokedAt),
    ))
    .limit(1);
  if (currentMembership) {
    throw new ApiError(409, "This Ready identity already owns a PAYO workspace and cannot be relinked.", "AUTH_LINK_CONFLICT");
  }
  const [legacyMembership] = await database
    .select({ vaultPublicKey: organizationMembers.vaultPublicKey })
    .from(organizationMembers)
    .where(and(
      eq(organizationMembers.organizationId, input.organizationId),
      eq(organizationMembers.principalId, input.legacyPrincipalId),
      isNull(organizationMembers.revokedAt),
    ))
    .limit(1);
  if (!legacyMembership) {
    throw new ApiError(403, "The recovery package cannot authorize this workspace.", "AUTH_RECOVERY_FORBIDDEN");
  }
  const active = await database
    .select({ id: readyRecoveryLinkChallenges.id })
    .from(readyRecoveryLinkChallenges)
    .where(and(
      eq(readyRecoveryLinkChallenges.walletAddress, walletAddress),
      eq(readyRecoveryLinkChallenges.chainId, chainId),
      isNull(readyRecoveryLinkChallenges.consumedAt),
      gt(readyRecoveryLinkChallenges.expiresAt, now),
    ))
    .limit(MAX_ACTIVE_CHALLENGES);
  if (active.length >= MAX_ACTIVE_CHALLENGES) {
    throw new ApiError(429, "Too many active recovery-link requests. Wait ten minutes and retry.", "AUTH_RATE_LIMITED");
  }

  const id = generateUuidV7(now.getTime());
  const proof = `0x${randomBytes(32).toString("hex")}`;
  const expiresAt = new Date(now.getTime() + RECOVERY_LINK_TTL_SECONDS * 1_000);
  const envelope = encryptVaultRecord(
    { proof },
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "wallet-recovery-link",
      recordId: id,
      revision: 1,
    },
    [{ principalId: input.legacyPrincipalId, publicKey: legacyMembership.vaultPublicKey }],
  );
  await database.insert(readyRecoveryLinkChallenges).values({
    id,
    walletAddress,
    chainId,
    organizationId: input.organizationId,
    legacyPrincipalId: input.legacyPrincipalId,
    proofHash: digest(proof.toLowerCase()),
    expiresAt,
  });
  return { challengeId: id, expiresAt: expiresAt.toISOString(), envelope };
}

export async function completeReadyRecoveryLink(
  principal: AuthenticatedPrincipal,
  input: { challengeId: string; proof: string },
): Promise<ReadySessionPayload> {
  const walletAddress = principal.walletAddress;
  const chainId = principal.chainId;
  if (!walletAddress || !chainId) {
    throw new ApiError(401, "A Ready-authorized PAYO session is required.", "AUTH_REQUIRED");
  }
  const database = getDatabase();
  const now = new Date();
  const [challenge] = await database
    .select()
    .from(readyRecoveryLinkChallenges)
    .where(and(
      eq(readyRecoveryLinkChallenges.id, input.challengeId),
      eq(readyRecoveryLinkChallenges.walletAddress, walletAddress),
      eq(readyRecoveryLinkChallenges.chainId, chainId),
    ))
    .limit(1);
  if (
    !challenge
    || challenge.consumedAt
    || challenge.expiresAt <= now
    || challenge.attempts >= MAX_VERIFICATION_ATTEMPTS
  ) {
    throw new ApiError(401, "This recovery-link request is expired or already used.", "AUTH_RECOVERY_INVALID");
  }
  const proofHash = digest(input.proof.toLowerCase());
  if (!secureEqualHex(proofHash, challenge.proofHash)) {
    await database
      .update(readyRecoveryLinkChallenges)
      .set({ attempts: sql`${readyRecoveryLinkChallenges.attempts} + 1` })
      .where(eq(readyRecoveryLinkChallenges.id, challenge.id));
    throw new ApiError(401, "The recovery package could not prove control of this workspace.", "AUTH_RECOVERY_INVALID");
  }

  return database.transaction(async (transaction) => {
    const [consumed] = await transaction
      .update(readyRecoveryLinkChallenges)
      .set({ consumedAt: now })
      .where(and(
        eq(readyRecoveryLinkChallenges.id, challenge.id),
        isNull(readyRecoveryLinkChallenges.consumedAt),
        gt(readyRecoveryLinkChallenges.expiresAt, now),
        lt(readyRecoveryLinkChallenges.attempts, MAX_VERIFICATION_ATTEMPTS),
      ))
      .returning({ id: readyRecoveryLinkChallenges.id });
    if (!consumed) {
      throw new ApiError(409, "This recovery-link request was already completed.", "AUTH_RECOVERY_REPLAYED");
    }
    const [link] = await transaction
      .insert(readyPrincipalLinks)
      .values({
        walletAddress,
        chainId,
        principalId: challenge.legacyPrincipalId,
        linkMethod: "vault_recovery",
      })
      .onConflictDoNothing()
      .returning({ principalId: readyPrincipalLinks.principalId });
    if (!link) {
      const [existing] = await transaction
        .select({ principalId: readyPrincipalLinks.principalId })
        .from(readyPrincipalLinks)
        .where(and(
          eq(readyPrincipalLinks.walletAddress, walletAddress),
          eq(readyPrincipalLinks.chainId, chainId),
        ))
        .limit(1);
      if (existing?.principalId !== challenge.legacyPrincipalId) {
        throw new ApiError(409, "This Ready wallet is linked to another PAYO identity.", "AUTH_LINK_CONFLICT");
      }
    }
    await transaction
      .update(readyAuthSessions)
      .set({ revokedAt: now })
      .where(and(
        eq(readyAuthSessions.walletAddress, walletAddress),
        eq(readyAuthSessions.chainId, chainId),
        isNull(readyAuthSessions.revokedAt),
      ));
    const issued = issueSessionValues({
      walletAddress,
      chainId: READY_AUTH_CHAIN_ID,
      principalId: challenge.legacyPrincipalId,
      now,
    });
    await transaction.insert(readyAuthSessions).values(issued.row);
    return issued.payload;
  });
}
