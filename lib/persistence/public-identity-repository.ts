import "server-only";

import { and, eq } from "drizzle-orm";
import { validateAndParseAddress } from "starknet";
import {
  parsePayoPublicIdentity,
  type PayoPublicIdentity,
} from "@/lib/client/proof-package-files";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { workerPublicIdentities } from "./schema";

function readyWallet(principal: AuthenticatedPrincipal): { chainId: string; walletAddress: string } {
  if (principal.authKind !== "ready" || !principal.chainId || !principal.walletAddress) {
    throw new ApiError(403, "A Ready wallet session is required for public identity discovery.", "READY_AUTH_REQUIRED");
  }
  return {
    chainId: principal.chainId,
    walletAddress: validateAndParseAddress(principal.walletAddress),
  };
}

function publicIdentityV2(value: unknown): Extract<PayoPublicIdentity, { format: "payo-public-identity-v2" }> {
  const identity = parsePayoPublicIdentity(value);
  if (identity.format !== "payo-public-identity-v2") {
    throw new ApiError(400, "Publish a PAYO v2 worker identity.", "PUBLIC_IDENTITY_V2_REQUIRED");
  }
  return identity;
}

export async function publishWorkerPublicIdentity(input: {
  identity: unknown;
  principal: AuthenticatedPrincipal;
}) {
  const owner = readyWallet(input.principal);
  const identity = publicIdentityV2(input.identity);
  if (identity.principalId !== input.principal.principalId) {
    throw new ApiError(
      403,
      "The public identity does not belong to the authenticated Ready wallet.",
      "PUBLIC_IDENTITY_PRINCIPAL_MISMATCH",
    );
  }
  const now = new Date();
  const [published] = await getDatabase()
    .insert(workerPublicIdentities)
    .values({
      ...owner,
      principalId: identity.principalId,
      fingerprint: identity.fingerprint.toLowerCase(),
      identity,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: [workerPublicIdentities.chainId, workerPublicIdentities.walletAddress],
      set: {
        principalId: identity.principalId,
        fingerprint: identity.fingerprint.toLowerCase(),
        identity,
        updatedAt: now,
      },
    })
    .returning({
      chainId: workerPublicIdentities.chainId,
      walletAddress: workerPublicIdentities.walletAddress,
      principalId: workerPublicIdentities.principalId,
      fingerprint: workerPublicIdentities.fingerprint,
      identity: workerPublicIdentities.identity,
      firstPublishedAt: workerPublicIdentities.firstPublishedAt,
      updatedAt: workerPublicIdentities.updatedAt,
    });
  return { ...published, identity: publicIdentityV2(published.identity) };
}

export async function findWorkerPublicIdentity(input: {
  walletAddress: string;
  principal: AuthenticatedPrincipal;
}) {
  const requester = readyWallet(input.principal);
  const walletAddress = validateAndParseAddress(input.walletAddress);
  const [published] = await getDatabase()
    .select({
      chainId: workerPublicIdentities.chainId,
      walletAddress: workerPublicIdentities.walletAddress,
      principalId: workerPublicIdentities.principalId,
      fingerprint: workerPublicIdentities.fingerprint,
      identity: workerPublicIdentities.identity,
      firstPublishedAt: workerPublicIdentities.firstPublishedAt,
      updatedAt: workerPublicIdentities.updatedAt,
    })
    .from(workerPublicIdentities)
    .where(and(
      eq(workerPublicIdentities.chainId, requester.chainId),
      eq(workerPublicIdentities.walletAddress, walletAddress),
    ))
    .limit(1);
  return published ? { ...published, identity: publicIdentityV2(published.identity) } : null;
}
