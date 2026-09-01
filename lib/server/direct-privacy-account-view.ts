import "server-only";

import { and, eq, isNull } from "drizzle-orm";
import { directPrivacyAccountConfigSchema } from "@/lib/domain/direct-privacy";
import {
  directPrivacyAccounts,
  directPrivacyAuthorizedRuns,
  directPrivacyTreasuries,
} from "@/lib/persistence/schema";
import type {
  DirectPrivacyAccountPublic,
  DirectPrivacyAccountSummary,
} from "@/lib/persistence/direct-privacy-repository";
import { getDatabase } from "@/lib/persistence/db";
import { requireOrganizationRoleWith } from "@/lib/persistence/repository";
import { ApiError, type AuthenticatedPrincipal } from "./auth";
import { decryptDirectPrivacyPayload } from "./direct-privacy-crypto";

function activationEvidence(account: typeof directPrivacyAccounts.$inferSelect): DirectPrivacyAccountPublic["activation"] {
  if (account.activationState === "pending") return null;
  if (
    account.activationState !== "active"
    || account.activationBlockNumber === null
    || !account.activationBlockHash
    || !account.activationClassHash
    || account.activationBlockTimestamp === null
    || !account.activatedAt
  ) throw new Error("DIRECT_ACCOUNT_ACTIVATION_EVIDENCE_INVALID");
  return {
    blockNumber: account.activationBlockNumber.toString(),
    blockHash: account.activationBlockHash,
    classHash: account.activationClassHash,
    blockTimestamp: account.activationBlockTimestamp.toString(),
    activatedAt: account.activatedAt.toISOString(),
  };
}

function accountSummary(
  account: typeof directPrivacyAccounts.$inferSelect,
  treasury: typeof directPrivacyTreasuries.$inferSelect,
  authorizedRunCount: number,
): DirectPrivacyAccountSummary {
  const config = directPrivacyAccountConfigSchema.parse(account.config);
  if (
    treasury.organizationId !== account.organizationId
    || BigInt(config.policyAccountAddress) !== BigInt(treasury.policyAccountAddress)
  ) {
    throw new Error("DIRECT_TREASURY_DEPLOYMENT_MISMATCH");
  }
  return {
    id: account.id,
    capabilityId: account.capabilityId,
    config,
    stateVersion: treasury.stateVersion,
    authorizedRunCount,
    activationState: account.activationState as "pending" | "active",
    activation: activationEvidence(account),
    activeExecutionId: treasury.activeExecutionId,
    activeLeaseExpiresAt: treasury.activeLeaseExpiresAt?.toISOString() ?? null,
    createdAt: account.createdAt.toISOString(),
    updatedAt: new Date(Math.max(account.updatedAt.getTime(), treasury.updatedAt.getTime())).toISOString(),
  };
}

/** Returns only public policy material; encrypted spend/view/session secrets never leave the server. */
export async function getDirectPrivacyAccountPublic(input: {
  accountId: string;
  principal: AuthenticatedPrincipal;
}): Promise<DirectPrivacyAccountPublic> {
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts)
      .where(eq(directPrivacyAccounts.id, input.accountId)).limit(1);
    if (!account || account.revokedAt) {
      throw new ApiError(404, "Direct private account not found.", "DIRECT_ACCOUNT_NOT_FOUND");
    }
    await requireOrganizationRoleWith(transaction, account.organizationId, input.principal, ["admin"]);
    const [treasury] = await transaction.select().from(directPrivacyTreasuries).where(
      eq(directPrivacyTreasuries.policyAccountAddress, account.treasuryAddress),
    ).limit(1);
    if (!treasury) throw new Error("DIRECT_TREASURY_NOT_FOUND");
    const authorizedRuns = await transaction.select({ id: directPrivacyAuthorizedRuns.id })
      .from(directPrivacyAuthorizedRuns)
      .where(eq(directPrivacyAuthorizedRuns.accountId, account.id));
    const secrets = decryptDirectPrivacyPayload(account.encryptedSecrets, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "secrets",
    });
    const summary = accountSummary(account, treasury, authorizedRuns.length);
    return {
      id: summary.id,
      config: summary.config,
      proofPrincipal: {
        principalId: secrets.proofPrincipal.principalId,
        publicKey: secrets.proofPrincipal.publicKey,
      },
      stateVersion: summary.stateVersion,
      authorizedRunCount: summary.authorizedRunCount,
      activationState: summary.activationState,
      activation: summary.activation,
    };
  });
}

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

/**
 * Resolves a lost-response retry without creating a second policy account.
 * Every caller-controlled scope remains exact; the stored configuration is
 * returned only for the same capability, policy, run set, period and limits.
 */
export async function getDirectPrivacyProvisioningReplay(input: {
  organizationId: string;
  capabilityId: string;
  runIds: readonly string[];
  policyAccountAddress: string;
  policyId: string;
  periodSeconds: number;
  maxCallsPerPeriod: number;
  maxCallCount: number;
  principal: AuthenticatedPrincipal;
}): Promise<DirectPrivacyAccountPublic | null> {
  return getDatabase().transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin"]);
    const [account] = await transaction.select().from(directPrivacyAccounts).where(and(
      eq(directPrivacyAccounts.organizationId, input.organizationId),
      eq(directPrivacyAccounts.capabilityId, input.capabilityId),
      isNull(directPrivacyAccounts.revokedAt),
    )).limit(1);
    if (!account) return null;
    const config = directPrivacyAccountConfigSchema.parse(account.config);
    const [treasury] = await transaction.select().from(directPrivacyTreasuries).where(
      eq(directPrivacyTreasuries.policyAccountAddress, account.treasuryAddress),
    ).limit(1);
    if (!treasury) throw new Error("DIRECT_TREASURY_NOT_FOUND");
    const authorizedRuns = await transaction.select({
      id: directPrivacyAuthorizedRuns.id,
      runId: directPrivacyAuthorizedRuns.runId,
    }).from(directPrivacyAuthorizedRuns).where(eq(
      directPrivacyAuthorizedRuns.accountId,
      account.id,
    ));
    const requestedRunIds = [...input.runIds].sort();
    const storedRunIds = authorizedRuns.map(({ runId }) => runId).sort();
    if (
      !sameFelt(config.policyAccountAddress, input.policyAccountAddress)
      || !sameFelt(config.policyId, input.policyId)
      || BigInt(config.periodSeconds) !== BigInt(input.periodSeconds)
      || config.maxCallsPerPeriod !== input.maxCallsPerPeriod
      || config.maxCallCount !== input.maxCallCount
      || requestedRunIds.length !== storedRunIds.length
      || requestedRunIds.some((runId, index) => runId !== storedRunIds[index])
    ) {
      throw new ApiError(
        409,
        "This capability already has a different direct private policy.",
        "DIRECT_ACCOUNT_REPLAY_MISMATCH",
      );
    }
    const secrets = decryptDirectPrivacyPayload(account.encryptedSecrets, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "secrets",
    });
    const summary = accountSummary(account, treasury, authorizedRuns.length);
    return {
      id: summary.id,
      config: summary.config,
      proofPrincipal: {
        principalId: secrets.proofPrincipal.principalId,
        publicKey: secrets.proofPrincipal.publicKey,
      },
      stateVersion: summary.stateVersion,
      authorizedRunCount: summary.authorizedRunCount,
      activationState: summary.activationState,
      activation: summary.activation,
    };
  });
}

/** Lists redacted operational state; encrypted spend/view/session secrets never leave the server. */
export async function listDirectPrivacyAccountsPublic(input: {
  organizationId: string;
  principal: AuthenticatedPrincipal;
}): Promise<DirectPrivacyAccountSummary[]> {
  return getDatabase().transaction(async (transaction) => {
    await requireOrganizationRoleWith(
      transaction,
      input.organizationId,
      input.principal,
      ["admin", "operator", "reviewer"],
    );
    const rows = await transaction.select({
      account: directPrivacyAccounts,
      treasury: directPrivacyTreasuries,
    }).from(directPrivacyAccounts).innerJoin(
      directPrivacyTreasuries,
      eq(directPrivacyTreasuries.policyAccountAddress, directPrivacyAccounts.treasuryAddress),
    ).where(and(
      eq(directPrivacyAccounts.organizationId, input.organizationId),
      isNull(directPrivacyAccounts.revokedAt),
    ));
    const counts = rows.length === 0
      ? []
      : await transaction.select({
          accountId: directPrivacyAuthorizedRuns.accountId,
          id: directPrivacyAuthorizedRuns.id,
        }).from(directPrivacyAuthorizedRuns).where(eq(
          directPrivacyAuthorizedRuns.organizationId,
          input.organizationId,
        ));
    const countByAccount = new Map<string, number>();
    for (const row of counts) {
      countByAccount.set(row.accountId, (countByAccount.get(row.accountId) ?? 0) + 1);
    }
    return rows.map(({ account, treasury }) =>
      accountSummary(account, treasury, countByAccount.get(account.id) ?? 0));
  });
}
