import "server-only";

import { and, eq } from "drizzle-orm";
import {
  commitDirectPrivacyPayrollAuthorization,
  directPrivacyPayrollAuthorizationSchema,
  type DirectPrivacyPayrollAuthorization,
} from "@/lib/domain/direct-privacy";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  decryptDirectPrivacyPayload,
  encryptDirectPrivacyPayload,
} from "@/lib/server/direct-privacy-crypto";
import { getDatabase } from "./db";
import {
  auditEvents,
  directPrivacyAccounts,
  directPrivacyPayrollAuthorizations,
} from "./schema";

const HASH_PATTERN = /^0x[0-9a-fA-F]{1,64}$/;
const STATE_RANK = {
  proof_ready: 0,
  sealed: 1,
  shard0_verified: 2,
  shard1_verified: 3,
  proven: 4,
} as const;
type AuthorizationState = keyof typeof STATE_RANK;
type AuthorizationRow = typeof directPrivacyPayrollAuthorizations.$inferSelect;
type AccountRow = typeof directPrivacyAccounts.$inferSelect;

function decryptAuthorization(
  row: AuthorizationRow,
  account: AccountRow,
): DirectPrivacyPayrollAuthorization {
  const authorization = decryptDirectPrivacyPayload(row.encryptedAuthorization, {
    accountId: account.id,
    organizationId: account.organizationId,
    capabilityId: account.capabilityId,
    purpose: "payroll-authorization",
    executionId: row.executionId,
    authorizationCommitment: row.authorizationCommitment,
  });
  if (
    commitDirectPrivacyPayrollAuthorization(authorization)
      !== row.authorizationCommitment
  ) throw new Error("DIRECT_PAYROLL_AUTHORIZATION_TAMPERED");
  return authorization;
}

export async function storeDirectPrivacyPayrollAuthorization(input: {
  accountId: string;
  organizationId: string;
  executionId: string;
  requestCommitment: string;
  authorization: DirectPrivacyPayrollAuthorization;
  now?: Date;
}): Promise<{ authorizationCommitment: `0x${string}`; replayed: boolean }> {
  const authorization = directPrivacyPayrollAuthorizationSchema.parse(input.authorization);
  if (
    authorization.executionId !== input.executionId
    || authorization.requestCommitment.toLowerCase()
      !== input.requestCommitment.toLowerCase()
  ) throw new Error("DIRECT_PAYROLL_AUTHORIZATION_BINDING_INVALID");
  const authorizationCommitment = commitDirectPrivacyPayrollAuthorization(authorization);
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts).where(and(
      eq(directPrivacyAccounts.id, input.accountId),
      eq(directPrivacyAccounts.organizationId, input.organizationId),
    )).limit(1).for("update");
    if (
      !account
      || account.revokedAt
      || account.activeExecutionId !== input.executionId
    ) throw new Error("DIRECT_PAYROLL_AUTHORIZATION_ACCOUNT_STALE");
    const [existing] = await transaction.select()
      .from(directPrivacyPayrollAuthorizations)
      .where(eq(directPrivacyPayrollAuthorizations.executionId, input.executionId))
      .limit(1).for("update");
    if (existing) {
      if (
        existing.accountId !== input.accountId
        || existing.organizationId !== input.organizationId
        || existing.authorizationCommitment !== authorizationCommitment
      ) throw new Error("DIRECT_PAYROLL_AUTHORIZATION_REPLAY_CONFLICT");
      return { authorizationCommitment, replayed: true };
    }
    const encryptedAuthorization = encryptDirectPrivacyPayload(authorization, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "payroll-authorization",
      executionId: input.executionId,
      authorizationCommitment,
    });
    await transaction.insert(directPrivacyPayrollAuthorizations).values({
      executionId: input.executionId,
      accountId: account.id,
      organizationId: account.organizationId,
      authorizationCommitment,
      encryptedAuthorization,
      state: "proof_ready",
      createdAt: now,
      updatedAt: now,
    });
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: account.organizationId,
      actorId: "system:direct-privacy-driver",
      action: "direct_privacy_payroll_authorization.stored",
      subjectId: input.executionId,
      metadata: {
        authorizationCommitment,
        shardHashes: authorization.shards.map(({ calldataHash }) => calldataHash),
      },
    });
    return { authorizationCommitment, replayed: false };
  });
}

export async function loadDirectPrivacyPayrollAuthorization(executionId: string): Promise<{
  row: AuthorizationRow;
  account: AccountRow;
  authorization: DirectPrivacyPayrollAuthorization;
} | null> {
  const [joined] = await getDatabase().select({
    row: directPrivacyPayrollAuthorizations,
    account: directPrivacyAccounts,
  }).from(directPrivacyPayrollAuthorizations).innerJoin(
    directPrivacyAccounts,
    eq(directPrivacyAccounts.id, directPrivacyPayrollAuthorizations.accountId),
  ).where(eq(directPrivacyPayrollAuthorizations.executionId, executionId)).limit(1);
  if (!joined) return null;
  return {
    ...joined,
    authorization: decryptAuthorization(joined.row, joined.account),
  };
}

export async function recordDirectPrivacyPayrollAuthorizationProgress(input: {
  executionId: string;
  state: Exclude<AuthorizationState, "proof_ready">;
  transactionHash?: string;
  now?: Date;
}): Promise<void> {
  if (input.transactionHash && !HASH_PATTERN.test(input.transactionHash)) {
    throw new Error("DIRECT_PAYROLL_AUTHORIZATION_HASH_INVALID");
  }
  const now = input.now ?? new Date();
  await getDatabase().transaction(async (transaction) => {
    const [row] = await transaction.select().from(directPrivacyPayrollAuthorizations)
      .where(eq(directPrivacyPayrollAuthorizations.executionId, input.executionId))
      .limit(1).for("update");
    if (!row || !(row.state in STATE_RANK)) {
      throw new Error("DIRECT_PAYROLL_AUTHORIZATION_NOT_FOUND");
    }
    const current = row.state as AuthorizationState;
    if (STATE_RANK[input.state] < STATE_RANK[current]) return;
    const field = input.state === "sealed" ? "precommitTransactionHash"
      : input.state === "shard0_verified" ? "shard0TransactionHash"
        : input.state === "shard1_verified" || input.state === "proven"
          ? "shard1TransactionHash"
          : null;
    if (
      field
      && input.transactionHash
      && row[field]
      && BigInt(row[field]!) !== BigInt(input.transactionHash)
    ) throw new Error("DIRECT_PAYROLL_AUTHORIZATION_HASH_CONFLICT");
    await transaction.update(directPrivacyPayrollAuthorizations).set({
      state: input.state,
      ...(field && input.transactionHash
        ? { [field]: input.transactionHash.toLowerCase() }
        : {}),
      updatedAt: now,
    }).where(eq(directPrivacyPayrollAuthorizations.executionId, input.executionId));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: row.organizationId,
      actorId: "system:direct-privacy-driver",
      action: input.state === "proven"
        ? "direct_privacy_payroll_authorization.proven"
        : "direct_privacy_payroll_authorization.progressed",
      subjectId: input.executionId,
      metadata: {
        state: input.state,
        ...(input.transactionHash
          ? { transactionHash: input.transactionHash.toLowerCase() }
          : { recoveredFromChain: true }),
      },
    });
  });
}
