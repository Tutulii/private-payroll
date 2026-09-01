import "server-only";

import { and, eq, or } from "drizzle-orm";
import {
  commitDirectPrivacyPreparedSubmission,
  directPrivacyPreparedSubmissionSchema,
  type DirectPrivacyPreparedSubmission,
} from "@/lib/domain/direct-privacy";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  decryptDirectPrivacyPayload,
  encryptDirectPrivacyPayload,
} from "@/lib/server/direct-privacy-crypto";
import type { LeasedAgentExecution } from "./agent-execution-worker-repository";
import { getDatabase } from "./db";
import {
  auditEvents,
  directPrivacyAccounts,
  directPrivacySubmissions,
  directPrivacyTreasuries,
} from "./schema";

const COMMITMENT_PATTERN = /^0x[0-9a-f]{64}$/;
const HASH_PATTERN = /^0x[0-9a-fA-F]{1,64}$/;

export async function storePreparedDirectPrivacySubmission(input: {
  job: Pick<
    LeasedAgentExecution,
    "id" | "capabilityId" | "organizationId" | "requestCommitment"
  >;
  accountId: string;
  prepared: DirectPrivacyPreparedSubmission;
  now?: Date;
}): Promise<{ submissionCommitment: `0x${string}`; expectedTransactionHash: string }> {
  const prepared = directPrivacyPreparedSubmissionSchema.parse(input.prepared);
  if (
    prepared.executionId !== input.job.id
    || prepared.requestCommitment !== input.job.requestCommitment
  ) throw new Error("DIRECT_PREPARED_BINDING_INVALID");
  const submissionCommitment = commitDirectPrivacyPreparedSubmission(prepared);
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts).where(and(
      eq(directPrivacyAccounts.id, input.accountId),
      eq(directPrivacyAccounts.capabilityId, input.job.capabilityId),
    )).limit(1).for("update");
    if (!account || account.organizationId !== input.job.organizationId) {
      throw new Error("DIRECT_PREPARED_ACCOUNT_STALE");
    }
    const [treasury] = await transaction.select().from(directPrivacyTreasuries).where(
      eq(directPrivacyTreasuries.policyAccountAddress, account.treasuryAddress),
    ).limit(1).for("update");
    if (
      !treasury
      || treasury.organizationId !== account.organizationId
      || treasury.activeAccountId !== account.id
      || treasury.activeExecutionId !== input.job.id
      || treasury.stateVersion !== prepared.expectedStateVersion
    ) throw new Error("DIRECT_PREPARED_ACCOUNT_STALE");
    const [existing] = await transaction.select().from(directPrivacySubmissions).where(
      eq(directPrivacySubmissions.executionId, input.job.id),
    ).limit(1).for("update");
    if (existing) {
      if (
        existing.accountId !== account.id
        || existing.submissionCommitment !== submissionCommitment
        || BigInt(existing.expectedTransactionHash) !== BigInt(prepared.expectedTransactionHash)
      ) throw new Error("DIRECT_SUBMISSION_REPLAY_CONFLICT");
      return {
        submissionCommitment,
        expectedTransactionHash: existing.expectedTransactionHash,
      };
    }
    const encryptedPrepared = encryptDirectPrivacyPayload(prepared, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "submission",
      executionId: input.job.id,
      submissionCommitment,
    });
    await transaction.insert(directPrivacySubmissions).values({
      executionId: input.job.id,
      accountId: account.id,
      organizationId: account.organizationId,
      submissionCommitment,
      expectedTransactionHash: prepared.expectedTransactionHash,
      encryptedPrepared,
      state: "prepared",
      createdAt: now,
      updatedAt: now,
    });
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: account.organizationId,
      actorId: "system:direct-privacy-driver",
      action: "direct_privacy_submission.prepared",
      subjectId: input.job.id,
      metadata: { submissionCommitment, expectedTransactionHash: prepared.expectedTransactionHash },
    });
    return { submissionCommitment, expectedTransactionHash: prepared.expectedTransactionHash };
  });
}

function decryptPrepared(
  row: typeof directPrivacySubmissions.$inferSelect,
  account: typeof directPrivacyAccounts.$inferSelect,
): DirectPrivacyPreparedSubmission {
  return decryptDirectPrivacyPayload(row.encryptedPrepared, {
    accountId: account.id,
    organizationId: account.organizationId,
    capabilityId: account.capabilityId,
    purpose: "submission",
    executionId: row.executionId,
    submissionCommitment: row.submissionCommitment,
  });
}

export async function loadPreparedDirectPrivacySubmission(input: {
  executionId: string;
  requestCommitment: string;
  submissionCommitment: string;
}): Promise<DirectPrivacyPreparedSubmission> {
  if (!COMMITMENT_PATTERN.test(input.submissionCommitment)) {
    throw new Error("DIRECT_SUBMISSION_COMMITMENT_INVALID");
  }
  const [joined] = await getDatabase().select({
    submission: directPrivacySubmissions,
    account: directPrivacyAccounts,
  }).from(directPrivacySubmissions).innerJoin(
    directPrivacyAccounts,
    eq(directPrivacyAccounts.id, directPrivacySubmissions.accountId),
  ).where(and(
    eq(directPrivacySubmissions.executionId, input.executionId),
    eq(directPrivacySubmissions.submissionCommitment, input.submissionCommitment),
  )).limit(1);
  if (!joined) throw new Error("DIRECT_SUBMISSION_NOT_FOUND");
  const prepared = decryptPrepared(joined.submission, joined.account);
  if (
    prepared.requestCommitment !== input.requestCommitment
    || commitDirectPrivacyPreparedSubmission(prepared) !== input.submissionCommitment
  ) throw new Error("DIRECT_SUBMISSION_TAMPERED");
  return prepared;
}

export async function loadDirectPrivacySubmissionByExecution(
  executionId: string,
): Promise<{
  prepared: DirectPrivacyPreparedSubmission;
  submissionCommitment: string;
  state: string;
} | null> {
  const [joined] = await getDatabase().select({
    row: directPrivacySubmissions,
    account: directPrivacyAccounts,
  }).from(directPrivacySubmissions).innerJoin(
    directPrivacyAccounts,
    eq(directPrivacyAccounts.id, directPrivacySubmissions.accountId),
  ).where(eq(directPrivacySubmissions.executionId, executionId)).limit(1);
  if (!joined) return null;
  const prepared = decryptPrepared(joined.row, joined.account);
  if (commitDirectPrivacyPreparedSubmission(prepared) !== joined.row.submissionCommitment) {
    throw new Error("DIRECT_SUBMISSION_TAMPERED");
  }
  return { prepared, submissionCommitment: joined.row.submissionCommitment, state: joined.row.state };
}

export async function markDirectPrivacySubmissionBroadcasting(
  executionId: string,
  submissionCommitment: string,
  now = new Date(),
): Promise<void> {
  const [updated] = await getDatabase().update(directPrivacySubmissions).set({
    state: "broadcasting",
    updatedAt: now,
  }).where(and(
    eq(directPrivacySubmissions.executionId, executionId),
    eq(directPrivacySubmissions.submissionCommitment, submissionCommitment),
    or(
      eq(directPrivacySubmissions.state, "prepared"),
      eq(directPrivacySubmissions.state, "reorged"),
    ),
  )).returning();
  if (!updated) {
    const [current] = await getDatabase().select().from(directPrivacySubmissions).where(and(
      eq(directPrivacySubmissions.executionId, executionId),
      eq(directPrivacySubmissions.submissionCommitment, submissionCommitment),
    )).limit(1);
    if (!current || !["broadcasting", "submitted", "confirmed"].includes(current.state)) {
      throw new Error("DIRECT_SUBMISSION_STATE_INVALID");
    }
  }
}

export async function recordDirectPrivacyBroadcast(input: {
  executionId: string;
  submissionCommitment: string;
  transactionHash: string;
  now?: Date;
}): Promise<void> {
  if (!HASH_PATTERN.test(input.transactionHash)) throw new Error("DIRECT_TRANSACTION_HASH_INVALID");
  const now = input.now ?? new Date();
  await getDatabase().transaction(async (transaction) => {
    const [row] = await transaction.select().from(directPrivacySubmissions).where(and(
      eq(directPrivacySubmissions.executionId, input.executionId),
      eq(directPrivacySubmissions.submissionCommitment, input.submissionCommitment),
    )).limit(1).for("update");
    if (!row || !["broadcasting", "submitted"].includes(row.state)) {
      throw new Error("DIRECT_SUBMISSION_STATE_INVALID");
    }
    if (BigInt(row.expectedTransactionHash) !== BigInt(input.transactionHash)) {
      throw new Error("DIRECT_TRANSACTION_HASH_MISMATCH");
    }
    await transaction.update(directPrivacySubmissions).set({
      state: "submitted",
      transactionHash: input.transactionHash.toLowerCase(),
      updatedAt: now,
    }).where(eq(directPrivacySubmissions.executionId, row.executionId));
  });
}

export async function findDirectPrivacySubmission(
  transactionHash: string,
): Promise<{
  row: typeof directPrivacySubmissions.$inferSelect;
  account: typeof directPrivacyAccounts.$inferSelect;
  prepared: DirectPrivacyPreparedSubmission;
} | null> {
  if (!HASH_PATTERN.test(transactionHash)) return null;
  const [joined] = await getDatabase().select({
    row: directPrivacySubmissions,
    account: directPrivacyAccounts,
  }).from(directPrivacySubmissions).innerJoin(
    directPrivacyAccounts,
    eq(directPrivacyAccounts.id, directPrivacySubmissions.accountId),
  ).where(or(
    eq(directPrivacySubmissions.expectedTransactionHash, transactionHash.toLowerCase()),
    eq(directPrivacySubmissions.transactionHash, transactionHash.toLowerCase()),
  )).limit(1);
  if (!joined) return null;
  return { ...joined, prepared: decryptPrepared(joined.row, joined.account) };
}

export async function finalizeDirectPrivacySubmission(
  transactionHash: string,
  now = new Date(),
): Promise<void> {
  await getDatabase().transaction(async (transaction) => {
    const [row] = await transaction.select().from(directPrivacySubmissions).where(or(
      eq(directPrivacySubmissions.expectedTransactionHash, transactionHash.toLowerCase()),
      eq(directPrivacySubmissions.transactionHash, transactionHash.toLowerCase()),
    )).limit(1).for("update");
    if (!row) throw new Error("DIRECT_SUBMISSION_NOT_FOUND");
    if (row.state === "confirmed") return;
    if (!row.transactionHash || BigInt(row.transactionHash) !== BigInt(transactionHash)) {
      throw new Error("DIRECT_SUBMISSION_HASH_UNRECORDED");
    }
    const [account] = await transaction.select().from(directPrivacyAccounts).where(
      eq(directPrivacyAccounts.id, row.accountId),
    ).limit(1).for("update");
    if (!account) throw new Error("DIRECT_ACCOUNT_LEASE_LOST");
    const [treasury] = await transaction.select().from(directPrivacyTreasuries).where(
      eq(directPrivacyTreasuries.policyAccountAddress, account.treasuryAddress),
    ).limit(1).for("update");
    if (
      !treasury
      || treasury.organizationId !== account.organizationId
      || treasury.activeAccountId !== account.id
      || treasury.activeExecutionId !== row.executionId
    ) throw new Error("DIRECT_ACCOUNT_LEASE_LOST");
    const prepared = decryptPrepared(row, account);
    if (treasury.stateVersion !== prepared.expectedStateVersion) {
      throw new Error("DIRECT_STATE_VERSION_CONFLICT");
    }
    const nextVersion = treasury.stateVersion + 1;
    const encryptedState = encryptDirectPrivacyPayload(prepared.nextState, {
      policyAccountAddress: treasury.policyAccountAddress,
      organizationId: treasury.organizationId,
      poolAddress: treasury.poolAddress,
      purpose: "treasury-state",
      stateVersion: nextVersion,
    });
    await transaction.update(directPrivacyTreasuries).set({
      encryptedState,
      stateVersion: nextVersion,
      activeExecutionId: null,
      activeAccountId: null,
      activeLeaseExpiresAt: null,
      updatedAt: now,
    }).where(eq(directPrivacyTreasuries.policyAccountAddress, treasury.policyAccountAddress));
    await transaction.update(directPrivacySubmissions).set({ state: "confirmed", updatedAt: now })
      .where(eq(directPrivacySubmissions.executionId, row.executionId));
  });
}

export async function failDirectPrivacySubmission(
  transactionHash: string,
  state: "reverted" | "reorged",
  now = new Date(),
): Promise<void> {
  await getDatabase().transaction(async (transaction) => {
    const [row] = await transaction.select().from(directPrivacySubmissions).where(or(
      eq(directPrivacySubmissions.expectedTransactionHash, transactionHash.toLowerCase()),
      eq(directPrivacySubmissions.transactionHash, transactionHash.toLowerCase()),
    )).limit(1).for("update");
    if (!row || row.state === "confirmed") return;
    await transaction.update(directPrivacySubmissions).set({ state, updatedAt: now })
      .where(eq(directPrivacySubmissions.executionId, row.executionId));
    if (state === "reverted") {
      const [account] = await transaction.select().from(directPrivacyAccounts).where(
        eq(directPrivacyAccounts.id, row.accountId),
      ).limit(1);
      if (account) {
        await transaction.update(directPrivacyTreasuries).set({
          activeExecutionId: null,
          activeAccountId: null,
          activeLeaseExpiresAt: null,
          updatedAt: now,
        }).where(and(
          eq(directPrivacyTreasuries.policyAccountAddress, account.treasuryAddress),
          eq(directPrivacyTreasuries.activeAccountId, account.id),
          eq(directPrivacyTreasuries.activeExecutionId, row.executionId),
        ));
      }
    }
  });
}
