import "server-only";

import { and, eq } from "drizzle-orm";
import {
  commitDirectPrivacyPreparation,
  directPrivacyPreparationSchema,
  type DirectPrivacyPreparation,
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
  directPrivacyPreparations,
  directPrivacyTreasuries,
  directPrivacySubmissions,
} from "./schema";

const COMMITMENT_PATTERN = /^0x[0-9a-f]{64}$/;

function decryptPreparation(
  row: typeof directPrivacyPreparations.$inferSelect,
  account: typeof directPrivacyAccounts.$inferSelect,
): DirectPrivacyPreparation {
  return decryptDirectPrivacyPayload(row.encryptedPreparation, {
    accountId: account.id,
    organizationId: account.organizationId,
    capabilityId: account.capabilityId,
    purpose: "preparation",
    executionId: row.executionId,
    preparationCommitment: row.preparationCommitment,
  });
}

export async function storeDirectPrivacyPreparation(input: {
  job: LeasedAgentExecution;
  accountId: string;
  preparation: DirectPrivacyPreparation;
  now?: Date;
}): Promise<{ preparationCommitment: `0x${string}` }> {
  const preparation = directPrivacyPreparationSchema.parse(input.preparation);
  if (
    preparation.executionId !== input.job.id
    || preparation.requestCommitment !== input.job.requestCommitment
  ) throw new Error("DIRECT_PREPARATION_BINDING_INVALID");
  const preparationCommitment = commitDirectPrivacyPreparation(preparation);
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts).where(and(
      eq(directPrivacyAccounts.id, input.accountId),
      eq(directPrivacyAccounts.capabilityId, input.job.capabilityId),
    )).limit(1).for("update");
    if (
      !account
      || account.revokedAt
      || account.organizationId !== input.job.organizationId
    ) throw new Error("DIRECT_PREPARATION_ACCOUNT_STALE");
    const [treasury] = await transaction.select().from(directPrivacyTreasuries).where(
      eq(directPrivacyTreasuries.policyAccountAddress, account.treasuryAddress),
    ).limit(1).for("update");
    if (
      !treasury
      || treasury.organizationId !== account.organizationId
      || treasury.activeAccountId !== account.id
      || treasury.activeExecutionId !== input.job.id
      || treasury.stateVersion !== preparation.expectedStateVersion
    ) throw new Error("DIRECT_PREPARATION_ACCOUNT_STALE");
    const [existing] = await transaction.select().from(directPrivacyPreparations).where(
      eq(directPrivacyPreparations.executionId, input.job.id),
    ).limit(1).for("update");
    if (existing) {
      if (
        existing.accountId !== account.id
        || existing.preparationCommitment !== preparationCommitment
        || existing.state === "abandoned"
      ) throw new Error("DIRECT_PREPARATION_REPLAY_CONFLICT");
      return { preparationCommitment };
    }
    const encryptedPreparation = encryptDirectPrivacyPayload(preparation, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "preparation",
      executionId: input.job.id,
      preparationCommitment,
    });
    await transaction.insert(directPrivacyPreparations).values({
      executionId: input.job.id,
      accountId: account.id,
      organizationId: account.organizationId,
      preparationCommitment,
      encryptedPreparation,
      state: "prepared",
      createdAt: now,
      updatedAt: now,
    });
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: account.organizationId,
      actorId: "system:direct-privacy-driver",
      action: "direct_privacy_preparation.stored",
      subjectId: input.job.id,
      metadata: { preparationCommitment, pinnedBlock: preparation.pinnedBlock.number },
    });
    return { preparationCommitment };
  });
}

export async function loadDirectPrivacyPreparation(input: {
  executionId: string;
  requestCommitment: string;
  preparationCommitment: string;
}): Promise<{
  preparation: DirectPrivacyPreparation;
  account: typeof directPrivacyAccounts.$inferSelect;
  state: string;
}> {
  if (!COMMITMENT_PATTERN.test(input.preparationCommitment)) {
    throw new Error("DIRECT_PREPARATION_COMMITMENT_INVALID");
  }
  const [joined] = await getDatabase().select({
    row: directPrivacyPreparations,
    account: directPrivacyAccounts,
    treasury: directPrivacyTreasuries,
  }).from(directPrivacyPreparations).innerJoin(
    directPrivacyAccounts,
    eq(directPrivacyAccounts.id, directPrivacyPreparations.accountId),
  ).innerJoin(
    directPrivacyTreasuries,
    eq(directPrivacyTreasuries.policyAccountAddress, directPrivacyAccounts.treasuryAddress),
  ).where(and(
    eq(directPrivacyPreparations.executionId, input.executionId),
    eq(directPrivacyPreparations.preparationCommitment, input.preparationCommitment),
  )).limit(1);
  if (
    !joined
    || joined.row.state === "abandoned"
    || joined.account.revokedAt
    || joined.treasury.organizationId !== joined.account.organizationId
    || joined.treasury.activeAccountId !== joined.account.id
    || joined.treasury.activeExecutionId !== input.executionId
  ) throw new Error("DIRECT_PREPARATION_NOT_FOUND");
  const preparation = decryptPreparation(joined.row, joined.account);
  if (
    preparation.requestCommitment !== input.requestCommitment
    || commitDirectPrivacyPreparation(preparation) !== input.preparationCommitment
  ) throw new Error("DIRECT_PREPARATION_TAMPERED");
  return { preparation, account: joined.account, state: joined.row.state };
}

/** Recovers the exact encrypted, already-simulated preparation after a worker restart. */
export async function findDirectPrivacyPreparation(
  job: LeasedAgentExecution,
): Promise<{
  preparation: DirectPrivacyPreparation;
  accountId: string;
  preparationCommitment: `0x${string}`;
} | null> {
  const [row] = await getDatabase().select({
    accountId: directPrivacyPreparations.accountId,
    organizationId: directPrivacyPreparations.organizationId,
    preparationCommitment: directPrivacyPreparations.preparationCommitment,
  }).from(directPrivacyPreparations).where(
    eq(directPrivacyPreparations.executionId, job.id),
  ).limit(1);
  if (!row) return null;
  if (
    row.organizationId !== job.organizationId
    || !COMMITMENT_PATTERN.test(row.preparationCommitment)
  ) throw new Error("DIRECT_PREPARATION_REPLAY_CONFLICT");
  const loaded = await loadDirectPrivacyPreparation({
    executionId: job.id,
    requestCommitment: job.requestCommitment,
    preparationCommitment: row.preparationCommitment,
  });
  if (
    loaded.account.id !== row.accountId
    || loaded.account.capabilityId !== job.capabilityId
  ) throw new Error("DIRECT_PREPARATION_REPLAY_CONFLICT");
  return {
    preparation: loaded.preparation,
    accountId: row.accountId,
    preparationCommitment: row.preparationCommitment as `0x${string}`,
  };
}

export async function markDirectPrivacyPreparationSigned(
  executionId: string,
  preparationCommitment: string,
  now = new Date(),
): Promise<void> {
  const [updated] = await getDatabase().update(directPrivacyPreparations).set({
    state: "signed",
    updatedAt: now,
  }).where(and(
    eq(directPrivacyPreparations.executionId, executionId),
    eq(directPrivacyPreparations.preparationCommitment, preparationCommitment),
    eq(directPrivacyPreparations.state, "prepared"),
  )).returning();
  if (!updated) {
    const [current] = await getDatabase().select().from(directPrivacyPreparations).where(and(
      eq(directPrivacyPreparations.executionId, executionId),
      eq(directPrivacyPreparations.preparationCommitment, preparationCommitment),
    )).limit(1);
    if (!current || current.state !== "signed") throw new Error("DIRECT_PREPARATION_STATE_INVALID");
  }
}

export async function abandonDirectPrivacyPreparation(input: {
  executionId: string;
  preparationCommitment: string;
  now?: Date;
}): Promise<void> {
  const now = input.now ?? new Date();
  await getDatabase().transaction(async (transaction) => {
    const [row] = await transaction.select().from(directPrivacyPreparations).where(and(
      eq(directPrivacyPreparations.executionId, input.executionId),
      eq(directPrivacyPreparations.preparationCommitment, input.preparationCommitment),
    )).limit(1).for("update");
    if (!row || row.state === "abandoned") return;
    const [submission] = await transaction.select({ executionId: directPrivacySubmissions.executionId })
      .from(directPrivacySubmissions)
      .where(eq(directPrivacySubmissions.executionId, input.executionId)).limit(1);
    if (submission || row.state !== "prepared") {
      throw new Error("DIRECT_PREPARATION_ALREADY_SIGNED");
    }
    const [account] = await transaction.select().from(directPrivacyAccounts).where(
      eq(directPrivacyAccounts.id, row.accountId),
    ).limit(1);
    await transaction.update(directPrivacyPreparations).set({ state: "abandoned", updatedAt: now })
      .where(eq(directPrivacyPreparations.executionId, input.executionId));
    if (account) {
      await transaction.update(directPrivacyTreasuries).set({
        activeExecutionId: null,
        activeAccountId: null,
        activeLeaseExpiresAt: null,
        updatedAt: now,
      }).where(and(
        eq(directPrivacyTreasuries.policyAccountAddress, account.treasuryAddress),
        eq(directPrivacyTreasuries.activeAccountId, account.id),
        eq(directPrivacyTreasuries.activeExecutionId, input.executionId),
      ));
    }
  });
}
