import "server-only";

import { and, asc, eq, isNull, lte, sql } from "drizzle-orm";
import { assertOperationalMetadataSafe } from "@/lib/domain/privacy";
import {
  obligationScheduleRegistrationSchema,
  type ObligationScheduleRegistration,
} from "@/lib/domain/obligation-schedule";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole, requireOrganizationRoleWith } from "./repository";
import { auditEvents, obligationSchedules, vaultRecords } from "./schema";

function scheduleIdentity(schedule: ObligationScheduleRegistration): string {
  return `${schedule.agreementId}:${schedule.agreementRevision}`;
}

function sameInstant(left: Date, right: string): boolean {
  return left.getTime() === new Date(right).getTime();
}

export async function registerObligationSchedules(input: {
  organizationId: string;
  schedules: readonly ObligationScheduleRegistration[];
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  if (input.schedules.length < 1 || input.schedules.length > 100) {
    throw new ApiError(400, "An obligation schedule batch must contain 1–100 entries.", "SCHEDULE_BATCH_SIZE_INVALID");
  }
  const schedules = input.schedules.map((schedule) => obligationScheduleRegistrationSchema.parse(schedule));
  const identities = schedules.map(scheduleIdentity);
  if (new Set(identities).size !== identities.length) {
    throw new ApiError(400, "An obligation schedule batch contains duplicate revisions.", "SCHEDULE_BATCH_DUPLICATE");
  }
  const now = input.now ?? new Date();
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin", "operator"]);
    const results = [];
    for (const schedule of [...schedules].sort((left, right) => scheduleIdentity(left).localeCompare(scheduleIdentity(right)))) {
      // A transaction-scoped lock makes concurrent browser tabs deterministic,
      // including the first registration where no row exists to lock yet.
      await transaction.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`${input.organizationId}:${schedule.agreementId}`}, 0))`);

      const [vaultRevision] = await transaction
        .select({ id: vaultRecords.id })
        .from(vaultRecords)
        .where(and(
          eq(vaultRecords.organizationId, input.organizationId),
          eq(vaultRecords.id, schedule.vaultRecordId),
          eq(vaultRecords.revision, schedule.agreementRevision),
          eq(vaultRecords.recordType, "pay-agreement"),
          isNull(vaultRecords.supersededAt),
        ))
        .limit(1);
      if (!vaultRevision) {
        throw new ApiError(
          409,
          "The schedule must reference the current encrypted pay-agreement revision.",
          "SCHEDULE_AGREEMENT_REVISION_STALE",
        );
      }

      const [existing] = await transaction
        .select()
        .from(obligationSchedules)
        .where(and(
          eq(obligationSchedules.organizationId, input.organizationId),
          eq(obligationSchedules.agreementId, schedule.agreementId),
          eq(obligationSchedules.agreementRevision, schedule.agreementRevision),
        ))
        .limit(1);
      if (existing) {
        if (
          existing.scheduleCommitment.toLowerCase() !== schedule.scheduleCommitment.toLowerCase()
          || !sameInstant(existing.dueAt, schedule.dueAt)
        ) {
          throw new ApiError(
            409,
            "This agreement revision already has different scheduling metadata.",
            "SCHEDULE_REVISION_CONFLICT",
          );
        }
        results.push({
          agreementId: existing.agreementId,
          agreementRevision: existing.agreementRevision,
          scheduleCommitment: existing.scheduleCommitment,
          dueAt: existing.dueAt.toISOString(),
          materializedAt: existing.materializedAt?.toISOString() ?? null,
          replayed: true,
        });
        continue;
      }

      await transaction
        .update(obligationSchedules)
        .set({ state: "superseded", updatedAt: now })
        .where(and(
          eq(obligationSchedules.organizationId, input.organizationId),
          eq(obligationSchedules.agreementId, schedule.agreementId),
          eq(obligationSchedules.state, "active"),
        ));
      const dueAt = new Date(schedule.dueAt);
      const [stored] = await transaction
        .insert(obligationSchedules)
        .values({
          organizationId: input.organizationId,
          agreementId: schedule.agreementId,
          agreementRevision: schedule.agreementRevision,
          scheduleCommitment: schedule.scheduleCommitment.toLowerCase(),
          dueAt,
          materializedAt: dueAt <= now ? now : null,
          createdBy: input.principal.principalId,
          updatedAt: now,
        })
        .returning();
      const metadata = {
        agreementRevision: stored.agreementRevision,
        scheduleCommitment: stored.scheduleCommitment,
        dueAt: stored.dueAt.toISOString(),
        materializedAt: stored.materializedAt?.toISOString() ?? null,
      };
      assertOperationalMetadataSafe(metadata);
      await transaction.insert(auditEvents).values({
        id: generateUuidV7(),
        organizationId: input.organizationId,
        actorId: input.principal.principalId,
        action: "obligation_schedule.registered",
        subjectId: schedule.agreementId,
        metadata,
      });
      results.push({
        agreementId: stored.agreementId,
        agreementRevision: stored.agreementRevision,
        scheduleCommitment: stored.scheduleCommitment,
        dueAt: stored.dueAt.toISOString(),
        materializedAt: stored.materializedAt?.toISOString() ?? null,
        replayed: false,
      });
    }
    return results;
  });
}

export async function materializeDueObligationSchedules(input: { now?: Date; limit?: number } = {}) {
  const now = input.now ?? new Date();
  const limit = Math.max(1, Math.min(input.limit ?? 100, 500));
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const candidates = await transaction
      .select({
        organizationId: obligationSchedules.organizationId,
        agreementId: obligationSchedules.agreementId,
        agreementRevision: obligationSchedules.agreementRevision,
      })
      .from(obligationSchedules)
      .where(and(
        eq(obligationSchedules.state, "active"),
        isNull(obligationSchedules.materializedAt),
        lte(obligationSchedules.dueAt, now),
      ))
      .orderBy(asc(obligationSchedules.dueAt))
      .limit(limit)
      .for("update", { skipLocked: true });
    if (candidates.length === 0) return { materialized: 0, hasMore: false };
    for (const candidate of candidates) {
      await transaction
        .update(obligationSchedules)
        .set({ materializedAt: now, updatedAt: now })
        .where(and(
          eq(obligationSchedules.organizationId, candidate.organizationId),
          eq(obligationSchedules.agreementId, candidate.agreementId),
          eq(obligationSchedules.agreementRevision, candidate.agreementRevision),
          eq(obligationSchedules.state, "active"),
          isNull(obligationSchedules.materializedAt),
        ));
    }
    return { materialized: candidates.length, hasMore: candidates.length === limit };
  });
}

export async function listDueObligationSchedules(input: {
  organizationId: string;
  principal: AuthenticatedPrincipal;
  limit?: number;
}) {
  await requireOrganizationRole(input.organizationId, input.principal, ["admin", "operator", "reviewer"]);
  const limit = Math.max(1, Math.min(input.limit ?? 100, 500));
  const rows = await getDatabase()
    .select({
      agreementId: obligationSchedules.agreementId,
      agreementRevision: obligationSchedules.agreementRevision,
      scheduleCommitment: obligationSchedules.scheduleCommitment,
      dueAt: obligationSchedules.dueAt,
      materializedAt: obligationSchedules.materializedAt,
    })
    .from(obligationSchedules)
    .where(and(
      eq(obligationSchedules.organizationId, input.organizationId),
      eq(obligationSchedules.state, "active"),
      lte(obligationSchedules.dueAt, new Date()),
      sql`${obligationSchedules.materializedAt} is not null`,
    ))
    .orderBy(asc(obligationSchedules.dueAt))
    .limit(limit);
  return rows.map((row) => ({
    agreementId: row.agreementId,
    agreementRevision: row.agreementRevision,
    scheduleCommitment: row.scheduleCommitment,
    dueAt: row.dueAt.toISOString(),
    materializedAt: row.materializedAt!.toISOString(),
  }));
}
