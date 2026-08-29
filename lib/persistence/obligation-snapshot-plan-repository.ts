import "server-only";

import { and, desc, eq, isNull } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  obligationSnapshotPlanCreateSchema,
  type ObligationClaimAccessGrantCreate,
  type ObligationSnapshotPlanCreate,
} from "@/lib/domain/obligation-snapshot-plan";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase, type Database } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  auditEvents,
  obligationClaimAccessGrants,
  obligationSnapshotPlans,
  organizationMembers,
  organizations,
  payrollRuns,
  vaultRecords,
} from "./schema";

const MINIMUM_REGISTRATION_HEADROOM_SECONDS = 120n;
const MAXIMUM_GRACE_SECONDS = 30n * 24n * 60n * 60n;
const MAXIMUM_CLAIM_WINDOW_SECONDS = 366n * 24n * 60n * 60n;
const MAXIMUM_JAVASCRIPT_DATE_SECONDS = 253_402_300_799n;

function canonicalTransactionHash(value: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
    throw new ApiError(400, "Snapshot registration transaction hash is invalid.", "TRANSACTION_HASH_INVALID");
  }
  return `0x${BigInt(value).toString(16)}`;
}

function timestamp(value: string, label: string): Date {
  const seconds = BigInt(value);
  if (seconds > MAXIMUM_JAVASCRIPT_DATE_SECONDS) {
    throw new ApiError(400, `${label} is outside PAYO's supported date range.`, "SNAPSHOT_WINDOW_INVALID");
  }
  return new Date(Number(seconds) * 1_000);
}

function publicPlan<T extends typeof obligationSnapshotPlans.$inferSelect>(plan: T, envelope?: unknown) {
  return {
    id: plan.id,
    runId: plan.runId,
    organizationId: plan.organizationId,
    cycleId: plan.cycleId,
    revision: plan.revision,
    ownerAddress: plan.ownerAddress,
    agreementRoot: plan.agreementRoot,
    claimRoot: plan.claimRoot,
    policyRoot: plan.policyRoot,
    runNullifier: plan.runNullifier,
    snapshotFact: plan.snapshotFact,
    dueAt: plan.dueAt.toISOString(),
    graceEndsAt: plan.graceEndsAt.toISOString(),
    claimEndsAt: plan.claimEndsAt.toISOString(),
    state: plan.state,
    registrationTransactionHash: plan.registrationTransactionHash,
    registeredAt: plan.registeredAt?.toISOString() ?? null,
    consumedAt: plan.consumedAt?.toISOString() ?? null,
    createdAt: plan.createdAt.toISOString(),
    updatedAt: plan.updatedAt.toISOString(),
    ...(envelope ? { envelope } : {}),
  };
}

function immutableFingerprint(input: ObligationSnapshotPlanCreate) {
  return hashCanonicalJson({
    runId: input.runId,
    organizationId: input.organizationId,
    cycleId: input.cycleId,
    revision: input.payrollRevision,
    ownerAddress: input.ownerAddress,
    snapshot: input.snapshot,
    snapshotCommitment: input.snapshotCommitment,
  });
}

function storedFingerprint(plan: typeof obligationSnapshotPlans.$inferSelect) {
  return hashCanonicalJson({
    runId: plan.runId,
    organizationId: plan.organizationId,
    cycleId: plan.cycleId,
    revision: plan.revision,
    ownerAddress: plan.ownerAddress,
    snapshot: {
      schemaVersion: 2,
      runNullifier: plan.runNullifier,
      baseAgreementRoot: plan.agreementRoot,
      obligationRoot: plan.claimRoot,
      policyRoot: plan.policyRoot,
      ownerAddress: plan.ownerAddress,
      dueAt: String(Math.floor(plan.dueAt.getTime() / 1_000)),
      graceEndsAt: String(Math.floor(plan.graceEndsAt.getTime() / 1_000)),
      claimEndsAt: String(Math.floor(plan.claimEndsAt.getTime() / 1_000)),
      availabilityCommitment: plan.claimRoot,
    },
    snapshotCommitment: plan.snapshotFact,
  });
}

async function ensureSnapshotRunReservation(
  transaction: Pick<Database, "select" | "insert">,
  plan: typeof obligationSnapshotPlans.$inferSelect,
) {
  const [existing] = await transaction.select().from(payrollRuns)
    .where(eq(payrollRuns.id, plan.runId)).limit(1).for("update");
  if (existing) {
    const matches = existing.organizationId === plan.organizationId
      && existing.cycleId === plan.cycleId
      && existing.revision === plan.revision
      && existing.dueAt.getTime() === plan.dueAt.getTime()
      && existing.obligationSnapshotPlanId === plan.id
      && BigInt(existing.agreementRoot ?? "0x0") === BigInt(plan.agreementRoot)
      && BigInt(existing.policyRoot ?? "0x0") === BigInt(plan.policyRoot)
      && BigInt(existing.runNullifier ?? "0x0") === BigInt(plan.runNullifier);
    if (!matches) {
      throw new ApiError(409, "The snapshot run identifier is already bound to different immutable payroll facts.", "SNAPSHOT_RUN_RESERVATION_CONFLICT");
    }
    return existing;
  }
  const [reserved] = await transaction.insert(payrollRuns).values({
    id: plan.runId,
    organizationId: plan.organizationId,
    cycleId: plan.cycleId,
    revision: plan.revision,
    dueAt: plan.dueAt,
    agreementRoot: plan.agreementRoot,
    policyRoot: plan.policyRoot,
    runNullifier: plan.runNullifier,
    obligationSnapshotPlanId: plan.id,
  }).returning();
  return reserved;
}

async function storeSnapshotClaimAccessGrants(
  transaction: Pick<Database, "select" | "insert">,
  plan: typeof obligationSnapshotPlans.$inferSelect,
  grants: readonly ObligationClaimAccessGrantCreate[],
  createdBy: string,
  allowCreate: boolean,
) {
  for (const grant of grants) {
    const envelopeHash = hashCanonicalJson(grant.envelope);
    const [existing] = await transaction.select().from(obligationClaimAccessGrants)
      .where(eq(obligationClaimAccessGrants.id, grant.id)).limit(1).for("update");
    const [vault] = await transaction.select({
      envelopeHash: vaultRecords.envelopeHash,
      recordType: vaultRecords.recordType,
      revision: vaultRecords.revision,
    }).from(vaultRecords).where(and(
      eq(vaultRecords.organizationId, plan.organizationId),
      eq(vaultRecords.id, grant.id),
      isNull(vaultRecords.supersededAt),
    )).limit(1).for("update");
    if (existing || vault) {
      const matches = existing?.snapshotPlanId === plan.id
        && existing.organizationId === plan.organizationId
        && existing.runId === plan.runId
        && existing.claimantPrincipalId === grant.claimantPrincipalId
        && existing.revokedAt === null
        && vault?.recordType === "obligation-claim-access"
        && vault.revision === 1
        && vault.envelopeHash === envelopeHash;
      if (!matches) {
        throw new ApiError(409, "A claim-access grant already contains different encrypted bindings.", "CLAIM_ACCESS_CONFLICT");
      }
      continue;
    }
    if (!allowCreate) {
      throw new ApiError(409, "The stored snapshot is missing its worker claim-access packet.", "CLAIM_ACCESS_MISSING");
    }
    await transaction.insert(vaultRecords).values({
      id: grant.id,
      organizationId: plan.organizationId,
      recordType: "obligation-claim-access",
      revision: 1,
      ciphertext: grant.envelope.ciphertext,
      envelope: grant.envelope,
      envelopeHash,
      createdBy,
    });
    await transaction.insert(obligationClaimAccessGrants).values({
      id: grant.id,
      snapshotPlanId: plan.id,
      organizationId: plan.organizationId,
      runId: plan.runId,
      claimantPrincipalId: grant.claimantPrincipalId,
    });
  }
}

export async function createObligationSnapshotPlan(input: {
  plan: ObligationSnapshotPlanCreate;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const plan = obligationSnapshotPlanCreateSchema.parse(input.plan);
  if (
    !input.principal.walletAddress
    || BigInt(input.principal.walletAddress) !== BigInt(plan.ownerAddress)
  ) {
    throw new ApiError(
      403,
      "The connected Ready account must own the snapshot it registers.",
      "SNAPSHOT_OWNER_MISMATCH",
    );
  }
  const now = input.now ?? new Date();
  const nowSeconds = BigInt(Math.floor(now.getTime() / 1_000));
  const dueSeconds = BigInt(plan.snapshot.dueAt);
  const graceSeconds = BigInt(plan.snapshot.graceEndsAt);
  const claimSeconds = BigInt(plan.snapshot.claimEndsAt);
  if (dueSeconds <= nowSeconds + MINIMUM_REGISTRATION_HEADROOM_SECONDS) {
    throw new ApiError(
      409,
      "Prepare the obligation snapshot at least two minutes before payday.",
      "SNAPSHOT_REGISTRATION_TOO_LATE",
    );
  }
  if (graceSeconds - dueSeconds > MAXIMUM_GRACE_SECONDS || claimSeconds - dueSeconds > MAXIMUM_CLAIM_WINDOW_SECONDS) {
    throw new ApiError(400, "Snapshot dispute windows exceed PAYO's production bounds.", "SNAPSHOT_WINDOW_INVALID");
  }
  const dueAt = timestamp(plan.snapshot.dueAt, "Snapshot payday");
  const graceEndsAt = timestamp(plan.snapshot.graceEndsAt, "Snapshot grace deadline");
  const claimEndsAt = timestamp(plan.snapshot.claimEndsAt, "Snapshot claim deadline");
  const envelopeHash = hashCanonicalJson(plan.envelope);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [membership] = await transaction.select({ role: organizationMembers.role })
      .from(organizationMembers).where(and(
        eq(organizationMembers.organizationId, plan.organizationId),
        eq(organizationMembers.principalId, input.principal.principalId),
        isNull(organizationMembers.revokedAt),
      )).limit(1).for("update");
    if (!membership || !["admin", "operator"].includes(membership.role)) {
      throw new ApiError(403, "You cannot prepare snapshots for this organization.", "ORG_FORBIDDEN");
    }
    const [organization] = await transaction.select({ recoveryState: organizations.recoveryState })
      .from(organizations).where(eq(organizations.id, plan.organizationId)).limit(1).for("update");
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    if (organization.recoveryState === "required") {
      throw new ApiError(409, "Configure vault recovery before reserving a payroll snapshot.", "VAULT_RECOVERY_REQUIRED");
    }
    const [existing] = await transaction.select().from(obligationSnapshotPlans)
      .where(eq(obligationSnapshotPlans.id, plan.id)).limit(1).for("update");
    if (existing) {
      const [vault] = await transaction.select({ envelopeHash: vaultRecords.envelopeHash })
        .from(vaultRecords).where(and(
          eq(vaultRecords.organizationId, plan.organizationId),
          eq(vaultRecords.id, plan.id),
          eq(vaultRecords.recordType, "obligation-snapshot-plan"),
          eq(vaultRecords.revision, 1),
        )).limit(1);
      if (storedFingerprint(existing) === immutableFingerprint(plan) && vault?.envelopeHash === envelopeHash) {
        await ensureSnapshotRunReservation(transaction, existing);
        await storeSnapshotClaimAccessGrants(
          transaction, existing, plan.claimAccessGrants, input.principal.principalId, false,
        );
        return { ...publicPlan(existing), replayed: true };
      }
      throw new ApiError(409, "Snapshot-plan ID already contains different commitments.", "SNAPSHOT_PLAN_CONFLICT");
    }
    const [cycleReservation] = await transaction.select({ id: obligationSnapshotPlans.id })
      .from(obligationSnapshotPlans).where(and(
        eq(obligationSnapshotPlans.organizationId, plan.organizationId),
        eq(obligationSnapshotPlans.cycleId, plan.cycleId),
        eq(obligationSnapshotPlans.revision, plan.payrollRevision),
      )).limit(1).for("update");
    if (cycleReservation) {
      throw new ApiError(409, "This payroll cycle revision already has another snapshot.", "SNAPSHOT_REVISION_CONFLICT");
    }
    await transaction.insert(vaultRecords).values({
      id: plan.id,
      organizationId: plan.organizationId,
      recordType: "obligation-snapshot-plan",
      revision: 1,
      ciphertext: plan.envelope.ciphertext,
      envelope: plan.envelope,
      envelopeHash,
      createdBy: input.principal.principalId,
    });
    const [created] = await transaction.insert(obligationSnapshotPlans).values({
      id: plan.id,
      runId: plan.runId,
      organizationId: plan.organizationId,
      cycleId: plan.cycleId,
      revision: plan.payrollRevision,
      ownerAddress: plan.ownerAddress,
      agreementRoot: plan.snapshot.baseAgreementRoot,
      claimRoot: plan.snapshot.obligationRoot,
      policyRoot: plan.snapshot.policyRoot,
      runNullifier: plan.snapshot.runNullifier,
      snapshotFact: plan.snapshotCommitment,
      dueAt,
      graceEndsAt,
      claimEndsAt,
      createdBy: input.principal.principalId,
      createdAt: now,
      updatedAt: now,
    }).returning();
    await ensureSnapshotRunReservation(transaction, created);
    await storeSnapshotClaimAccessGrants(
      transaction, created, plan.claimAccessGrants, input.principal.principalId, true,
    );
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: plan.organizationId,
      actorId: input.principal.principalId,
      action: "obligation_snapshot.prepared",
      subjectId: plan.id,
      metadata: {
        runId: plan.runId,
        cycleId: plan.cycleId,
        revision: plan.payrollRevision,
        runNullifier: plan.snapshot.runNullifier,
        snapshotFact: plan.snapshotCommitment,
        claimAccessCount: plan.claimAccessGrants.length,
      },
    });
    return { ...publicPlan(created), replayed: false };
  });
}

export async function recordObligationSnapshotSubmission(input: {
  planId: string;
  transactionHash: string;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const transactionHash = canonicalTransactionHash(input.transactionHash);
  const now = input.now ?? new Date();
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [plan] = await transaction.select().from(obligationSnapshotPlans)
      .where(eq(obligationSnapshotPlans.id, input.planId)).limit(1).for("update");
    if (!plan) throw new ApiError(404, "Snapshot plan not found.", "SNAPSHOT_PLAN_NOT_FOUND");
    const [membership] = await transaction.select({ role: organizationMembers.role })
      .from(organizationMembers).where(and(
        eq(organizationMembers.organizationId, plan.organizationId),
        eq(organizationMembers.principalId, input.principal.principalId),
        isNull(organizationMembers.revokedAt),
      )).limit(1);
    if (!membership || !["admin", "operator"].includes(membership.role)) {
      throw new ApiError(403, "You cannot record this snapshot registration.", "ORG_FORBIDDEN");
    }
    if (["cancelled", "expired"].includes(plan.state)) {
      throw new ApiError(409, "This snapshot plan can no longer be submitted.", "SNAPSHOT_PLAN_TERMINAL");
    }
    if (plan.registrationTransactionHash && BigInt(plan.registrationTransactionHash) !== BigInt(transactionHash)) {
      throw new ApiError(409, "This snapshot already references another transaction.", "SNAPSHOT_TRANSACTION_CONFLICT");
    }
    if (plan.state === "consumed" || plan.state === "registered" || plan.state === "submitted") {
      return { ...publicPlan(plan), replayed: true };
    }
    const [updated] = await transaction.update(obligationSnapshotPlans).set({
      state: "submitted",
      registrationTransactionHash: transactionHash,
      updatedAt: now,
    }).where(and(
      eq(obligationSnapshotPlans.id, plan.id),
      eq(obligationSnapshotPlans.state, "prepared"),
    )).returning();
    if (!updated) throw new ApiError(409, "Snapshot plan changed while recording submission.", "SNAPSHOT_STATE_CONFLICT");
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: plan.organizationId,
      actorId: input.principal.principalId,
      action: "obligation_snapshot.submitted",
      subjectId: plan.id,
      metadata: { runId: plan.runId, transactionHash },
    });
    return { ...publicPlan(updated), replayed: false };
  });
}

/** Called only after a pinned RPC read matches every stored snapshot field. */
export async function markObligationSnapshotRegistered(input: {
  planId: string;
  transactionHash?: string | null;
  registeredAt: Date;
}) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [plan] = await transaction.select().from(obligationSnapshotPlans)
      .where(eq(obligationSnapshotPlans.id, input.planId)).limit(1).for("update");
    if (!plan) throw new ApiError(404, "Snapshot plan not found.", "SNAPSHOT_PLAN_NOT_FOUND");
    if (plan.state === "cancelled" || plan.state === "expired") {
      throw new ApiError(409, "A terminal snapshot plan cannot be registered.", "SNAPSHOT_PLAN_TERMINAL");
    }
    if (plan.state === "registered" || plan.state === "consumed") return { ...publicPlan(plan), replayed: true };
    const transactionHash = input.transactionHash
      ? canonicalTransactionHash(input.transactionHash)
      : plan.registrationTransactionHash;
    if (
      plan.registrationTransactionHash
      && transactionHash
      && BigInt(plan.registrationTransactionHash) !== BigInt(transactionHash)
    ) throw new ApiError(409, "Snapshot registration transaction changed.", "SNAPSHOT_TRANSACTION_CONFLICT");
    const [updated] = await transaction.update(obligationSnapshotPlans).set({
      state: "registered",
      registrationTransactionHash: transactionHash,
      registeredAt: input.registeredAt,
      updatedAt: input.registeredAt,
    }).where(eq(obligationSnapshotPlans.id, plan.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: plan.organizationId,
      actorId: "system:snapshot-reconciler",
      action: "obligation_snapshot.registered",
      subjectId: plan.id,
      metadata: { runId: plan.runId, transactionHash },
    });
    return { ...publicPlan(updated), replayed: false };
  });
}

export async function getObligationSnapshotPlan(planId: string, principal: AuthenticatedPrincipal) {
  const database = getDatabase();
  const [plan] = await database.select().from(obligationSnapshotPlans)
    .where(eq(obligationSnapshotPlans.id, planId)).limit(1);
  if (!plan) throw new ApiError(404, "Snapshot plan not found.", "SNAPSHOT_PLAN_NOT_FOUND");
  await requireOrganizationRole(plan.organizationId, principal, ["admin", "operator", "reviewer"]);
  const [vault] = await database.select({ envelope: vaultRecords.envelope }).from(vaultRecords)
    .where(and(
      eq(vaultRecords.organizationId, plan.organizationId),
      eq(vaultRecords.id, plan.id),
      eq(vaultRecords.recordType, "obligation-snapshot-plan"),
      isNull(vaultRecords.supersededAt),
    )).orderBy(desc(vaultRecords.revision)).limit(1);
  if (!vault) throw new ApiError(500, "Encrypted snapshot plan is missing.", "SNAPSHOT_PLAN_VAULT_MISSING");
  return publicPlan(plan, vault.envelope);
}

export async function findRegisteredObligationSnapshotPlan(input: {
  organizationId: string;
  cycleId: string;
  agreementRoot: string;
  principal: AuthenticatedPrincipal;
}) {
  await requireOrganizationRole(input.organizationId, input.principal, ["admin", "operator", "reviewer"]);
  const database = getDatabase();
  const [plan] = await database.select().from(obligationSnapshotPlans).where(and(
    eq(obligationSnapshotPlans.organizationId, input.organizationId),
    eq(obligationSnapshotPlans.cycleId, input.cycleId),
    eq(obligationSnapshotPlans.agreementRoot, input.agreementRoot),
    eq(obligationSnapshotPlans.state, "registered"),
  )).orderBy(desc(obligationSnapshotPlans.revision)).limit(1);
  if (!plan) throw new ApiError(
    404,
    "No registered pre-payday snapshot matches this exact obligation batch.",
    "SNAPSHOT_PLAN_NOT_FOUND",
  );
  return getObligationSnapshotPlan(plan.id, input.principal);
}

export async function listObligationClaimAccessGrants(principal: AuthenticatedPrincipal) {
  const rows = await getDatabase().select({
    id: obligationClaimAccessGrants.id,
    claimantPrincipalId: obligationClaimAccessGrants.claimantPrincipalId,
    revokedAt: obligationClaimAccessGrants.revokedAt,
    envelope: vaultRecords.envelope,
    plan: obligationSnapshotPlans,
  }).from(obligationClaimAccessGrants)
    .innerJoin(obligationSnapshotPlans, eq(
      obligationClaimAccessGrants.snapshotPlanId,
      obligationSnapshotPlans.id,
    ))
    .innerJoin(vaultRecords, and(
      eq(vaultRecords.organizationId, obligationClaimAccessGrants.organizationId),
      eq(vaultRecords.id, obligationClaimAccessGrants.id),
      eq(vaultRecords.recordType, "obligation-claim-access"),
      isNull(vaultRecords.supersededAt),
    ))
    .where(and(
      eq(obligationClaimAccessGrants.claimantPrincipalId, principal.principalId),
      isNull(obligationClaimAccessGrants.revokedAt),
    ))
    .orderBy(desc(obligationSnapshotPlans.dueAt), desc(obligationClaimAccessGrants.createdAt));
  return rows.map(({ id, claimantPrincipalId, revokedAt, envelope, plan }) => ({
    id,
    claimantPrincipalId,
    revokedAt: revokedAt?.toISOString() ?? null,
    plan: publicPlan(plan),
    envelope,
  }));
}

export async function getObligationClaimAccessGrant(
  grantId: string,
  principal: AuthenticatedPrincipal,
) {
  const grants = await getDatabase().select({
    id: obligationClaimAccessGrants.id,
    claimantPrincipalId: obligationClaimAccessGrants.claimantPrincipalId,
    organizationId: obligationClaimAccessGrants.organizationId,
    runId: obligationClaimAccessGrants.runId,
    snapshotPlanId: obligationClaimAccessGrants.snapshotPlanId,
    revokedAt: obligationClaimAccessGrants.revokedAt,
    envelope: vaultRecords.envelope,
  }).from(obligationClaimAccessGrants)
    .innerJoin(vaultRecords, and(
      eq(vaultRecords.organizationId, obligationClaimAccessGrants.organizationId),
      eq(vaultRecords.id, obligationClaimAccessGrants.id),
      eq(vaultRecords.recordType, "obligation-claim-access"),
      isNull(vaultRecords.supersededAt),
    ))
    .where(and(
      eq(obligationClaimAccessGrants.id, grantId),
      eq(obligationClaimAccessGrants.claimantPrincipalId, principal.principalId),
      isNull(obligationClaimAccessGrants.revokedAt),
    ))
    .limit(1);
  const [grant] = grants;
  if (!grant) throw new ApiError(404, "Worker claim access was not found.", "CLAIM_ACCESS_NOT_FOUND");
  return grant;
}

export async function listObligationSnapshotPlans(organizationId: string, principal: AuthenticatedPrincipal) {
  await requireOrganizationRole(organizationId, principal, ["admin", "operator", "reviewer"]);
  const plans = await getDatabase().select().from(obligationSnapshotPlans)
    .where(eq(obligationSnapshotPlans.organizationId, organizationId))
    .orderBy(desc(obligationSnapshotPlans.dueAt), desc(obligationSnapshotPlans.revision));
  return plans.map((plan) => publicPlan(plan));
}
