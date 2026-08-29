import "server-only";

import { and, desc, eq, isNull, or } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  employerStatementCreateSchema,
  type EmployerStatementCreate,
} from "@/lib/domain/employer-statement";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  auditEvents,
  employerStatements,
  obligationClaimAccessGrants,
  obligationSnapshotPlans,
  organizationMembers,
  payrollStatementEvidenceGrants,
  vaultRecords,
} from "./schema";

const MAXIMUM_JAVASCRIPT_DATE_SECONDS = 253_402_300_799n;
const MAXIMUM_CLOCK_SKEW_SECONDS = 60n;

function canonicalTransactionHash(value: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
    throw new ApiError(
      400,
      "Statement registration transaction hash is invalid.",
      "TRANSACTION_HASH_INVALID",
    );
  }
  return "0x" + BigInt(value).toString(16);
}

function canonicalCommitment(value: string): string {
  return "0x" + BigInt(value).toString(16).padStart(64, "0");
}

function timestamp(value: string, label: string): Date {
  const seconds = BigInt(value);
  if (seconds > MAXIMUM_JAVASCRIPT_DATE_SECONDS) {
    throw new ApiError(
      400,
      label + " is outside PAYO's supported date range.",
      "STATEMENT_TIME_INVALID",
    );
  }
  return new Date(Number(seconds) * 1_000);
}

function publicStatement(
  statement: typeof employerStatements.$inferSelect,
  envelope?: unknown,
) {
  return {
    id: statement.id,
    snapshotPlanId: statement.snapshotPlanId,
    organizationId: statement.organizationId,
    runId: statement.runId,
    ownerAddress: statement.ownerAddress,
    statementFact: statement.statementFact,
    manifestRoot: statement.manifestRoot,
    fxRoot: statement.fxRoot,
    availabilityCommitment: statement.availabilityCommitment,
    observedAt: statement.observedAt.toISOString(),
    source: "employer_statement" as const,
    state: statement.state,
    registrationTransactionHash: statement.registrationTransactionHash,
    registeredAt: statement.registeredAt?.toISOString() ?? null,
    createdAt: statement.createdAt.toISOString(),
    updatedAt: statement.updatedAt.toISOString(),
    ...(envelope === undefined ? {} : { envelope }),
  };
}

type StoredEvidence = {
  id: string;
  claimAccessGrantId: string;
  claimantPrincipalId: string;
  envelopeHash: string;
};

function immutableFingerprint(input: {
  statement: EmployerStatementCreate;
  evidence: readonly StoredEvidence[];
  statementEnvelopeHash: string;
}) {
  const { statement } = input;
  return hashCanonicalJson({
    snapshotPlanId: statement.snapshotPlanId,
    organizationId: statement.organizationId,
    runId: statement.runId,
    ownerAddress: canonicalCommitment(statement.ownerAddress),
    statement: {
      ...statement.statement,
      runNullifier: canonicalCommitment(statement.statement.runNullifier),
      snapshotCommitment: canonicalCommitment(statement.statement.snapshotCommitment),
      manifestRoot: canonicalCommitment(statement.statement.manifestRoot),
      fxRoot: canonicalCommitment(statement.statement.fxRoot),
      availabilityCommitment: canonicalCommitment(statement.statement.availabilityCommitment),
      observedAt: BigInt(statement.statement.observedAt).toString(),
    },
    statementCommitment: canonicalCommitment(statement.statementCommitment),
    evidence: [...input.evidence].sort((left, right) => left.id.localeCompare(right.id)),
    statementEnvelopeHash: input.statementEnvelopeHash,
  });
}

function storedFingerprint(input: {
  statement: typeof employerStatements.$inferSelect;
  snapshot: typeof obligationSnapshotPlans.$inferSelect;
  evidence: readonly StoredEvidence[];
  statementEnvelopeHash: string;
}) {
  return hashCanonicalJson({
    snapshotPlanId: input.statement.snapshotPlanId,
    organizationId: input.statement.organizationId,
    runId: input.statement.runId,
    ownerAddress: canonicalCommitment(input.statement.ownerAddress),
    statement: {
      schemaVersion: 2,
      runNullifier: canonicalCommitment(input.snapshot.runNullifier),
      snapshotCommitment: canonicalCommitment(input.snapshot.snapshotFact),
      manifestRoot: canonicalCommitment(input.statement.manifestRoot),
      fxRoot: canonicalCommitment(input.statement.fxRoot),
      availabilityCommitment: canonicalCommitment(input.statement.availabilityCommitment),
      observedAt: String(Math.floor(input.statement.observedAt.getTime() / 1_000)),
      source: "employer_statement",
    },
    statementCommitment: canonicalCommitment(input.statement.statementFact),
    evidence: [...input.evidence].sort((left, right) => left.id.localeCompare(right.id)),
    statementEnvelopeHash: input.statementEnvelopeHash,
  });
}

export async function createEmployerStatement(input: {
  statement: EmployerStatementCreate;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const statement = employerStatementCreateSchema.parse(input.statement);
  if (
    !input.principal.walletAddress
    || BigInt(input.principal.walletAddress) !== BigInt(statement.ownerAddress)
  ) {
    throw new ApiError(
      403,
      "The connected Ready account must own the employer statement it registers.",
      "STATEMENT_OWNER_MISMATCH",
    );
  }
  const now = input.now ?? new Date();
  const observedAt = timestamp(statement.statement.observedAt, "Statement observation time");
  const nowSeconds = BigInt(Math.floor(now.getTime() / 1_000));
  if (BigInt(statement.statement.observedAt) > nowSeconds + MAXIMUM_CLOCK_SKEW_SECONDS) {
    throw new ApiError(
      409,
      "An employer statement cannot be observed in the future.",
      "STATEMENT_TIME_INVALID",
    );
  }
  if (
    BigInt(statement.statement.manifestRoot) === 0n
    || BigInt(statement.statement.availabilityCommitment) === 0n
  ) {
    throw new ApiError(
      400,
      "Employer statement availability commitments must be non-zero.",
      "STATEMENT_COMMITMENT_INVALID",
    );
  }

  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [membership] = await transaction.select({ role: organizationMembers.role })
      .from(organizationMembers).where(and(
        eq(organizationMembers.organizationId, statement.organizationId),
        eq(organizationMembers.principalId, input.principal.principalId),
        isNull(organizationMembers.revokedAt),
      )).limit(1).for("update");
    if (!membership || !["admin", "operator"].includes(membership.role)) {
      throw new ApiError(
        403,
        "You cannot register statements for this organization.",
        "ORG_FORBIDDEN",
      );
    }

    const [snapshot] = await transaction.select().from(obligationSnapshotPlans)
      .where(eq(obligationSnapshotPlans.id, statement.snapshotPlanId))
      .limit(1)
      .for("update");
    if (!snapshot) {
      throw new ApiError(404, "Obligation snapshot not found.", "SNAPSHOT_PLAN_NOT_FOUND");
    }
    if (
      snapshot.organizationId !== statement.organizationId
      || snapshot.runId !== statement.runId
      || BigInt(snapshot.ownerAddress) !== BigInt(statement.ownerAddress)
      || BigInt(snapshot.runNullifier) !== BigInt(statement.statement.runNullifier)
      || BigInt(snapshot.snapshotFact) !== BigInt(statement.statement.snapshotCommitment)
    ) {
      throw new ApiError(
        409,
        "Employer statement differs from its immutable snapshot.",
        "STATEMENT_SNAPSHOT_MISMATCH",
      );
    }
    if (!["registered", "consumed"].includes(snapshot.state)) {
      throw new ApiError(
        409,
        "Register the obligation snapshot before its employer statement.",
        "SNAPSHOT_NOT_REGISTERED",
      );
    }
    if (observedAt.getTime() < snapshot.dueAt.getTime()) {
      throw new ApiError(
        409,
        "An employer statement cannot precede the committed payday.",
        "STATEMENT_BEFORE_PAYDAY",
      );
    }

    const activeEmployers = await transaction.select({
      principalId: organizationMembers.principalId,
    }).from(organizationMembers).where(and(
      eq(organizationMembers.organizationId, statement.organizationId),
      isNull(organizationMembers.revokedAt),
      or(
        eq(organizationMembers.role, "admin"),
        eq(organizationMembers.role, "operator"),
      ),
    ));
    const employerIds = new Set(activeEmployers.map(({ principalId }) => principalId));
    const statementRecipients = statement.envelope.wrappedKeys.map(({ principalId }) => principalId);
    if (
      !statementRecipients.includes(input.principal.principalId)
      || statementRecipients.some((principalId) => !employerIds.has(principalId))
    ) {
      throw new ApiError(
        400,
        "The employer statement must be encrypted only to active employer administrators.",
        "STATEMENT_RECIPIENTS_INVALID",
      );
    }

    const activeAccess = await transaction.select()
      .from(obligationClaimAccessGrants)
      .where(and(
        eq(obligationClaimAccessGrants.snapshotPlanId, snapshot.id),
        isNull(obligationClaimAccessGrants.revokedAt),
      ))
      .orderBy(obligationClaimAccessGrants.id);
    const submittedAccess = new Map(
      statement.evidenceGrants.map((grant) => [grant.claimAccessGrantId, grant]),
    );
    if (
      activeAccess.length !== statement.evidenceGrants.length
      || activeAccess.some((access) => {
        const grant = submittedAccess.get(access.id);
        return !grant
          || grant.claimantPrincipalId !== access.claimantPrincipalId
          || access.organizationId !== statement.organizationId
          || access.runId !== statement.runId;
      })
    ) {
      throw new ApiError(
        409,
        "Statement evidence must cover every active worker in the immutable snapshot exactly once.",
        "STATEMENT_EVIDENCE_INCOMPLETE",
      );
    }

    const [existing] = await transaction.select().from(employerStatements)
      .where(eq(employerStatements.id, statement.id))
      .limit(1)
      .for("update");
    if (existing) {
      const [storedVault] = await transaction.select({
        envelopeHash: vaultRecords.envelopeHash,
      }).from(vaultRecords).where(and(
        eq(vaultRecords.organizationId, statement.organizationId),
        eq(vaultRecords.id, statement.id),
        eq(vaultRecords.recordType, "employer-statement-v2"),
        eq(vaultRecords.revision, 1),
        isNull(vaultRecords.supersededAt),
      )).limit(1);
      const storedEvidence = await transaction.select({
        id: payrollStatementEvidenceGrants.id,
        claimAccessGrantId: payrollStatementEvidenceGrants.claimAccessGrantId,
        claimantPrincipalId: payrollStatementEvidenceGrants.claimantPrincipalId,
        envelopeHash: vaultRecords.envelopeHash,
      }).from(payrollStatementEvidenceGrants).innerJoin(vaultRecords, and(
        eq(vaultRecords.organizationId, payrollStatementEvidenceGrants.organizationId),
        eq(vaultRecords.id, payrollStatementEvidenceGrants.id),
        eq(vaultRecords.recordType, "payroll-statement-evidence"),
        eq(vaultRecords.revision, 1),
        isNull(vaultRecords.supersededAt),
      )).where(eq(payrollStatementEvidenceGrants.statementId, statement.id))
        .orderBy(payrollStatementEvidenceGrants.id);
      const submittedEvidence = statement.evidenceGrants.map((grant) => ({
        id: grant.id,
        claimAccessGrantId: grant.claimAccessGrantId,
        claimantPrincipalId: grant.claimantPrincipalId,
        envelopeHash: hashCanonicalJson(grant.envelope),
      }));
      if (
        storedVault
        && storedFingerprint({
          statement: existing,
          snapshot,
          evidence: storedEvidence,
          statementEnvelopeHash: storedVault.envelopeHash,
        }) === immutableFingerprint({
          statement,
          evidence: submittedEvidence,
          statementEnvelopeHash: hashCanonicalJson(statement.envelope),
        })
      ) {
        return { ...publicStatement(existing), replayed: true };
      }
      throw new ApiError(
        409,
        "Employer statement ID already contains different immutable evidence.",
        "STATEMENT_CONFLICT",
      );
    }

    const [duplicate] = await transaction.select({ id: employerStatements.id })
      .from(employerStatements)
      .where(or(
        eq(
          employerStatements.statementFact,
          canonicalCommitment(statement.statementCommitment),
        ),
        and(
          eq(employerStatements.runId, statement.runId),
          eq(employerStatements.fxRoot, canonicalCommitment(statement.statement.fxRoot)),
        ),
      ))
      .limit(1)
      .for("update");
    if (duplicate) {
      throw new ApiError(
        409,
        "This payroll run already has an immutable statement for that FX profile.",
        "STATEMENT_DUPLICATE",
      );
    }

    const identifiers = [statement.id, ...statement.evidenceGrants.map(({ id }) => id)];
    for (const identifier of identifiers) {
      const [conflict] = await transaction.select({ id: vaultRecords.id })
        .from(vaultRecords)
        .where(and(
          eq(vaultRecords.organizationId, statement.organizationId),
          eq(vaultRecords.id, identifier),
        ))
        .limit(1)
        .for("update");
      if (conflict) {
        throw new ApiError(
          409,
          "A statement vault identifier is already in use.",
          "STATEMENT_VAULT_CONFLICT",
        );
      }
    }

    await transaction.insert(vaultRecords).values({
      id: statement.id,
      organizationId: statement.organizationId,
      recordType: "employer-statement-v2",
      revision: 1,
      ciphertext: statement.envelope.ciphertext,
      envelope: statement.envelope,
      envelopeHash: hashCanonicalJson(statement.envelope),
      createdBy: input.principal.principalId,
      createdAt: now,
    });
    const [created] = await transaction.insert(employerStatements).values({
      id: statement.id,
      snapshotPlanId: statement.snapshotPlanId,
      organizationId: statement.organizationId,
      runId: statement.runId,
      ownerAddress: statement.ownerAddress,
      statementFact: canonicalCommitment(statement.statementCommitment),
      manifestRoot: canonicalCommitment(statement.statement.manifestRoot),
      fxRoot: canonicalCommitment(statement.statement.fxRoot),
      availabilityCommitment: canonicalCommitment(
        statement.statement.availabilityCommitment,
      ),
      observedAt,
      source: "employer_statement",
      createdBy: input.principal.principalId,
      createdAt: now,
      updatedAt: now,
    }).returning();

    for (const grant of statement.evidenceGrants) {
      await transaction.insert(vaultRecords).values({
        id: grant.id,
        organizationId: statement.organizationId,
        recordType: "payroll-statement-evidence",
        revision: 1,
        ciphertext: grant.envelope.ciphertext,
        envelope: grant.envelope,
        envelopeHash: hashCanonicalJson(grant.envelope),
        createdBy: input.principal.principalId,
        createdAt: now,
      });
      await transaction.insert(payrollStatementEvidenceGrants).values({
        id: grant.id,
        statementId: statement.id,
        claimAccessGrantId: grant.claimAccessGrantId,
        organizationId: statement.organizationId,
        runId: statement.runId,
        claimantPrincipalId: grant.claimantPrincipalId,
        createdAt: now,
      });
    }

    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: statement.organizationId,
      actorId: input.principal.principalId,
      action: "employer_statement.prepared",
      subjectId: statement.id,
      metadata: {
        runId: statement.runId,
        snapshotPlanId: statement.snapshotPlanId,
        statementFact: canonicalCommitment(statement.statementCommitment),
        evidenceGrantCount: statement.evidenceGrants.length,
      },
    });
    return { ...publicStatement(created), replayed: false };
  });
}

export async function recordEmployerStatementSubmission(input: {
  statementId: string;
  transactionHash: string;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const transactionHash = canonicalTransactionHash(input.transactionHash);
  const now = input.now ?? new Date();
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [statement] = await transaction.select().from(employerStatements)
      .where(eq(employerStatements.id, input.statementId))
      .limit(1)
      .for("update");
    if (!statement) {
      throw new ApiError(404, "Employer statement not found.", "STATEMENT_NOT_FOUND");
    }
    const [membership] = await transaction.select({ role: organizationMembers.role })
      .from(organizationMembers).where(and(
        eq(organizationMembers.organizationId, statement.organizationId),
        eq(organizationMembers.principalId, input.principal.principalId),
        isNull(organizationMembers.revokedAt),
      )).limit(1);
    if (!membership || !["admin", "operator"].includes(membership.role)) {
      throw new ApiError(
        403,
        "You cannot record this statement registration.",
        "ORG_FORBIDDEN",
      );
    }
    if (statement.state === "failed") {
      throw new ApiError(
        409,
        "A failed statement cannot be submitted again under the same identifier.",
        "STATEMENT_TERMINAL",
      );
    }
    if (
      statement.registrationTransactionHash
      && BigInt(statement.registrationTransactionHash) !== BigInt(transactionHash)
    ) {
      throw new ApiError(
        409,
        "This statement already references another transaction.",
        "STATEMENT_TRANSACTION_CONFLICT",
      );
    }
    if (statement.state === "submitted" || statement.state === "registered") {
      return { ...publicStatement(statement), replayed: true };
    }

    const [updated] = await transaction.update(employerStatements).set({
      state: "submitted",
      registrationTransactionHash: transactionHash,
      updatedAt: now,
    }).where(and(
      eq(employerStatements.id, statement.id),
      eq(employerStatements.state, "prepared"),
    )).returning();
    if (!updated) {
      throw new ApiError(
        409,
        "Employer statement changed while recording submission.",
        "STATEMENT_STATE_CONFLICT",
      );
    }
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: statement.organizationId,
      actorId: input.principal.principalId,
      action: "employer_statement.submitted",
      subjectId: statement.id,
      metadata: { runId: statement.runId, transactionHash },
    });
    return { ...publicStatement(updated), replayed: false };
  });
}

/** Called only after a pinned RPC read and finalized event match all stored fields. */
export async function markEmployerStatementRegistered(input: {
  statementId: string;
  transactionHash?: string | null;
  registeredAt: Date;
}) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [statement] = await transaction.select().from(employerStatements)
      .where(eq(employerStatements.id, input.statementId))
      .limit(1)
      .for("update");
    if (!statement) {
      throw new ApiError(404, "Employer statement not found.", "STATEMENT_NOT_FOUND");
    }
    if (statement.state === "failed") {
      throw new ApiError(
        409,
        "A failed statement cannot be registered.",
        "STATEMENT_TERMINAL",
      );
    }
    if (statement.state === "registered") {
      return { ...publicStatement(statement), replayed: true };
    }
    const transactionHash = input.transactionHash
      ? canonicalTransactionHash(input.transactionHash)
      : statement.registrationTransactionHash;
    if (
      statement.registrationTransactionHash
      && transactionHash
      && BigInt(statement.registrationTransactionHash) !== BigInt(transactionHash)
    ) {
      throw new ApiError(
        409,
        "Statement registration transaction changed.",
        "STATEMENT_TRANSACTION_CONFLICT",
      );
    }

    const [updated] = await transaction.update(employerStatements).set({
      state: "registered",
      registrationTransactionHash: transactionHash,
      registeredAt: input.registeredAt,
      updatedAt: input.registeredAt,
    }).where(eq(employerStatements.id, statement.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: statement.organizationId,
      actorId: "system:statement-reconciler",
      action: "employer_statement.registered",
      subjectId: statement.id,
      metadata: { runId: statement.runId, transactionHash },
    });
    return { ...publicStatement(updated), replayed: false };
  });
}

export async function getEmployerStatement(
  statementId: string,
  principal: AuthenticatedPrincipal,
) {
  const database = getDatabase();
  const [row] = await database.select({
    statement: employerStatements,
    envelope: vaultRecords.envelope,
  }).from(employerStatements).innerJoin(vaultRecords, and(
    eq(vaultRecords.organizationId, employerStatements.organizationId),
    eq(vaultRecords.id, employerStatements.id),
    eq(vaultRecords.recordType, "employer-statement-v2"),
    isNull(vaultRecords.supersededAt),
  )).where(eq(employerStatements.id, statementId)).limit(1);
  if (!row) {
    throw new ApiError(404, "Employer statement not found.", "STATEMENT_NOT_FOUND");
  }
  await requireOrganizationRole(
    row.statement.organizationId,
    principal,
    ["admin", "operator", "reviewer"],
  );
  return publicStatement(row.statement, row.envelope);
}

export async function listEmployerStatements(
  organizationId: string,
  principal: AuthenticatedPrincipal,
) {
  await requireOrganizationRole(
    organizationId,
    principal,
    ["admin", "operator", "reviewer"],
  );
  const statements = await getDatabase().select().from(employerStatements)
    .where(eq(employerStatements.organizationId, organizationId))
    .orderBy(desc(employerStatements.observedAt), desc(employerStatements.createdAt));
  return statements.map((statement) => publicStatement(statement));
}

export async function listPayrollStatementEvidenceGrants(
  principal: AuthenticatedPrincipal,
) {
  const rows = await getDatabase().select({
    grant: payrollStatementEvidenceGrants,
    statement: employerStatements,
    envelope: vaultRecords.envelope,
  }).from(payrollStatementEvidenceGrants)
    .innerJoin(employerStatements, eq(
      payrollStatementEvidenceGrants.statementId,
      employerStatements.id,
    ))
    .innerJoin(vaultRecords, and(
      eq(vaultRecords.organizationId, payrollStatementEvidenceGrants.organizationId),
      eq(vaultRecords.id, payrollStatementEvidenceGrants.id),
      eq(vaultRecords.recordType, "payroll-statement-evidence"),
      isNull(vaultRecords.supersededAt),
    ))
    .where(and(
      eq(
        payrollStatementEvidenceGrants.claimantPrincipalId,
        principal.principalId,
      ),
      isNull(payrollStatementEvidenceGrants.revokedAt),
      eq(employerStatements.state, "registered"),
    ))
    .orderBy(desc(payrollStatementEvidenceGrants.createdAt));
  return rows.map(({ grant, statement, envelope }) => ({
    id: grant.id,
    statementId: grant.statementId,
    claimAccessGrantId: grant.claimAccessGrantId,
    claimantPrincipalId: grant.claimantPrincipalId,
    revokedAt: grant.revokedAt?.toISOString() ?? null,
    statement: publicStatement(statement),
    envelope,
  }));
}
