import "server-only";

import { and, desc, eq, inArray, isNull } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { encryptedVaultRecordSchema, type EncryptedVaultRecord } from "@/lib/crypto/vault";
import type { SignedCapability } from "@/lib/domain/capability";
import { hashCapability } from "@/lib/domain/capability";
import { assertOperationalMetadataSafe } from "@/lib/domain/privacy";
import type { EncryptedRunCreate, PayrollRunState } from "@/lib/domain/payroll";
import { assertPayrollTransition } from "@/lib/domain/payroll";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import {
  decryptCapabilityPolicy,
  encryptCapabilityPolicy,
} from "@/lib/server/capability-policy-crypto";
import { getDatabase, type DatabaseExecutor } from "./db";
import {
  auditEvents,
  agentCapabilities,
  organizationMembers,
  organizations,
  obligationSnapshotPlans,
  payrollRuns,
  vaultRecords,
} from "./schema";

type OrganizationRole = "admin" | "operator" | "reviewer";

function eventId(): string {
  return generateUuidV7();
}

function auditMetadata<T extends Record<string, unknown>>(metadata: T): T {
  assertOperationalMetadataSafe(metadata);
  return metadata;
}

function payloadHash(value: unknown): string {
  return hashCanonicalJson(value);
}

export async function requireOrganizationRole(
  organizationId: string,
  principal: AuthenticatedPrincipal,
  allowed: readonly OrganizationRole[],
) {
  return requireOrganizationRoleWith(getDatabase(), organizationId, principal, allowed);
}

/** Use the transaction executor for every authorization guarding a mutation. */
export async function requireOrganizationRoleWith(
  database: DatabaseExecutor,
  organizationId: string,
  principal: AuthenticatedPrincipal,
  allowed: readonly OrganizationRole[],
) {
  if (principal.authKind === "agent_capability") {
    if (
      principal.capabilityOrganizationId !== organizationId
      || principal.capabilityPrincipalId !== principal.principalId
      || !principal.capabilityId
      || !allowed.includes("operator")
    ) {
      throw new ApiError(403, "The scoped agent credential cannot access this organization action.", "AGENT_ORG_SCOPE_DENIED");
    }
    // The request authenticator has already checked the signed action and
    // capability route. This virtual operator role never enters the member
    // table and therefore cannot be reused by Ready or administrative routes.
    return { role: "operator" as const };
  }
  const [membership] = await database
    .select({ role: organizationMembers.role })
    .from(organizationMembers)
    .where(
      and(
        eq(organizationMembers.organizationId, organizationId),
        eq(organizationMembers.principalId, principal.principalId),
        isNull(organizationMembers.revokedAt),
      ),
    )
    .limit(1);
  if (!membership || !allowed.includes(membership.role)) {
    throw new ApiError(403, "You do not have access to this organization.", "ORG_FORBIDDEN");
  }
  return membership;
}

export async function listOrganizations(principal: AuthenticatedPrincipal) {
  return getDatabase()
    .select({
      id: organizations.id,
      encryptedProfile: organizations.encryptedProfile,
      recoveryState: organizations.recoveryState,
      recoveryConfiguredAt: organizations.recoveryConfiguredAt,
      keyVersion: organizations.keyVersion,
      role: organizationMembers.role,
      vaultPublicKey: organizationMembers.vaultPublicKey,
      createdAt: organizations.createdAt,
    })
    .from(organizationMembers)
    .innerJoin(organizations, eq(organizationMembers.organizationId, organizations.id))
    .where(and(
      eq(organizationMembers.principalId, principal.principalId),
      isNull(organizationMembers.revokedAt),
    ))
    .orderBy(desc(organizations.createdAt));
}

export async function createOrganization(input: {
  organizationId: string;
  encryptedProfile: unknown;
  vaultPublicKey: string;
  initialPrincipal: {
    recordId: string;
    envelope: unknown;
  };
  principal: AuthenticatedPrincipal;
}) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [organization] = await transaction
      .insert(organizations)
      .values({ id: input.organizationId, encryptedProfile: input.encryptedProfile })
      .returning({ id: organizations.id, createdAt: organizations.createdAt });
    await transaction.insert(organizationMembers).values({
      organizationId: input.organizationId,
      principalId: input.principal.principalId,
      role: "admin",
      vaultPublicKey: input.vaultPublicKey,
    });
    const initialPrincipalEnvelope = encryptedVaultRecordSchema.parse(input.initialPrincipal.envelope);
    if (
      initialPrincipalEnvelope.aad.organizationId !== input.organizationId
      || initialPrincipalEnvelope.aad.recordId !== input.initialPrincipal.recordId
      || initialPrincipalEnvelope.aad.recordType !== "principal"
      || initialPrincipalEnvelope.aad.revision !== 1
    ) throw new ApiError(400, "The initial principal envelope has invalid storage identity.", "PRINCIPAL_AAD_MISMATCH");
    await transaction.insert(vaultRecords).values({
      id: input.initialPrincipal.recordId,
      organizationId: input.organizationId,
      recordType: "principal",
      revision: 1,
      ciphertext: initialPrincipalEnvelope.ciphertext,
      envelope: initialPrincipalEnvelope,
      envelopeHash: payloadHash(initialPrincipalEnvelope),
      createdBy: input.principal.principalId,
    });
    await transaction.insert(auditEvents).values({
      id: eventId(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "organization.created",
      subjectId: input.organizationId,
      metadata: auditMetadata({ sessionId: input.principal.sessionId }),
    });
    return organization;
  });
}

export async function createEncryptedRun(input: EncryptedRunCreate, principal: AuthenticatedPrincipal) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, principal, ["admin", "operator"]);
    const [organization] = await transaction
      .select({ recoveryState: organizations.recoveryState })
      .from(organizations)
      .where(eq(organizations.id, input.organizationId))
      .limit(1)
      .for("update");
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    if (organization.recoveryState === "required") {
      throw new ApiError(
        409,
        "Download a recovery package or add a second administrator before creating production payroll.",
        "VAULT_RECOVERY_REQUIRED",
      );
    }
    const now = new Date();
    let snapshotPlan: typeof obligationSnapshotPlans.$inferSelect | undefined;
    if (input.obligationSnapshotPlanId) {
      [snapshotPlan] = await transaction.select().from(obligationSnapshotPlans).where(and(
        eq(obligationSnapshotPlans.id, input.obligationSnapshotPlanId),
        eq(obligationSnapshotPlans.organizationId, input.organizationId),
      )).limit(1).for("update");
      if (!snapshotPlan) {
        throw new ApiError(404, "Obligation snapshot plan not found.", "SNAPSHOT_PLAN_NOT_FOUND");
      }
      if (snapshotPlan.state !== "registered" && snapshotPlan.state !== "consumed") {
        throw new ApiError(
          409,
          "The obligation snapshot must be registered before creating its payroll.",
          "SNAPSHOT_PLAN_NOT_REGISTERED",
        );
      }
      if (
        !principal.walletAddress
        || BigInt(principal.walletAddress) !== BigInt(snapshotPlan.ownerAddress)
      ) {
        throw new ApiError(403, "Use the Ready account that registered this snapshot.", "SNAPSHOT_OWNER_MISMATCH");
      }
      const immutableBindingsMatch = snapshotPlan.runId === input.id
        && snapshotPlan.cycleId === input.cycleId
        && snapshotPlan.revision === input.revision
        && snapshotPlan.dueAt.getTime() === new Date(input.dueAt).getTime()
        && BigInt(snapshotPlan.agreementRoot) === BigInt(input.agreementRoot)
        && BigInt(snapshotPlan.policyRoot) === BigInt(input.policyRoot)
        && BigInt(snapshotPlan.runNullifier) === BigInt(input.runNullifier);
      if (!immutableBindingsMatch) {
        throw new ApiError(
          409,
          "The payroll differs from its registered obligation snapshot.",
          "SNAPSHOT_PAYROLL_BINDING_MISMATCH",
        );
      }
      if (now.getTime() < snapshotPlan.dueAt.getTime()) {
        throw new ApiError(409, "This registered payroll is not due yet.", "SNAPSHOT_PAYROLL_NOT_DUE");
      }
      if (now.getTime() > snapshotPlan.claimEndsAt.getTime()) {
        throw new ApiError(409, "This snapshot's payroll and claim window has expired.", "SNAPSHOT_PLAN_EXPIRED");
      }
    }
    const runEnvelope = encryptedVaultRecordSchema.parse(input.envelope);
    const lineRecords = input.lineRecords.map((line) => ({
      ...line,
      envelope: encryptedVaultRecordSchema.parse(line.envelope),
    }));
    if (
      runEnvelope.ciphertext !== input.ciphertext
      || runEnvelope.aad.organizationId !== input.organizationId
      || runEnvelope.aad.recordId !== input.id
      || runEnvelope.aad.recordType !== "payroll-run"
      || runEnvelope.aad.revision !== input.revision
    ) throw new ApiError(400, "Encrypted payroll-run AAD does not match its storage identity.", "AAD_MISMATCH");
    if (new Set(lineRecords.map(({ id }) => id)).size !== lineRecords.length) {
      throw new ApiError(400, "Encrypted payroll-line identifiers must be unique.", "PAYROLL_LINE_DUPLICATE");
    }
    for (const line of lineRecords) {
      if (
        line.envelope.aad.organizationId !== input.organizationId
        || line.envelope.aad.recordId !== line.id
        || line.envelope.aad.recordType !== "payroll-line"
        || line.envelope.aad.revision !== line.revision
      ) throw new ApiError(400, "Encrypted payroll-line AAD does not match its storage identity.", "AAD_MISMATCH");
    }
    const [existingRun] = await transaction.select().from(payrollRuns)
      .where(eq(payrollRuns.id, input.id)).limit(1).for("update");
    if (existingRun) {
      const publicBindingsMatch = existingRun.organizationId === input.organizationId
        && existingRun.cycleId === input.cycleId
        && existingRun.revision === input.revision
        && existingRun.dueAt.getTime() === new Date(input.dueAt).getTime()
        && existingRun.obligationSnapshotPlanId === (input.obligationSnapshotPlanId ?? null)
        && BigInt(existingRun.agreementRoot ?? "0x0") === BigInt(input.agreementRoot)
        && BigInt(existingRun.policyRoot ?? "0x0") === BigInt(input.policyRoot)
        && BigInt(existingRun.runNullifier ?? "0x0") === BigInt(input.runNullifier);
      if (!publicBindingsMatch) {
        throw new ApiError(409, "This payroll identifier is already reserved for different immutable facts.", "RUN_CONFLICT");
      }
      const recordIds = [input.id, ...lineRecords.map(({ id }) => id)];
      const storedRecords = await transaction.select({
        id: vaultRecords.id,
        recordType: vaultRecords.recordType,
        revision: vaultRecords.revision,
        envelopeHash: vaultRecords.envelopeHash,
      }).from(vaultRecords).where(and(
        eq(vaultRecords.organizationId, input.organizationId),
        inArray(vaultRecords.id, recordIds),
        isNull(vaultRecords.supersededAt),
      ));
      const storedRunEnvelope = storedRecords.find(({ id, recordType }) =>
        id === input.id && recordType === "payroll-run");
      if (storedRunEnvelope) {
        const expectedRecords = [
          { id: input.id, recordType: "payroll-run", revision: input.revision, envelopeHash: payloadHash(runEnvelope) },
          ...lineRecords.map((line) => ({
            id: line.id,
            recordType: "payroll-line",
            revision: line.revision,
            envelopeHash: payloadHash(line.envelope),
          })),
        ];
        const envelopesMatch = storedRecords.length === expectedRecords.length
          && expectedRecords.every((expected) => storedRecords.some((stored) =>
            stored.id === expected.id
            && stored.recordType === expected.recordType
            && stored.revision === expected.revision
            && stored.envelopeHash === expected.envelopeHash));
        const completedBindingsMatch = BigInt(existingRun.manifestRoot ?? "0x0") === BigInt(input.manifestRoot)
          && BigInt(existingRun.fxRoot ?? "0x0") === BigInt(input.fxRoot);
        if (!envelopesMatch || !completedBindingsMatch || (snapshotPlan && snapshotPlan.state !== "consumed")) {
          throw new ApiError(409, "The existing payroll payload differs from this retry.", "RUN_REPLAY_MISMATCH");
        }
        return { ...existingRun, replayed: true };
      }
      if (
        !snapshotPlan
        || snapshotPlan.state !== "registered"
        || existingRun.state !== "draft"
        || existingRun.manifestRoot !== null
        || existingRun.fxRoot !== null
      ) {
        throw new ApiError(409, "This payroll reservation cannot accept a new encrypted payload.", "RUN_RESERVATION_INVALID");
      }
    } else if (snapshotPlan) {
      throw new ApiError(409, "The registered snapshot is missing its durable run reservation.", "SNAPSHOT_RUN_RESERVATION_MISSING");
    }
    await transaction.insert(vaultRecords).values({
      id: input.id,
      organizationId: input.organizationId,
      recordType: "payroll-run",
      revision: input.revision,
      ciphertext: input.ciphertext,
      envelope: runEnvelope,
      envelopeHash: payloadHash(runEnvelope),
      createdBy: principal.principalId,
    });
    await transaction.insert(vaultRecords).values(lineRecords.map((line) => ({
      id: line.id,
      organizationId: input.organizationId,
      recordType: "payroll-line" as const,
      revision: line.revision,
      ciphertext: line.envelope.ciphertext,
      envelope: line.envelope,
      envelopeHash: payloadHash(line.envelope),
      createdBy: principal.principalId,
    })));
    const [run] = existingRun
      ? await transaction.update(payrollRuns).set({
        manifestRoot: input.manifestRoot,
        fxRoot: input.fxRoot,
        updatedAt: now,
      }).where(and(
        eq(payrollRuns.id, input.id),
        eq(payrollRuns.state, "draft"),
        isNull(payrollRuns.manifestRoot),
        isNull(payrollRuns.fxRoot),
      )).returning()
      : await transaction.insert(payrollRuns).values({
        id: input.id,
        organizationId: input.organizationId,
        cycleId: input.cycleId,
        revision: input.revision,
        dueAt: new Date(input.dueAt),
        agreementRoot: input.agreementRoot,
        manifestRoot: input.manifestRoot,
        policyRoot: input.policyRoot,
        fxRoot: input.fxRoot,
        runNullifier: input.runNullifier,
        obligationSnapshotPlanId: input.obligationSnapshotPlanId,
      }).returning();
    if (!run) throw new ApiError(409, "The payroll reservation changed; retry safely.", "RUN_STATE_CONFLICT");
    if (snapshotPlan) {
      const [consumed] = await transaction.update(obligationSnapshotPlans).set({
        state: "consumed",
        consumedAt: now,
        updatedAt: now,
      }).where(and(
        eq(obligationSnapshotPlans.id, snapshotPlan.id),
        eq(obligationSnapshotPlans.state, "registered"),
      )).returning({ id: obligationSnapshotPlans.id });
      if (!consumed) {
        throw new ApiError(409, "The snapshot was consumed by another payroll.", "SNAPSHOT_PLAN_CONSUMED");
      }
    }
    await transaction.insert(auditEvents).values({
      id: eventId(),
      organizationId: input.organizationId,
      actorId: principal.principalId,
      action: "payroll_run.created",
      subjectId: input.id,
      metadata: auditMetadata({
        revision: input.revision,
        encryptedLineCount: lineRecords.length,
        ...(snapshotPlan ? { obligationSnapshotPlanId: snapshotPlan.id } : {}),
      }),
    });
    return { ...run, replayed: false };
  });
}

export async function listPayrollRuns(organizationId: string, principal: AuthenticatedPrincipal) {
  await requireOrganizationRole(organizationId, principal, ["admin", "operator", "reviewer"]);
  return getDatabase()
    .select({
      id: payrollRuns.id,
      cycleId: payrollRuns.cycleId,
      revision: payrollRuns.revision,
      state: payrollRuns.state,
      dueAt: payrollRuns.dueAt,
      agreementRoot: payrollRuns.agreementRoot,
      policyRoot: payrollRuns.policyRoot,
      fxRoot: payrollRuns.fxRoot,
      manifestRoot: payrollRuns.manifestRoot,
      runNullifier: payrollRuns.runNullifier,
      obligationSnapshotPlanId: payrollRuns.obligationSnapshotPlanId,
      transactionHash: payrollRuns.transactionHash,
      createdAt: payrollRuns.createdAt,
      updatedAt: payrollRuns.updatedAt,
    })
    .from(payrollRuns)
    .where(eq(payrollRuns.organizationId, organizationId))
    .orderBy(desc(payrollRuns.dueAt));
}

export async function listAuditEvents(
  organizationId: string,
  principal: AuthenticatedPrincipal,
  limit = 100,
) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
    throw new ApiError(400, "Audit-event list limit must be 1–200.", "LIMIT_INVALID");
  }
  await requireOrganizationRole(organizationId, principal, ["admin", "operator", "reviewer"]);
  return getDatabase()
    .select({
      id: auditEvents.id,
      actorId: auditEvents.actorId,
      action: auditEvents.action,
      subjectId: auditEvents.subjectId,
      metadata: auditEvents.metadata,
      createdAt: auditEvents.createdAt,
    })
    .from(auditEvents)
    .where(eq(auditEvents.organizationId, organizationId))
    .orderBy(desc(auditEvents.createdAt))
    .limit(limit);
}

export async function getEncryptedRun(runId: string, principal: AuthenticatedPrincipal) {
  const database = getDatabase();
  const [run] = await database
    .select()
    .from(payrollRuns)
    .where(eq(payrollRuns.id, runId))
    .limit(1);
  if (!run) throw new ApiError(404, "Payroll run not found.", "RUN_NOT_FOUND");
  await requireOrganizationRole(run.organizationId, principal, ["admin", "operator", "reviewer"]);
  const [vault] = await database
    .select({
      ciphertext: vaultRecords.ciphertext,
      envelope: vaultRecords.envelope,
      vaultRevision: vaultRecords.revision,
    })
    .from(vaultRecords)
    .where(
      and(
        eq(vaultRecords.organizationId, run.organizationId),
        eq(vaultRecords.id, run.id),
      ),
    )
    .orderBy(desc(vaultRecords.revision))
    .limit(1);
  if (!vault) throw new ApiError(500, "The encrypted run payload is missing.", "RUN_VAULT_MISSING");
  return { ...run, ...vault };
}

export async function transitionRun(input: {
  runId: string;
  state: PayrollRunState;
  transactionHash?: string;
  manifestRoot?: string;
  runNullifier?: string;
  principal: AuthenticatedPrincipal;
}) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [existing] = await transaction
      .select()
      .from(payrollRuns)
      .where(eq(payrollRuns.id, input.runId))
      .limit(1)
      .for("update");
    if (!existing) throw new ApiError(404, "Payroll run not found.", "RUN_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, existing.organizationId, input.principal, ["admin", "operator"]);
    assertPayrollTransition(existing.state, input.state);
    const [run] = await transaction
      .update(payrollRuns)
      .set({
        state: input.state,
        transactionHash: input.transactionHash ?? existing.transactionHash,
        manifestRoot: input.manifestRoot ?? existing.manifestRoot,
        runNullifier: input.runNullifier ?? existing.runNullifier,
        updatedAt: new Date(),
      })
      .where(and(eq(payrollRuns.id, input.runId), eq(payrollRuns.state, existing.state)))
      .returning();
    if (!run) throw new ApiError(409, "The payroll run changed; refresh and retry.", "RUN_STATE_CONFLICT");
    await transaction.insert(auditEvents).values({
      id: eventId(),
      organizationId: existing.organizationId,
      actorId: input.principal.principalId,
      action: "payroll_run.transitioned",
      subjectId: input.runId,
      metadata: auditMetadata({ from: existing.state, to: input.state }),
    });
    return run;
  });
}

export async function registerAgentCapability(
  input: {
    signedCapability: SignedCapability;
    recordId: string;
    revision: number;
    envelope: EncryptedVaultRecord;
  },
  principal: AuthenticatedPrincipal,
) {
  const { signedCapability } = input;
  const { capability } = signedCapability;
  if (input.recordId !== capability.id || input.revision !== 1) {
    throw new ApiError(400, "A capability must start at its matching encrypted record revision 1.", "CAPABILITY_RECORD_MISMATCH");
  }
  const envelope = encryptedVaultRecordSchema.parse(input.envelope);
  if (
    envelope.aad.organizationId !== capability.organizationId
    || envelope.aad.recordId !== input.recordId
    || envelope.aad.recordType !== "agent-capability"
    || envelope.aad.revision !== input.revision
  ) throw new ApiError(400, "Encrypted capability AAD does not match its policy identity.", "AAD_MISMATCH");
  const capabilityHash = hashCapability(capability);
  const envelopeHash = payloadHash(envelope);
  const policyContext = {
    capabilityId: capability.id,
    organizationId: capability.organizationId,
    principalId: capability.principalId,
    capabilityHash,
  };
  const encryptedPolicy = encryptCapabilityPolicy(signedCapability, policyContext);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, capability.organizationId, principal, ["admin"]);
    const [existingCapability] = await transaction
      .select({ capabilityHash: agentCapabilities.capabilityHash })
      .from(agentCapabilities)
      .where(eq(agentCapabilities.id, capability.id))
      .limit(1)
      .for("update");
    const [existingEnvelope] = await transaction
      .select({ envelopeHash: vaultRecords.envelopeHash })
      .from(vaultRecords)
      .where(and(
        eq(vaultRecords.organizationId, capability.organizationId),
        eq(vaultRecords.id, input.recordId),
        eq(vaultRecords.revision, input.revision),
      ))
      .limit(1)
      .for("update");
    if (existingCapability || existingEnvelope) {
      if (
        existingCapability?.capabilityHash === capabilityHash
        && existingEnvelope?.envelopeHash === envelopeHash
      ) return {
        id: capability.id,
        capabilityHash,
        expiresAt: new Date(capability.expiresAt),
        replayed: true,
      };
      throw new ApiError(409, "This capability identity already contains different data.", "CAPABILITY_CONFLICT");
    }
    await transaction.insert(vaultRecords).values({
      id: input.recordId,
      organizationId: capability.organizationId,
      recordType: "agent-capability",
      revision: input.revision,
      ciphertext: envelope.ciphertext,
      envelope,
      envelopeHash,
      createdBy: principal.principalId,
    });
    const [stored] = await transaction
      .insert(agentCapabilities)
      .values({
        id: capability.id,
        organizationId: capability.organizationId,
        principalId: capability.principalId,
        capabilityHash,
        policy: encryptedPolicy,
        expiresAt: new Date(capability.expiresAt),
      })
      .returning({
        id: agentCapabilities.id,
        capabilityHash: agentCapabilities.capabilityHash,
        expiresAt: agentCapabilities.expiresAt,
      });
    await transaction.insert(auditEvents).values({
      id: eventId(),
      organizationId: capability.organizationId,
      actorId: principal.principalId,
      action: "agent_capability.registered",
      subjectId: capability.id,
      metadata: auditMetadata({
        principalId: capability.principalId,
        capabilityHash: stored.capabilityHash,
        envelopeHash,
      }),
    });
    return { ...stored, replayed: false };
  });
}

export async function getAgentCapability(capabilityId: string, principal: AuthenticatedPrincipal) {
  const database = getDatabase();
  const [stored] = await database
    .select()
    .from(agentCapabilities)
    .where(eq(agentCapabilities.id, capabilityId))
    .limit(1);
  if (!stored) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
  await requireOrganizationRole(stored.organizationId, principal, ["admin", "operator", "reviewer"]);
  if (stored.revokedAt) throw new ApiError(410, "Agent capability was revoked.", "CAPABILITY_REVOKED");
  if (stored.expiresAt.getTime() <= Date.now()) {
    throw new ApiError(410, "Agent capability expired.", "CAPABILITY_EXPIRED");
  }
  return decryptCapabilityPolicy(stored.policy, {
    capabilityId: stored.id,
    organizationId: stored.organizationId,
    principalId: stored.principalId,
    capabilityHash: stored.capabilityHash,
  });
}

export async function revokeAgentCapability(input: {
  capabilityId: string;
  organizationId: string;
  revision: number;
  envelope: EncryptedVaultRecord;
}, principal: AuthenticatedPrincipal) {
  const envelope = encryptedVaultRecordSchema.parse(input.envelope);
  if (
    envelope.aad.organizationId !== input.organizationId
    || envelope.aad.recordId !== input.capabilityId
    || envelope.aad.recordType !== "agent-capability"
    || envelope.aad.revision !== input.revision
  ) throw new ApiError(400, "Encrypted capability AAD does not match its revocation revision.", "AAD_MISMATCH");
  const envelopeHash = payloadHash(envelope);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [stored] = await transaction
      .select()
      .from(agentCapabilities)
      .where(eq(agentCapabilities.id, input.capabilityId))
      .limit(1)
      .for("update");
    if (!stored) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
    if (stored.organizationId !== input.organizationId) {
      throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
    }
    await requireOrganizationRoleWith(transaction, stored.organizationId, principal, ["admin"]);
    const [latestEnvelope] = await transaction
      .select({ revision: vaultRecords.revision, envelopeHash: vaultRecords.envelopeHash })
      .from(vaultRecords)
      .where(and(
        eq(vaultRecords.organizationId, input.organizationId),
        eq(vaultRecords.id, input.capabilityId),
      ))
      .orderBy(desc(vaultRecords.revision))
      .limit(1)
      .for("update");
    if (!latestEnvelope) throw new ApiError(409, "The encrypted capability record is missing.", "CAPABILITY_VAULT_MISSING");
    if (input.revision === latestEnvelope.revision && latestEnvelope.envelopeHash === envelopeHash && stored.revokedAt) {
      return { id: stored.id, revokedAt: stored.revokedAt, replayed: true };
    }
    if (input.revision !== latestEnvelope.revision + 1) {
      throw new ApiError(409, `Encrypted capability revision must be ${latestEnvelope.revision + 1}.`, "RECORD_REVISION_GAP");
    }
    if (stored.revokedAt) {
      throw new ApiError(409, "The capability was already revoked with another encrypted revision.", "CAPABILITY_REVOKED");
    }
    const revokedAt = new Date();
    const [revoked] = await transaction
      .update(agentCapabilities)
      .set({ revokedAt })
      .where(and(eq(agentCapabilities.id, input.capabilityId), eq(agentCapabilities.organizationId, stored.organizationId)))
      .returning({ id: agentCapabilities.id, revokedAt: agentCapabilities.revokedAt });
    await transaction
      .update(vaultRecords)
      .set({ supersededAt: revokedAt })
      .where(and(
        eq(vaultRecords.organizationId, input.organizationId),
        eq(vaultRecords.id, input.capabilityId),
        eq(vaultRecords.revision, latestEnvelope.revision),
      ));
    await transaction.insert(vaultRecords).values({
      id: input.capabilityId,
      organizationId: input.organizationId,
      recordType: "agent-capability",
      revision: input.revision,
      ciphertext: envelope.ciphertext,
      envelope,
      envelopeHash,
      createdBy: principal.principalId,
    });
    await transaction.insert(auditEvents).values({
      id: eventId(),
      organizationId: stored.organizationId,
      actorId: principal.principalId,
      action: "agent_capability.revoked",
      subjectId: input.capabilityId,
      metadata: auditMetadata({ capabilityHash: stored.capabilityHash, envelopeHash }),
    });
    return { ...revoked, replayed: false };
  });
}
