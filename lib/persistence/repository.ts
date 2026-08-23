import { and, desc, eq } from "drizzle-orm";
import type { SignedCapability } from "@/lib/domain/capability";
import { hashCapability } from "@/lib/domain/capability";
import type { EncryptedRunCreate, PayrollRunState, ProofPackage } from "@/lib/domain/payroll";
import { assertPayrollTransition } from "@/lib/domain/payroll";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import {
  auditEvents,
  agentCapabilities,
  organizationMembers,
  organizations,
  payrollRuns,
  proofBundles,
  vaultRecords,
} from "./schema";

type OrganizationRole = "admin" | "operator" | "reviewer";

function eventId(): string {
  return crypto.randomUUID();
}

export async function requireOrganizationRole(
  organizationId: string,
  principal: AuthenticatedPrincipal,
  allowed: readonly OrganizationRole[],
) {
  const database = getDatabase();
  const [membership] = await database
    .select({ role: organizationMembers.role })
    .from(organizationMembers)
    .where(
      and(
        eq(organizationMembers.organizationId, organizationId),
        eq(organizationMembers.principalId, principal.principalId),
      ),
    )
    .limit(1);
  if (!membership || !allowed.includes(membership.role)) {
    throw new ApiError(403, "You do not have access to this organization.", "ORG_FORBIDDEN");
  }
  return membership;
}

export async function createOrganization(input: {
  organizationId: string;
  encryptedProfile: unknown;
  vaultPublicKey: string;
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
    await transaction.insert(auditEvents).values({
      id: eventId(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "organization.created",
      subjectId: input.organizationId,
      metadata: { sessionId: input.principal.sessionId },
    });
    return organization;
  });
}

export async function createEncryptedRun(input: EncryptedRunCreate, principal: AuthenticatedPrincipal) {
  await requireOrganizationRole(input.organizationId, principal, ["admin", "operator"]);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await transaction.insert(vaultRecords).values({
      id: input.id,
      organizationId: input.organizationId,
      recordType: "payroll-run",
      revision: input.revision,
      ciphertext: input.ciphertext,
      envelope: input.envelope,
      createdBy: principal.principalId,
    });
    const [run] = await transaction
      .insert(payrollRuns)
      .values({
        id: input.id,
        organizationId: input.organizationId,
        cycleId: input.cycleId,
        revision: input.revision,
        dueAt: new Date(input.dueAt),
        manifestRoot: input.manifestRoot,
        runNullifier: input.runNullifier,
      })
      .returning();
    await transaction.insert(auditEvents).values({
      id: eventId(),
      organizationId: input.organizationId,
      actorId: principal.principalId,
      action: "payroll_run.created",
      subjectId: input.id,
      metadata: { revision: input.revision },
    });
    return run;
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
      manifestRoot: payrollRuns.manifestRoot,
      runNullifier: payrollRuns.runNullifier,
      transactionHash: payrollRuns.transactionHash,
      updatedAt: payrollRuns.updatedAt,
    })
    .from(payrollRuns)
    .where(eq(payrollRuns.organizationId, organizationId))
    .orderBy(desc(payrollRuns.dueAt));
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
    .select({ ciphertext: vaultRecords.ciphertext, envelope: vaultRecords.envelope })
    .from(vaultRecords)
    .where(
      and(
        eq(vaultRecords.organizationId, run.organizationId),
        eq(vaultRecords.id, run.id),
        eq(vaultRecords.revision, run.revision),
      ),
    )
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
  const [existing] = await database.select().from(payrollRuns).where(eq(payrollRuns.id, input.runId)).limit(1);
  if (!existing) throw new ApiError(404, "Payroll run not found.", "RUN_NOT_FOUND");
  await requireOrganizationRole(existing.organizationId, input.principal, ["admin", "operator"]);
  assertPayrollTransition(existing.state, input.state);

  return database.transaction(async (transaction) => {
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
      metadata: { from: existing.state, to: input.state },
    });
    return run;
  });
}

export async function storeProofPackage(proofPackage: ProofPackage, principal: AuthenticatedPrincipal) {
  await requireOrganizationRole(proofPackage.organizationId, principal, ["admin", "operator", "reviewer"]);
  const database = getDatabase();
  const [run] = await database
    .select({ organizationId: payrollRuns.organizationId })
    .from(payrollRuns)
    .where(eq(payrollRuns.id, proofPackage.runId))
    .limit(1);
  if (!run || run.organizationId !== proofPackage.organizationId) {
    throw new ApiError(404, "Payroll run not found in this organization.", "RUN_NOT_FOUND");
  }
  const [stored] = await database
    .insert(proofBundles)
    .values({
      id: eventId(),
      runId: proofPackage.runId,
      organizationId: proofPackage.organizationId,
      proofType: proofPackage.proofType,
      proofVersion: proofPackage.proofVersion,
      proofPackage,
    })
    .returning({ id: proofBundles.id, createdAt: proofBundles.createdAt });
  return stored;
}

export async function registerAgentCapability(
  signedCapability: SignedCapability,
  principal: AuthenticatedPrincipal,
) {
  const { capability } = signedCapability;
  await requireOrganizationRole(capability.organizationId, principal, ["admin"]);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [stored] = await transaction
      .insert(agentCapabilities)
      .values({
        id: capability.id,
        organizationId: capability.organizationId,
        principalId: capability.principalId,
        capabilityHash: hashCapability(capability),
        policy: signedCapability,
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
      metadata: { principalId: capability.principalId, capabilityHash: stored.capabilityHash },
    });
    return stored;
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
  return stored.policy as SignedCapability;
}

export async function revokeAgentCapability(capabilityId: string, principal: AuthenticatedPrincipal) {
  const database = getDatabase();
  const [stored] = await database
    .select()
    .from(agentCapabilities)
    .where(eq(agentCapabilities.id, capabilityId))
    .limit(1);
  if (!stored) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
  await requireOrganizationRole(stored.organizationId, principal, ["admin"]);
  if (stored.revokedAt) return { id: stored.id, revokedAt: stored.revokedAt };

  return database.transaction(async (transaction) => {
    const [revoked] = await transaction
      .update(agentCapabilities)
      .set({ revokedAt: new Date() })
      .where(and(eq(agentCapabilities.id, capabilityId), eq(agentCapabilities.organizationId, stored.organizationId)))
      .returning({ id: agentCapabilities.id, revokedAt: agentCapabilities.revokedAt });
    await transaction.insert(auditEvents).values({
      id: eventId(),
      organizationId: stored.organizationId,
      actorId: principal.principalId,
      action: "agent_capability.revoked",
      subjectId: capabilityId,
      metadata: { capabilityHash: stored.capabilityHash },
    });
    return revoked;
  });
}
