import "server-only";

import { and, desc, eq, isNull, or } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  workerClaimCreateSchema,
  type WorkerClaimCreate,
} from "@/lib/domain/worker-claim";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  auditEvents,
  obligationClaimAccessGrants,
  organizationMembers,
  vaultRecords,
  workerClaims,
} from "./schema";

function publicWorkerClaim(
  claim: typeof workerClaims.$inferSelect,
  envelope: unknown,
) {
  return {
    id: claim.id,
    claimAccessGrantId: claim.claimAccessGrantId,
    organizationId: claim.organizationId,
    runId: claim.runId,
    claimantPrincipalId: claim.claimantPrincipalId,
    proofBundleId: claim.proofBundleId,
    claimSubjectNullifier: claim.claimSubjectNullifier,
    claimFactCommitment: claim.claimFactCommitment,
    state: claim.state,
    createdAt: claim.createdAt.toISOString(),
    updatedAt: claim.updatedAt.toISOString(),
    envelope,
  };
}

export async function createWorkerClaim(input: {
  claim: WorkerClaimCreate;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const claim = workerClaimCreateSchema.parse(input.claim);
  const now = input.now ?? new Date();
  const envelopeHash = hashCanonicalJson(claim.envelope);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [grant] = await transaction.select().from(obligationClaimAccessGrants)
      .where(and(
        eq(obligationClaimAccessGrants.id, claim.claimAccessGrantId),
        eq(obligationClaimAccessGrants.claimantPrincipalId, input.principal.principalId),
        isNull(obligationClaimAccessGrants.revokedAt),
      )).limit(1).for("update");
    if (!grant) {
      throw new ApiError(404, "Worker claim access was not found.", "CLAIM_ACCESS_NOT_FOUND");
    }
    if (grant.organizationId !== claim.organizationId || grant.runId !== claim.runId) {
      throw new ApiError(409, "Worker claim routing differs from its immutable snapshot.", "WORKER_CLAIM_BINDING_MISMATCH");
    }
    const recipients = new Set(claim.envelope.wrappedKeys.map(({ principalId }) => principalId));
    if (!recipients.has(input.principal.principalId)) {
      throw new ApiError(403, "The worker claim is not encrypted to its claimant.", "WORKER_CLAIM_ENVELOPE_FORBIDDEN");
    }
    const employerRecipients = [...recipients].filter((id) => id !== input.principal.principalId);
    const activeEmployers = await transaction.select({ principalId: organizationMembers.principalId })
      .from(organizationMembers).where(and(
        eq(organizationMembers.organizationId, claim.organizationId),
        isNull(organizationMembers.revokedAt),
        or(eq(organizationMembers.role, "admin"), eq(organizationMembers.role, "operator")),
      ));
    const activeEmployerIds = new Set(activeEmployers.map(({ principalId }) => principalId));
    if (
      employerRecipients.length < 1
      || employerRecipients.some((principalId) => !activeEmployerIds.has(principalId))
    ) {
      throw new ApiError(
        400,
        "The worker claim must be encrypted only to its claimant and an active employer administrator.",
        "WORKER_CLAIM_RECIPIENTS_INVALID",
      );
    }

    const [existing] = await transaction.select().from(workerClaims)
      .where(eq(workerClaims.id, claim.id)).limit(1).for("update");
    const [vault] = await transaction.select({
      envelopeHash: vaultRecords.envelopeHash,
      recordType: vaultRecords.recordType,
      revision: vaultRecords.revision,
      envelope: vaultRecords.envelope,
    }).from(vaultRecords).where(and(
      eq(vaultRecords.organizationId, claim.organizationId),
      eq(vaultRecords.id, claim.id),
      isNull(vaultRecords.supersededAt),
    )).limit(1).for("update");
    if (existing || vault) {
      const matches = existing?.claimAccessGrantId === claim.claimAccessGrantId
        && existing.organizationId === claim.organizationId
        && existing.runId === claim.runId
        && existing.claimantPrincipalId === input.principal.principalId
        && existing.proofBundleId === claim.proofBundleId
        && BigInt(existing.claimSubjectNullifier) === BigInt(claim.claimSubjectNullifier)
        && BigInt(existing.claimFactCommitment) === BigInt(claim.claimFactCommitment)
        && vault?.recordType === "wage-claim-v2"
        && vault.revision === 1
        && vault.envelopeHash === envelopeHash;
      if (!matches || !existing || !vault) {
        throw new ApiError(409, "Worker claim ID already contains different immutable evidence.", "WORKER_CLAIM_CONFLICT");
      }
      return { ...publicWorkerClaim(existing, vault.envelope), replayed: true };
    }
    const [duplicate] = await transaction.select({ id: workerClaims.id })
      .from(workerClaims).where(or(
        eq(workerClaims.proofBundleId, claim.proofBundleId),
        eq(workerClaims.claimSubjectNullifier, claim.claimSubjectNullifier),
      )).limit(1).for("update");
    if (duplicate) {
      throw new ApiError(409, "This deterministic claim subject already has a durable record.", "WORKER_CLAIM_DUPLICATE");
    }
    await transaction.insert(vaultRecords).values({
      id: claim.id,
      organizationId: claim.organizationId,
      recordType: "wage-claim-v2",
      revision: 1,
      ciphertext: claim.envelope.ciphertext,
      envelope: claim.envelope,
      envelopeHash,
      createdBy: input.principal.principalId,
      createdAt: now,
    });
    const [created] = await transaction.insert(workerClaims).values({
      id: claim.id,
      claimAccessGrantId: claim.claimAccessGrantId,
      organizationId: claim.organizationId,
      runId: claim.runId,
      claimantPrincipalId: input.principal.principalId,
      proofBundleId: claim.proofBundleId,
      claimSubjectNullifier: claim.claimSubjectNullifier,
      claimFactCommitment: claim.claimFactCommitment,
      createdAt: now,
      updatedAt: now,
    }).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: claim.organizationId,
      actorId: input.principal.principalId,
      action: "worker_claim.prepared",
      subjectId: claim.id,
      metadata: {
        runId: claim.runId,
        claimAccessGrantId: claim.claimAccessGrantId,
        proofBundleId: claim.proofBundleId,
        claimSubjectNullifier: claim.claimSubjectNullifier,
        claimFactCommitment: claim.claimFactCommitment,
      },
    });
    return { ...publicWorkerClaim(created, claim.envelope), replayed: false };
  });
}

export async function listWorkerClaims(input: {
  principal: AuthenticatedPrincipal;
  organizationId?: string;
}) {
  if (input.organizationId) {
    await requireOrganizationRole(input.organizationId, input.principal, ["admin", "operator"]);
  }
  const predicate = input.organizationId
    ? eq(workerClaims.organizationId, input.organizationId)
    : eq(workerClaims.claimantPrincipalId, input.principal.principalId);
  const rows = await getDatabase().select({
    claim: workerClaims,
    envelope: vaultRecords.envelope,
  }).from(workerClaims).innerJoin(vaultRecords, and(
    eq(vaultRecords.organizationId, workerClaims.organizationId),
    eq(vaultRecords.id, workerClaims.id),
    eq(vaultRecords.recordType, "wage-claim-v2"),
    isNull(vaultRecords.supersededAt),
  )).where(predicate).orderBy(desc(workerClaims.createdAt));
  return rows.map(({ claim, envelope }) => publicWorkerClaim(claim, envelope));
}

export async function getWorkerClaim(
  claimId: string,
  principal: AuthenticatedPrincipal,
) {
  const [row] = await getDatabase().select({
    claim: workerClaims,
    envelope: vaultRecords.envelope,
  }).from(workerClaims).innerJoin(vaultRecords, and(
    eq(vaultRecords.organizationId, workerClaims.organizationId),
    eq(vaultRecords.id, workerClaims.id),
    eq(vaultRecords.recordType, "wage-claim-v2"),
    isNull(vaultRecords.supersededAt),
  )).where(eq(workerClaims.id, claimId)).limit(1);
  if (!row) throw new ApiError(404, "Worker claim not found.", "WORKER_CLAIM_NOT_FOUND");
  if (row.claim.claimantPrincipalId !== principal.principalId) {
    await requireOrganizationRole(row.claim.organizationId, principal, ["admin", "operator"]);
  }
  return publicWorkerClaim(row.claim, row.envelope);
}
