import "server-only";

import { and, desc, eq, inArray, isNull, or } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  wageRemediationCreateSchema,
  type WageRemediationCreate,
} from "@/lib/domain/wage-remediation";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  auditEvents,
  organizationMembers,
  proofBundles,
  settlements,
  vaultRecords,
  wageRemediations,
  workerClaims,
} from "./schema";

const MAXIMUM_JAVASCRIPT_DATE_SECONDS = 253_402_300_799n;
const ACTIVE_STATES = [
  "prepared",
  "proved",
  "authorization_pending",
  "authorized",
  "payment_pending",
  "payment_confirmed",
] as const;

function canonicalCommitment(value: string): string {
  return "0x" + BigInt(value).toString(16).padStart(64, "0");
}

function expiresAt(value: string): Date {
  const seconds = BigInt(value);
  if (seconds > MAXIMUM_JAVASCRIPT_DATE_SECONDS) {
    throw new ApiError(
      400,
      "Remediation expiry is outside PAYO's supported date range.",
      "REMEDIATION_EXPIRY_INVALID",
    );
  }
  return new Date(Number(seconds) * 1_000);
}

function publicRemediation(
  remediation: typeof wageRemediations.$inferSelect,
  envelope: unknown,
) {
  return {
    id: remediation.id,
    workerClaimId: remediation.workerClaimId,
    organizationId: remediation.organizationId,
    runId: remediation.runId,
    claimantPrincipalId: remediation.claimantPrincipalId,
    proofBundleId: remediation.proofBundleId,
    claimSubjectNullifier: remediation.claimSubjectNullifier,
    claimFactCommitment: remediation.claimFactCommitment,
    remediationSubjectNullifier: remediation.remediationSubjectNullifier,
    remediationFactCommitment: remediation.remediationFactCommitment,
    actionCommitment: remediation.actionCommitment,
    fxRoot: remediation.fxRoot,
    validityExpiresAt: remediation.validityExpiresAt.toISOString(),
    state: remediation.state,
    settlementId: remediation.settlementId,
    authorizedAt: remediation.authorizedAt?.toISOString() ?? null,
    paymentConfirmedAt: remediation.paymentConfirmedAt?.toISOString() ?? null,
    reconciledAt: remediation.reconciledAt?.toISOString() ?? null,
    lastErrorCode: remediation.lastErrorCode,
    lastErrorMessage: remediation.lastErrorMessage,
    createdAt: remediation.createdAt.toISOString(),
    updatedAt: remediation.updatedAt.toISOString(),
    envelope,
  };
}

export async function createWageRemediation(input: {
  remediation: WageRemediationCreate;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const remediation = wageRemediationCreateSchema.parse(input.remediation);
  const now = input.now ?? new Date();
  const expiry = expiresAt(remediation.validityExpiry);
  const remainingMs = expiry.getTime() - now.getTime();
  if (remainingMs <= 120_000 || remainingMs > 3_660_000) {
    throw new ApiError(
      409,
      "Remediation must retain 260 minutes of safe authorization time.",
      "REMEDIATION_EXPIRY_INVALID",
    );
  }
  const envelopeHash = hashCanonicalJson(remediation.envelope);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [membership] = await transaction.select({
      role: organizationMembers.role,
    }).from(organizationMembers).where(and(
      eq(organizationMembers.organizationId, remediation.organizationId),
      eq(organizationMembers.principalId, input.principal.principalId),
      isNull(organizationMembers.revokedAt),
    )).limit(1).for("update");
    if (!membership || !["admin", "operator"].includes(membership.role)) {
      throw new ApiError(
        403,
        "Only an active employer administrator can prepare remediation.",
        "ORG_FORBIDDEN",
      );
    }

    const [claimRoute] = await transaction.select({
      claim: workerClaims,
      proofType: proofBundles.proofType,
      proofVersion: proofBundles.proofVersion,
      verificationState: proofBundles.verificationState,
      verificationTransactionHash: proofBundles.verificationTransactionHash,
    }).from(workerClaims).innerJoin(
      proofBundles,
      eq(proofBundles.id, workerClaims.proofBundleId),
    ).where(eq(workerClaims.id, remediation.workerClaimId))
      .limit(1)
      .for("update");
    if (!claimRoute) {
      throw new ApiError(404, "Accepted worker claim not found.", "WORKER_CLAIM_NOT_FOUND");
    }
    const claim = claimRoute.claim;
    if (
      claim.organizationId !== remediation.organizationId
      || claim.runId !== remediation.runId
      || claim.state !== "accepted"
      || claimRoute.proofType !== "wage_claim"
      || claimRoute.proofVersion !== "6"
      || claimRoute.verificationState !== "onchain_verified"
      || !claimRoute.verificationTransactionHash
      || BigInt(claim.claimSubjectNullifier) !== BigInt(remediation.claimSubjectNullifier)
      || BigInt(claim.claimFactCommitment) !== BigInt(remediation.claimFactCommitment)
    ) {
      throw new ApiError(
        409,
        "Remediation requires one exact on-chain accepted Claim v6 fact.",
        "REMEDIATION_CLAIM_MISMATCH",
      );
    }

    const activeEmployers = await transaction.select({
      principalId: organizationMembers.principalId,
    }).from(organizationMembers).where(and(
      eq(organizationMembers.organizationId, remediation.organizationId),
      isNull(organizationMembers.revokedAt),
      or(
        eq(organizationMembers.role, "admin"),
        eq(organizationMembers.role, "operator"),
      ),
    ));
    const employerIds = new Set(activeEmployers.map(({ principalId }) => principalId));
    const recipientIds = remediation.envelope.wrappedKeys.map(
      ({ principalId }) => principalId,
    );
    const claimantCount = recipientIds.filter(
      (principalId) => principalId === claim.claimantPrincipalId,
    ).length;
    const employerRecipients = recipientIds.filter(
      (principalId) => principalId !== claim.claimantPrincipalId,
    );
    if (
      claimantCount !== 1
      || !employerRecipients.includes(input.principal.principalId)
      || employerRecipients.some((principalId) => !employerIds.has(principalId))
    ) {
      throw new ApiError(
        400,
        "Remediation must be encrypted only to its claimant and active employer administrators.",
        "REMEDIATION_RECIPIENTS_INVALID",
      );
    }

    const [existing] = await transaction.select().from(wageRemediations)
      .where(eq(wageRemediations.id, remediation.id))
      .limit(1)
      .for("update");
    const [storedVault] = await transaction.select({
      envelopeHash: vaultRecords.envelopeHash,
      recordType: vaultRecords.recordType,
      revision: vaultRecords.revision,
      envelope: vaultRecords.envelope,
    }).from(vaultRecords).where(and(
      eq(vaultRecords.organizationId, remediation.organizationId),
      eq(vaultRecords.id, remediation.id),
      isNull(vaultRecords.supersededAt),
    )).limit(1).for("update");
    if (existing || storedVault) {
      const matches = existing?.workerClaimId === remediation.workerClaimId
        && existing.organizationId === remediation.organizationId
        && existing.runId === remediation.runId
        && existing.claimantPrincipalId === claim.claimantPrincipalId
        && existing.proofBundleId === remediation.proofBundleId
        && BigInt(existing.claimSubjectNullifier) === BigInt(remediation.claimSubjectNullifier)
        && BigInt(existing.claimFactCommitment) === BigInt(remediation.claimFactCommitment)
        && BigInt(existing.remediationSubjectNullifier)
          === BigInt(remediation.remediationSubjectNullifier)
        && BigInt(existing.remediationFactCommitment)
          === BigInt(remediation.remediationFactCommitment)
        && BigInt(existing.actionCommitment) === BigInt(remediation.actionCommitment)
        && BigInt(existing.fxRoot) === BigInt(remediation.fxRoot)
        && existing.validityExpiresAt.getTime() === expiry.getTime()
        && storedVault?.recordType === "wage-remediation-v2"
        && storedVault.revision === 1
        && storedVault.envelopeHash === envelopeHash;
      if (!matches || !existing || !storedVault) {
        throw new ApiError(
          409,
          "Remediation ID already contains different immutable evidence.",
          "REMEDIATION_CONFLICT",
        );
      }
      return { ...publicRemediation(existing, storedVault.envelope), replayed: true };
    }

    const [active] = await transaction.select({ id: wageRemediations.id })
      .from(wageRemediations)
      .where(and(
        eq(wageRemediations.workerClaimId, claim.id),
        inArray(wageRemediations.state, [...ACTIVE_STATES]),
      ))
      .limit(1)
      .for("update");
    if (active) {
      throw new ApiError(
        409,
        "This claim already has an active remediation attempt; recover or expire it first.",
        "REMEDIATION_ATTEMPT_ACTIVE",
      );
    }
    const [duplicate] = await transaction.select({ id: wageRemediations.id })
      .from(wageRemediations)
      .where(or(
        eq(wageRemediations.proofBundleId, remediation.proofBundleId),
        eq(
          wageRemediations.remediationSubjectNullifier,
          canonicalCommitment(remediation.remediationSubjectNullifier),
        ),
        eq(
          wageRemediations.actionCommitment,
          canonicalCommitment(remediation.actionCommitment),
        ),
      ))
      .limit(1)
      .for("update");
    if (duplicate) {
      throw new ApiError(
        409,
        "This remediation proof subject or private action is already registered.",
        "REMEDIATION_DUPLICATE",
      );
    }

    await transaction.insert(vaultRecords).values({
      id: remediation.id,
      organizationId: remediation.organizationId,
      recordType: "wage-remediation-v2",
      revision: 1,
      ciphertext: remediation.envelope.ciphertext,
      envelope: remediation.envelope,
      envelopeHash,
      createdBy: input.principal.principalId,
      createdAt: now,
    });
    const [created] = await transaction.insert(wageRemediations).values({
      id: remediation.id,
      workerClaimId: remediation.workerClaimId,
      organizationId: remediation.organizationId,
      runId: remediation.runId,
      claimantPrincipalId: claim.claimantPrincipalId,
      proofBundleId: remediation.proofBundleId,
      claimSubjectNullifier: canonicalCommitment(remediation.claimSubjectNullifier),
      claimFactCommitment: canonicalCommitment(remediation.claimFactCommitment),
      remediationSubjectNullifier: canonicalCommitment(
        remediation.remediationSubjectNullifier,
      ),
      remediationFactCommitment: canonicalCommitment(
        remediation.remediationFactCommitment,
      ),
      actionCommitment: canonicalCommitment(remediation.actionCommitment),
      fxRoot: canonicalCommitment(remediation.fxRoot),
      validityExpiresAt: expiry,
      createdBy: input.principal.principalId,
      createdAt: now,
      updatedAt: now,
    }).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: remediation.organizationId,
      actorId: input.principal.principalId,
      action: "wage_remediation.prepared",
      subjectId: remediation.id,
      metadata: {
        runId: remediation.runId,
        workerClaimId: remediation.workerClaimId,
        proofBundleId: remediation.proofBundleId,
        remediationSubjectNullifier: remediation.remediationSubjectNullifier,
        remediationFactCommitment: remediation.remediationFactCommitment,
        actionCommitment: remediation.actionCommitment,
        validityExpiresAt: expiry.toISOString(),
      },
    });
    return { ...publicRemediation(created, remediation.envelope), replayed: false };
  });
}

export async function listWageRemediations(input: {
  principal: AuthenticatedPrincipal;
  organizationId?: string;
}) {
  if (input.organizationId) {
    await requireOrganizationRole(
      input.organizationId,
      input.principal,
      ["admin", "operator"],
    );
  }
  const predicate = input.organizationId
    ? eq(wageRemediations.organizationId, input.organizationId)
    : eq(wageRemediations.claimantPrincipalId, input.principal.principalId);
  const rows = await getDatabase().select({
    remediation: wageRemediations,
    envelope: vaultRecords.envelope,
  }).from(wageRemediations).innerJoin(vaultRecords, and(
    eq(vaultRecords.organizationId, wageRemediations.organizationId),
    eq(vaultRecords.id, wageRemediations.id),
    eq(vaultRecords.recordType, "wage-remediation-v2"),
    isNull(vaultRecords.supersededAt),
  )).where(predicate).orderBy(desc(wageRemediations.createdAt));
  return rows.map(({ remediation, envelope }) =>
    publicRemediation(remediation, envelope));
}

export async function getWageRemediation(
  remediationId: string,
  principal: AuthenticatedPrincipal,
) {
  const [row] = await getDatabase().select({
    remediation: wageRemediations,
    envelope: vaultRecords.envelope,
  }).from(wageRemediations).innerJoin(vaultRecords, and(
    eq(vaultRecords.organizationId, wageRemediations.organizationId),
    eq(vaultRecords.id, wageRemediations.id),
    eq(vaultRecords.recordType, "wage-remediation-v2"),
    isNull(vaultRecords.supersededAt),
  )).where(eq(wageRemediations.id, remediationId)).limit(1);
  if (!row) {
    throw new ApiError(404, "Wage remediation not found.", "REMEDIATION_NOT_FOUND");
  }
  if (row.remediation.claimantPrincipalId !== principal.principalId) {
    await requireOrganizationRole(
      row.remediation.organizationId,
      principal,
      ["admin", "operator"],
    );
  }
  return publicRemediation(row.remediation, row.envelope);
}

export async function attachWageRemediationSettlement(input: {
  remediationId: string;
  settlementId: string;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const database = getDatabase();
  const now = input.now ?? new Date();
  return database.transaction(async (transaction) => {
    const [remediation] = await transaction.select().from(wageRemediations)
      .where(eq(wageRemediations.id, input.remediationId))
      .limit(1)
      .for("update");
    if (!remediation) {
      throw new ApiError(404, "Wage remediation not found.", "REMEDIATION_NOT_FOUND");
    }
    await requireOrganizationRole(
      remediation.organizationId,
      input.principal,
      ["admin", "operator"],
    );
    const [settlement] = await transaction.select().from(settlements)
      .where(eq(settlements.id, input.settlementId))
      .limit(1)
      .for("update");
    if (
      !settlement
      || settlement.organizationId !== remediation.organizationId
      || settlement.runId !== remediation.runId
      || settlement.workflowType !== "wage_remediation"
      || settlement.subjectRecordId !== remediation.id
    ) {
      throw new ApiError(
        409,
        "Private payment intent does not match this Remediation v7 attempt.",
        "REMEDIATION_SETTLEMENT_MISMATCH",
      );
    }
    if (remediation.settlementId && remediation.settlementId !== settlement.id) {
      throw new ApiError(
        409,
        "Remediation is already bound to another private payment.",
        "REMEDIATION_SETTLEMENT_CONFLICT",
      );
    }
    if (!["authorized", "payment_pending"].includes(remediation.state)) {
      throw new ApiError(
        409,
        "Remediation payment requires an active on-chain authorization.",
        "REMEDIATION_STATE_INVALID",
      );
    }
    const [updated] = await transaction.update(wageRemediations).set({
      settlementId: settlement.id,
      state: "payment_pending",
      updatedAt: now,
    }).where(eq(wageRemediations.id, remediation.id)).returning();
    return publicRemediation(updated, (
      await transaction.select({ envelope: vaultRecords.envelope })
        .from(vaultRecords)
        .where(and(
          eq(vaultRecords.organizationId, remediation.organizationId),
          eq(vaultRecords.id, remediation.id),
          eq(vaultRecords.recordType, "wage-remediation-v2"),
          isNull(vaultRecords.supersededAt),
        ))
        .limit(1)
    )[0]?.envelope);
  });
}
