import "server-only";

import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import {
  exceptionProofBundleMetadataSchema,
  type EncryptedExceptionProofBundleCreate,
  type EncryptedPayoProofBundleCreate,
  type EncryptedPayrollIntegrityBundleCreate,
} from "@/lib/domain/proof-bundle";
import { assertOperationalMetadataSafe } from "@/lib/domain/privacy";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import type { PayoDeploymentConfig } from "@/lib/server/payo-deployment";
import { getDatabase } from "./db";
import {
  auditEvents,
  employerStatements,
  exceptionAuthorizationJobs,
  obligationClaimAccessGrants,
  obligationSnapshotPlans,
  payrollStatementEvidenceGrants,
  organizationMembers,
  organizations,
  payrollRuns,
  proofBundles,
  settlements,
  vaultRecords,
  wageRemediations,
  workerClaims,
} from "./schema";

const U128_LIMIT = 1n << 128n;

function combinedCommitment(highValue: string, lowValue: string, label: string): `0x${string}` {
  let high: bigint;
  let low: bigint;
  try {
    high = BigInt(highValue);
    low = BigInt(lowValue);
  } catch {
    throw new ApiError(400, `${label} limbs are invalid.`, "PROOF_PUBLIC_INPUT_INVALID");
  }
  if (high < 0n || high >= U128_LIMIT || low < 0n || low >= U128_LIMIT) {
    throw new ApiError(400, `${label} limbs exceed u128.`, "PROOF_PUBLIC_INPUT_INVALID");
  }
  return `0x${((high << 128n) | low).toString(16).padStart(64, "0")}`;
}

function assertPayrollDeploymentBound(
  input: EncryptedPayrollIntegrityBundleCreate,
  deployment: PayoDeploymentConfig,
) {
  if (BigInt(input.commonInputs.chainId) !== BigInt(deployment.chainId)) {
    throw new ApiError(400, "Proof is bound to a different Starknet chain.", "PROOF_CHAIN_MISMATCH");
  }
  if (BigInt(input.commonInputs.sealAddress) !== BigInt(deployment.sealAddress)) {
    throw new ApiError(400, "Proof is bound to a different PAYO seal.", "PROOF_SEAL_MISMATCH");
  }
}

function assertExceptionDeploymentBound(
  input: EncryptedExceptionProofBundleCreate,
  deployment: PayoDeploymentConfig,
) {
  if (BigInt(input.publicInputs.chainId) !== BigInt(deployment.chainId)) {
    throw new ApiError(400, "Exception proof is bound to a different Starknet chain.", "PROOF_CHAIN_MISMATCH");
  }
  if (BigInt(input.publicInputs.sealAddress) !== BigInt(deployment.sealAddress)) {
    throw new ApiError(400, "Exception proof is bound to a different PAYO seal.", "PROOF_SEAL_MISMATCH");
  }
}

function assertSafeExceptionProofWindow(bundle: EncryptedExceptionProofBundleCreate) {
  const validityStart = Number(bundle.publicInputs.validityStart);
  const validityExpiry = Number(bundle.publicInputs.validityExpiry);
  const nowSeconds = Math.floor(Date.now() / 1_000);
  if (
    !Number.isSafeInteger(validityStart)
    || !Number.isSafeInteger(validityExpiry)
    || validityStart > nowSeconds + 60
    || validityExpiry <= nowSeconds + 120
    || validityExpiry < validityStart
    || validityExpiry - validityStart > 3_600
  ) {
    throw new ApiError(
      400,
      "The vNext proof validity window is unsafe.",
      "EXCEPTION_PROOF_WINDOW_INVALID",
    );
  }
}

async function storeEncryptedExceptionProofBundle(input: {
  bundle: EncryptedExceptionProofBundleCreate;
  principal: AuthenticatedPrincipal;
  deployment: PayoDeploymentConfig;
}) {
  const { bundle, principal, deployment } = input;
  assertExceptionDeploymentBound(bundle, deployment);
  assertSafeExceptionProofWindow(bundle);
  const envelope = bundle.envelope;
  if (
    envelope.aad.organizationId !== bundle.organizationId
    || envelope.aad.recordType !== "proof-bundle"
    || envelope.aad.recordId !== bundle.id
    || envelope.aad.revision !== bundle.revision
  ) throw new ApiError(400, "Encrypted exception proof AAD does not match storage identity.", "AAD_MISMATCH");
  if (hashCanonicalJson(bundle.publicInputs) !== bundle.publicInputsHash) {
    throw new ApiError(400, "Exception proof public-input digest is inconsistent.", "PROOF_BUNDLE_INVALID");
  }
  if (!envelope.wrappedKeys.some(({ principalId }) => principalId === principal.principalId)) {
    throw new ApiError(
      403,
      "The exception proof is not encrypted to its submitting principal.",
      "PROOF_ENVELOPE_FORBIDDEN",
    );
  }
  const agreementRoot = combinedCommitment(
    bundle.publicInputs.agreementRootHigh,
    bundle.publicInputs.agreementRootLow,
    "Agreement root",
  );
  const policyRoot = combinedCommitment(
    bundle.publicInputs.policyRootHigh,
    bundle.publicInputs.policyRootLow,
    "Policy root",
  );
  const manifestRoot = combinedCommitment(
    bundle.publicInputs.manifestRootHigh,
    bundle.publicInputs.manifestRootLow,
    "Manifest root",
  );
  const fxRoot = combinedCommitment(
    bundle.publicInputs.fxRootHigh,
    bundle.publicInputs.fxRootLow,
    "FX root",
  );
  const subjectNullifier = combinedCommitment(
    bundle.publicInputs.subjectNullifierHigh,
    bundle.publicInputs.subjectNullifierLow,
    "Subject nullifier",
  );
  const parentNullifier = combinedCommitment(
    bundle.publicInputs.parentNullifierHigh,
    bundle.publicInputs.parentNullifierLow,
    "Parent nullifier",
  );
  const factCommitment = combinedCommitment(
    bundle.publicInputs.factCommitmentHigh,
    bundle.publicInputs.factCommitmentLow,
    "Fact commitment",
  );
  const parentFactCommitment = combinedCommitment(
    bundle.publicInputs.parentFactCommitmentHigh,
    bundle.publicInputs.parentFactCommitmentLow,
    "Parent fact commitment",
  );
  const metadata = {
    schemaVersion: 2 as const,
    envelopeRecordId: bundle.id,
    envelopeRevision: bundle.revision,
    proofType: bundle.proofType,
    subjectRecordId: bundle.subjectRecordId,
    proofVersion: bundle.proofVersion,
    circuitSha256: bundle.circuitSha256,
    verificationKeySha256: bundle.verificationKeySha256,
    publicInputsHash: bundle.publicInputsHash,
    publicInputs: bundle.publicInputs,
    proofCalldataHash: bundle.proofCalldataHash,
  };
  assertOperationalMetadataSafe(metadata);
  const envelopeHash = hashCanonicalJson(envelope);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [organization] = await transaction
      .select({ recoveryState: organizations.recoveryState })
      .from(organizations)
      .where(eq(organizations.id, bundle.organizationId))
      .limit(1);
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    if (organization.recoveryState === "required") {
      throw new ApiError(409, "Configure vault recovery before proving an exception.", "VAULT_RECOVERY_REQUIRED");
    }
    const [run] = await transaction
      .select()
      .from(payrollRuns)
      .where(eq(payrollRuns.id, bundle.runId))
      .limit(1)
      .for("update");
    if (!run || run.organizationId !== bundle.organizationId) {
      throw new ApiError(404, "Payroll run not found in this organization.", "RUN_NOT_FOUND");
    }
    let routedWorkerClaim: typeof workerClaims.$inferSelect | undefined;
    let routedWageRemediation: typeof wageRemediations.$inferSelect | undefined;
    if (bundle.proofType === "wage_claim") {
      const [route] = await transaction.select({
        claim: workerClaims,
        grantRevokedAt: obligationClaimAccessGrants.revokedAt,
      }).from(workerClaims).innerJoin(
        obligationClaimAccessGrants,
        eq(obligationClaimAccessGrants.id, workerClaims.claimAccessGrantId),
      ).where(and(
        eq(workerClaims.id, bundle.subjectRecordId),
        eq(workerClaims.claimantPrincipalId, principal.principalId),
      )).limit(1).for("update");
      if (!route || route.grantRevokedAt) {
        throw new ApiError(
          403,
          "This principal does not own active claim access for the proof.",
          "WORKER_CLAIM_FORBIDDEN",
        );
      }
      routedWorkerClaim = route.claim;
      if (
        route.claim.organizationId !== bundle.organizationId
        || route.claim.runId !== bundle.runId
        || route.claim.proofBundleId !== bundle.id
        || BigInt(route.claim.claimSubjectNullifier) !== BigInt(subjectNullifier)
        || BigInt(route.claim.claimFactCommitment) !== BigInt(factCommitment)
      ) {
        throw new ApiError(
          409,
          "The Claim v6 proof differs from its immutable worker-owned claim record.",
          "WORKER_CLAIM_BINDING_MISMATCH",
        );
      }
      if (!run.obligationSnapshotPlanId || !run.runNullifier) {
        throw new ApiError(409, "Claim v6 requires its registered obligation snapshot.", "CLAIM_SNAPSHOT_MISSING");
      }
      const [snapshot] = await transaction.select().from(obligationSnapshotPlans).where(and(
        eq(obligationSnapshotPlans.id, run.obligationSnapshotPlanId),
        eq(obligationSnapshotPlans.runId, run.id),
        eq(obligationSnapshotPlans.organizationId, run.organizationId),
      )).limit(1).for("update");
      if (
        !snapshot
        || !["registered", "consumed"].includes(snapshot.state)
        || BigInt(snapshot.runNullifier) !== BigInt(parentNullifier)
        || BigInt(snapshot.agreementRoot) !== BigInt(agreementRoot)
        || BigInt(snapshot.policyRoot) !== BigInt(policyRoot)
      ) {
        throw new ApiError(409, "Claim v6 does not match its registered obligation snapshot.", "CLAIM_SNAPSHOT_MISMATCH");
      }
      const usesSnapshotAbsence =
        BigInt(parentFactCommitment) === BigInt(snapshot.snapshotFact);
      if (usesSnapshotAbsence) {
        const [registeredStatement] = await transaction.select({
          id: employerStatements.id,
        }).from(employerStatements).where(and(
          eq(employerStatements.runId, run.id),
          eq(employerStatements.organizationId, run.organizationId),
          eq(employerStatements.state, "registered"),
        )).limit(1).for("update");
        if (
          BigInt(manifestRoot) !== 0n
          || BigInt(fxRoot) !== 0n
          || run.state !== "draft"
          || run.transactionHash !== null
          || registeredStatement
        ) {
          throw new ApiError(
            409,
            "Missing-obligation evidence requires an unpaid payday with no registered employer statement.",
            "CLAIM_EVIDENCE_CONFLICT",
          );
        }
      } else {
        const [statementRoute] = await transaction.select({
          statement: employerStatements,
          evidenceRevokedAt: payrollStatementEvidenceGrants.revokedAt,
          evidenceClaimant: payrollStatementEvidenceGrants.claimantPrincipalId,
        }).from(employerStatements).innerJoin(
          payrollStatementEvidenceGrants,
          and(
            eq(payrollStatementEvidenceGrants.statementId, employerStatements.id),
            eq(payrollStatementEvidenceGrants.claimAccessGrantId, route.claim.claimAccessGrantId),
          ),
        ).where(and(
          eq(employerStatements.statementFact, parentFactCommitment),
          eq(employerStatements.snapshotPlanId, snapshot.id),
          eq(employerStatements.organizationId, run.organizationId),
          eq(employerStatements.runId, run.id),
          eq(employerStatements.state, "registered"),
        )).limit(1).for("update");
        if (
          !statementRoute
          || statementRoute.evidenceRevokedAt
          || statementRoute.evidenceClaimant !== principal.principalId
          || BigInt(statementRoute.statement.ownerAddress) !== BigInt(snapshot.ownerAddress)
          || BigInt(statementRoute.statement.manifestRoot) !== BigInt(manifestRoot)
          || BigInt(statementRoute.statement.fxRoot) !== BigInt(fxRoot)
        ) {
          throw new ApiError(
            409,
            "Claim v6 requires the claimant's exact registered employer-statement evidence.",
            "CLAIM_EVIDENCE_NOT_REGISTERED",
          );
        }
      }
    } else {
      const [membership] = await transaction
        .select({ role: organizationMembers.role })
        .from(organizationMembers)
        .where(and(
          eq(organizationMembers.organizationId, bundle.organizationId),
          eq(organizationMembers.principalId, principal.principalId),
          isNull(organizationMembers.revokedAt),
        ))
        .limit(1)
        .for("update");
      if (!membership || !["admin", "operator"].includes(membership.role)) {
        throw new ApiError(403, "You cannot store this exception proof.", "ORG_FORBIDDEN");
      }
    }
    if (run.agreementRoot && run.agreementRoot.toLowerCase() !== agreementRoot.toLowerCase()) {
      throw new ApiError(409, "Exception proof agreement root does not match its payday.", "PROOF_RUN_MISMATCH");
    }
    if (run.policyRoot && run.policyRoot.toLowerCase() !== policyRoot.toLowerCase()) {
      throw new ApiError(409, "Exception proof policy root does not match its payday.", "PROOF_RUN_MISMATCH");
    }
    if (bundle.proofType === "obligation_snapshot") {
      if (bundle.subjectRecordId !== bundle.runId || !run.runNullifier) {
        throw new ApiError(409, "Obligation snapshot subject does not match its payday.", "PROOF_SUBJECT_MISMATCH");
      }
      if (run.runNullifier.toLowerCase() !== subjectNullifier.toLowerCase() || BigInt(parentNullifier) !== 0n) {
        throw new ApiError(409, "Obligation snapshot nullifier does not match its payday.", "PROOF_RUN_MISMATCH");
      }
      if (!["calculated", "proven"].includes(run.state)) {
        throw new ApiError(409, "An obligation snapshot must be stored before payroll submission.", "EXCEPTION_RUN_STATE_INVALID");
      }
    } else if (bundle.proofType === "wage_remediation") {
      const [route] = await transaction.select({
        remediation: wageRemediations,
        claim: workerClaims,
        claimProof: proofBundles,
      }).from(wageRemediations).innerJoin(
        workerClaims,
        eq(workerClaims.id, wageRemediations.workerClaimId),
      ).innerJoin(
        proofBundles,
        eq(proofBundles.id, workerClaims.proofBundleId),
      ).where(and(
        eq(wageRemediations.id, bundle.subjectRecordId),
        eq(wageRemediations.proofBundleId, bundle.id),
      )).limit(1).for("update");
      if (!route) {
        throw new ApiError(
          404,
          "Durable Remediation v7 subject was not found.",
          "REMEDIATION_NOT_FOUND",
        );
      }
      const claimProof = exceptionProofBundleMetadataSchema.parse(
        route.claimProof.proofPackage,
      );
      const acceptedAgreementRoot = combinedCommitment(
        claimProof.publicInputs.agreementRootHigh,
        claimProof.publicInputs.agreementRootLow,
        "Accepted claim agreement root",
      );
      const acceptedPolicyRoot = combinedCommitment(
        claimProof.publicInputs.policyRootHigh,
        claimProof.publicInputs.policyRootLow,
        "Accepted claim policy root",
      );
      if (
        route.remediation.organizationId !== bundle.organizationId
        || route.remediation.runId !== bundle.runId
        || !["prepared", "proved", "authorization_pending"].includes(
          route.remediation.state,
        )
        || route.claim.state !== "accepted"
        || route.claimProof.proofType !== "wage_claim"
        || route.claimProof.proofVersion !== "6"
        || route.claimProof.verificationState !== "onchain_verified"
        || !route.claimProof.verificationTransactionHash
        || claimProof.proofType !== "wage_claim"
        || claimProof.proofVersion !== "6"
        || BigInt(route.remediation.claimSubjectNullifier) !== BigInt(parentNullifier)
        || BigInt(route.remediation.claimFactCommitment) !== BigInt(parentFactCommitment)
        || BigInt(route.remediation.remediationSubjectNullifier)
          !== BigInt(subjectNullifier)
        || BigInt(route.remediation.remediationFactCommitment)
          !== BigInt(factCommitment)
        || BigInt(route.remediation.actionCommitment) !== BigInt(manifestRoot)
        || BigInt(route.remediation.fxRoot) !== BigInt(fxRoot)
        || BigInt(acceptedAgreementRoot) !== BigInt(agreementRoot)
        || BigInt(acceptedPolicyRoot) !== BigInt(policyRoot)
        || Math.floor(route.remediation.validityExpiresAt.getTime() / 1_000)
          !== Number(bundle.publicInputs.validityExpiry)
      ) {
        throw new ApiError(
          409,
          "Remediation v7 proof differs from its accepted Claim v6 fact or exact private action.",
          "REMEDIATION_BINDING_MISMATCH",
        );
      }
      routedWageRemediation = route.remediation;
    }
    const [existing] = await transaction
      .select()
      .from(proofBundles)
      .where(eq(proofBundles.id, bundle.id))
      .limit(1)
      .for("update");
    if (existing) {
      if (existing.proofHash === envelopeHash) {
        if (routedWorkerClaim?.state === "prepared") {
          await transaction.update(workerClaims).set({
            state: "proved",
            updatedAt: new Date(),
          }).where(eq(workerClaims.id, routedWorkerClaim.id));
        }
        if (routedWageRemediation?.state === "prepared") {
          await transaction.update(wageRemediations).set({
            state: "proved",
            updatedAt: new Date(),
          }).where(eq(wageRemediations.id, routedWageRemediation.id));
        }
        return { ...existing, replayed: true };
      }
      if (
        bundle.proofType === "obligation_snapshot"
        || existing.organizationId !== bundle.organizationId
        || existing.runId !== bundle.runId
        || existing.proofType !== bundle.proofType
        || existing.proofVersion !== bundle.proofVersion
        || existing.subjectRecordId !== bundle.subjectRecordId
        || existing.verificationState !== "locally_verified"
        || existing.verificationTransactionHash
      ) {
        throw new ApiError(409, "This vNext exception proof can no longer be refreshed.", "EXCEPTION_PROOF_REFRESH_FORBIDDEN");
      }
      const previous = existing.proofPackage as {
        schemaVersion?: number;
        envelopeRevision?: number;
        publicInputs?: Record<string, string>;
      };
      const stableInputKeys = [
        "chainId", "sealAddress", "proofVersion", "schemaVersion",
        "agreementRootHigh", "agreementRootLow", "manifestRootHigh", "manifestRootLow",
        "policyRootHigh", "policyRootLow", "fxRootHigh", "fxRootLow",
        "subjectNullifierHigh", "subjectNullifierLow",
        "parentNullifierHigh", "parentNullifierLow",
        "factCommitmentHigh", "factCommitmentLow",
        "parentFactCommitmentHigh", "parentFactCommitmentLow", "shardIndex",
      ];
      if (
        previous.schemaVersion !== 2
        || !previous.publicInputs
        || stableInputKeys.some((key) => previous.publicInputs?.[key] !== metadata.publicInputs[key as keyof typeof metadata.publicInputs])
      ) {
        throw new ApiError(409, "The refreshed vNext proof changed an immutable exception binding.", "EXCEPTION_PROOF_BINDING_CHANGED");
      }
      const [job] = await transaction
        .select()
        .from(exceptionAuthorizationJobs)
        .where(eq(exceptionAuthorizationJobs.proofBundleId, bundle.id))
        .limit(1)
        .for("update");
      if (job && (
        job.state === "complete"
        || job.state === "leased"
        || job.transactionHash !== null
      )) {
        throw new ApiError(
          409,
          "The vNext proof cannot change after its on-chain authorization started.",
          "EXCEPTION_PROOF_REFRESH_FORBIDDEN",
        );
      }
      const [latestVault] = await transaction
        .select({ revision: vaultRecords.revision })
        .from(vaultRecords)
        .where(and(
          eq(vaultRecords.organizationId, bundle.organizationId),
          eq(vaultRecords.id, bundle.id),
          eq(vaultRecords.recordType, "proof-bundle"),
        ))
        .orderBy(desc(vaultRecords.revision))
        .limit(1)
        .for("update");
      if (
        !latestVault
        || bundle.revision !== latestVault.revision + 1
        || bundle.revision !== (previous.envelopeRevision ?? 0) + 1
      ) {
        throw new ApiError(409, "The vNext proof refresh revision is stale.", "EXCEPTION_PROOF_REVISION_CONFLICT");
      }
      const refreshedAt = new Date();
      if (job && job.state === "pending") {
        await transaction.update(exceptionAuthorizationJobs).set({
          state: "dead",
          leaseOwner: null,
          leaseExpiresAt: null,
          lastErrorCode: "EXCEPTION_PROOF_SUPERSEDED",
          lastErrorMessage: "A fresher proof replaced this unsubmitted authorization.",
          updatedAt: refreshedAt,
        }).where(eq(exceptionAuthorizationJobs.id, job.id));
      }
      await transaction.update(vaultRecords).set({ supersededAt: refreshedAt }).where(and(
        eq(vaultRecords.organizationId, bundle.organizationId),
        eq(vaultRecords.id, bundle.id),
        eq(vaultRecords.recordType, "proof-bundle"),
        isNull(vaultRecords.supersededAt),
      ));
      await transaction.insert(vaultRecords).values({
        id: bundle.id,
        organizationId: bundle.organizationId,
        recordType: "proof-bundle",
        revision: bundle.revision,
        ciphertext: envelope.ciphertext,
        envelope,
        envelopeHash,
        createdBy: principal.principalId,
      });
      const [refreshed] = await transaction.update(proofBundles).set({
        proofPackage: metadata,
        proofHash: envelopeHash,
        verificationState: "locally_verified",
        verificationTransactionHash: null,
      }).where(eq(proofBundles.id, bundle.id)).returning();
      if (routedWorkerClaim) {
        await transaction.update(workerClaims).set({
          state: "proved",
          updatedAt: refreshedAt,
        }).where(eq(workerClaims.id, routedWorkerClaim.id));
      }
      if (routedWageRemediation) {
        await transaction.update(wageRemediations).set({
          state: "proved",
          updatedAt: refreshedAt,
        }).where(eq(wageRemediations.id, routedWageRemediation.id));
      }
      await transaction.insert(auditEvents).values({
        id: generateUuidV7(),
        organizationId: bundle.organizationId,
        actorId: principal.principalId,
        action: "proof_bundle.exception_vnext_refreshed",
        subjectId: bundle.id,
        metadata: {
          runId: bundle.runId,
          proofType: bundle.proofType,
          subjectRecordId: bundle.subjectRecordId,
          revision: bundle.revision,
          previousProofHash: existing.proofHash,
          proofHash: envelopeHash,
        },
      });
      return { ...refreshed, replayed: false, refreshed: true };
    }
    await transaction.insert(vaultRecords).values({
      id: bundle.id,
      organizationId: bundle.organizationId,
      recordType: "proof-bundle",
      revision: bundle.revision,
      ciphertext: envelope.ciphertext,
      envelope,
      envelopeHash,
      createdBy: principal.principalId,
    });
    const [stored] = await transaction.insert(proofBundles).values({
      id: bundle.id,
      runId: bundle.runId,
      organizationId: bundle.organizationId,
      proofType: bundle.proofType,
      proofVersion: bundle.proofVersion,
      subjectRecordId: bundle.subjectRecordId,
      proofPackage: metadata,
      proofHash: envelopeHash,
      verificationState: "locally_verified",
    }).returning();
    if (routedWorkerClaim) {
      await transaction.update(workerClaims).set({
        state: "proved",
        updatedAt: new Date(),
      }).where(eq(workerClaims.id, routedWorkerClaim.id));
    }
    if (routedWageRemediation) {
      await transaction.update(wageRemediations).set({
        state: "proved",
        updatedAt: new Date(),
      }).where(eq(wageRemediations.id, routedWageRemediation.id));
    }
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: bundle.organizationId,
      actorId: principal.principalId,
      action: "proof_bundle.exception_vnext_verified",
      subjectId: bundle.id,
      metadata: {
        runId: bundle.runId,
        proofType: bundle.proofType,
        proofVersion: bundle.proofVersion,
        subjectNullifier,
        parentNullifier,
        publicInputsHash: bundle.publicInputsHash,
      },
    });
    return { ...stored, replayed: false };
  });
}

export async function storeEncryptedPayrollIntegrityBundle(input: {
  bundle: EncryptedPayoProofBundleCreate;
  principal: AuthenticatedPrincipal;
  deployment: PayoDeploymentConfig;
}) {
  if ("publicInputs" in input.bundle) return storeEncryptedExceptionProofBundle({
    bundle: input.bundle,
    principal: input.principal,
    deployment: input.deployment,
  });
  const { bundle, principal, deployment } = input;
  assertPayrollDeploymentBound(bundle, deployment);
  const envelope = bundle.envelope;
  if (
    envelope.aad.organizationId !== bundle.organizationId
    || envelope.aad.recordType !== "proof-bundle"
    || envelope.aad.recordId !== bundle.id
    || envelope.aad.revision !== bundle.revision
  ) {
    throw new ApiError(400, "Encrypted proof-bundle AAD does not match storage identity.", "AAD_MISMATCH");
  }

  const agreementRoot = combinedCommitment(
    bundle.commonInputs.agreementRootHigh,
    bundle.commonInputs.agreementRootLow,
    "Agreement root",
  );
  const manifestRoot = combinedCommitment(
    bundle.commonInputs.manifestRootHigh,
    bundle.commonInputs.manifestRootLow,
    "Manifest root",
  );
  const policyRoot = combinedCommitment(
    bundle.commonInputs.policyRootHigh,
    bundle.commonInputs.policyRootLow,
    "Policy root",
  );
  const fxRoot = combinedCommitment(
    bundle.commonInputs.fxRootHigh,
    bundle.commonInputs.fxRootLow,
    "FX root",
  );
  const runNullifier = combinedCommitment(
    bundle.commonInputs.runNullifierHigh,
    bundle.commonInputs.runNullifierLow,
    "Run nullifier",
  );
  const envelopeHash = hashCanonicalJson(envelope);
  const metadata = {
    schemaVersion: 1,
    envelopeRecordId: bundle.id,
    envelopeRevision: bundle.revision,
    proofType: bundle.proofType,
    subjectRecordId: bundle.subjectRecordId,
    proofVersion: bundle.proofVersion,
    circuitSha256: bundle.circuitSha256,
    verificationKeySha256: bundle.verificationKeySha256,
    publicInputsHash: bundle.publicInputsHash,
    commonInputs: bundle.commonInputs,
    shardCalldataHashes: bundle.shardCalldataHashes,
  };
  assertOperationalMetadataSafe(metadata);
  const database = getDatabase();

  return database.transaction(async (transaction) => {
    const [membership] = await transaction
      .select({ role: organizationMembers.role })
      .from(organizationMembers)
      .where(and(
        eq(organizationMembers.organizationId, bundle.organizationId),
        eq(organizationMembers.principalId, principal.principalId),
        isNull(organizationMembers.revokedAt),
      ))
      .limit(1)
      .for("update");
    if (!membership || !["admin", "operator"].includes(membership.role)) {
      throw new ApiError(403, "You cannot store proofs for this organization.", "ORG_FORBIDDEN");
    }

    const [organization] = await transaction
      .select({ recoveryState: organizations.recoveryState })
      .from(organizations)
      .where(eq(organizations.id, bundle.organizationId))
      .limit(1);
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    if (organization.recoveryState === "required") {
      throw new ApiError(409, "Configure vault recovery before proving payroll.", "VAULT_RECOVERY_REQUIRED");
    }

    const [run] = await transaction
      .select()
      .from(payrollRuns)
      .where(eq(payrollRuns.id, bundle.runId))
      .limit(1)
      .for("update");
    if (!run || run.organizationId !== bundle.organizationId) {
      throw new ApiError(404, "Payroll run not found in this organization.", "RUN_NOT_FOUND");
    }

    const payrollProfile = bundle.proofType === "payroll_integrity";
    const [existing] = await transaction
      .select()
      .from(proofBundles)
      .where(eq(proofBundles.id, bundle.id))
      .limit(1)
      .for("update");
    if (existing) {
      if (existing.proofHash === envelopeHash) {
        return { ...existing, replayed: true };
      }
      if (payrollProfile) {
        throw new ApiError(409, "Proof-bundle ID already contains different ciphertext.", "PROOF_BUNDLE_CONFLICT");
      }
      if (
        existing.organizationId !== bundle.organizationId
        || existing.runId !== bundle.runId
        || existing.proofType !== bundle.proofType
        || existing.proofVersion !== bundle.proofVersion
        || existing.subjectRecordId !== bundle.subjectRecordId
        || existing.verificationState !== "locally_verified"
        || existing.verificationTransactionHash
      ) {
        throw new ApiError(409, "This exception proof can no longer be refreshed.", "EXCEPTION_PROOF_REFRESH_FORBIDDEN");
      }
      const previousPackage = existing.proofPackage as { commonInputs?: Record<string, string> };
      const nextCommon = metadata.commonInputs as Record<string, string>;
      const stableInputKeys = [
        "chainId", "sealAddress", "proofVersion", "schemaVersion",
        "agreementRootHigh", "agreementRootLow", "manifestRootHigh", "manifestRootLow",
        "policyRootHigh", "policyRootLow", "fxRootHigh", "fxRootLow",
        "runNullifierHigh", "runNullifierLow",
      ];
      if (!previousPackage.commonInputs || stableInputKeys.some((key) =>
        previousPackage.commonInputs?.[key] !== nextCommon[key])) {
        throw new ApiError(409, "The refreshed proof changed an immutable claim binding.", "EXCEPTION_PROOF_BINDING_CHANGED");
      }
      const validityStart = Number(nextCommon.validityStart);
      const validityExpiry = Number(nextCommon.validityExpiry);
      const nowSeconds = Math.floor(Date.now() / 1_000);
      if (
        !Number.isSafeInteger(validityStart)
        || !Number.isSafeInteger(validityExpiry)
        || validityStart > nowSeconds + 60
        || validityExpiry <= nowSeconds
        || validityExpiry - validityStart > 3_600
      ) {
        throw new ApiError(400, "The refreshed exception proof validity window is invalid.", "EXCEPTION_PROOF_WINDOW_INVALID");
      }
      const [approval] = await transaction
        .select({ id: settlements.id })
        .from(settlements)
        .where(and(
          eq(settlements.organizationId, bundle.organizationId),
          eq(settlements.runId, bundle.runId),
          eq(settlements.workflowType, bundle.proofType),
          eq(settlements.subjectRecordId, bundle.subjectRecordId),
          eq(settlements.state, "approval_pending"),
          isNull(settlements.transactionHash),
        ))
        .limit(1)
        .for("update");
      if (!approval) {
        throw new ApiError(409, "A pending unsigned approval is required to refresh this proof.", "EXCEPTION_PROOF_APPROVAL_MISSING");
      }
      const [latestVault] = await transaction
        .select({ revision: vaultRecords.revision })
        .from(vaultRecords)
        .where(and(
          eq(vaultRecords.organizationId, bundle.organizationId),
          eq(vaultRecords.id, bundle.id),
          eq(vaultRecords.recordType, "proof-bundle"),
        ))
        .orderBy(desc(vaultRecords.revision))
        .limit(1)
        .for("update");
      if (!latestVault || bundle.revision !== latestVault.revision + 1) {
        throw new ApiError(409, "The exception proof refresh revision is stale.", "EXCEPTION_PROOF_REVISION_CONFLICT");
      }
      const refreshedAt = new Date();
      await transaction
        .update(vaultRecords)
        .set({ supersededAt: refreshedAt })
        .where(and(
          eq(vaultRecords.organizationId, bundle.organizationId),
          eq(vaultRecords.id, bundle.id),
          eq(vaultRecords.recordType, "proof-bundle"),
          isNull(vaultRecords.supersededAt),
        ));
      await transaction.insert(vaultRecords).values({
        id: bundle.id,
        organizationId: bundle.organizationId,
        recordType: "proof-bundle",
        revision: bundle.revision,
        ciphertext: envelope.ciphertext,
        envelope,
        envelopeHash,
        createdBy: principal.principalId,
      });
      const [refreshed] = await transaction
        .update(proofBundles)
        .set({
          proofPackage: metadata,
          proofHash: envelopeHash,
          verificationState: "locally_verified",
          verificationTransactionHash: null,
        })
        .where(eq(proofBundles.id, bundle.id))
        .returning();
      await transaction.insert(auditEvents).values({
        id: generateUuidV7(),
        organizationId: bundle.organizationId,
        actorId: principal.principalId,
        action: "proof_bundle.exception_refreshed",
        subjectId: bundle.id,
        metadata: {
          runId: bundle.runId,
          subjectRecordId: bundle.subjectRecordId,
          proofType: bundle.proofType,
          revision: bundle.revision,
          previousEnvelopeHash: existing.proofHash,
          envelopeHash,
        },
      });
      return { ...refreshed, replayed: false, refreshed: true };
    }
    if (payrollProfile && run.state !== "calculated") {
      throw new ApiError(409, `Payroll must be calculated before proof storage; current state is ${run.state}.`, "RUN_NOT_CALCULATED");
    }
    if (!payrollProfile) {
      const expectedRecordType = bundle.proofType === "wage_claim" ? "wage-claim" : "remediation";
      const expectedRunState = bundle.proofType === "wage_claim" ? "confirmed" : "disputed";
      if (run.state !== expectedRunState) {
        throw new ApiError(
          409,
          `${bundle.proofType} requires a ${expectedRunState} payroll; current state is ${run.state}.`,
          "EXCEPTION_RUN_STATE_INVALID",
        );
      }
      const [subject] = await transaction
        .select({ recordType: vaultRecords.recordType })
        .from(vaultRecords)
        .where(and(
          eq(vaultRecords.organizationId, bundle.organizationId),
          eq(vaultRecords.id, bundle.subjectRecordId),
          eq(vaultRecords.recordType, expectedRecordType),
          isNull(vaultRecords.supersededAt),
        ))
        .limit(1);
      if (!subject) {
        throw new ApiError(404, "Encrypted proof subject was not found.", "PROOF_SUBJECT_NOT_FOUND");
      }
    }

    const rootsToMatch = payrollProfile ? [
      ["agreement", run.agreementRoot, agreementRoot],
      ["manifest", run.manifestRoot, manifestRoot],
      ["run nullifier", run.runNullifier, runNullifier],
    ] as const : [
      ["agreement", run.agreementRoot, agreementRoot],
      ["policy", run.policyRoot, policyRoot],
      ["FX", run.fxRoot, fxRoot],
    ] as const;
    for (const [label, existingRoot, proofRoot] of rootsToMatch) {
      if (existingRoot && existingRoot.toLowerCase() !== proofRoot.toLowerCase()) {
        throw new ApiError(409, `Proof ${label} does not match the payroll run.`, "PROOF_RUN_MISMATCH");
      }
    }

    await transaction.insert(vaultRecords).values({
      id: bundle.id,
      organizationId: bundle.organizationId,
      recordType: "proof-bundle",
      revision: bundle.revision,
      ciphertext: envelope.ciphertext,
      envelope,
      envelopeHash,
      createdBy: principal.principalId,
    });
    const [stored] = await transaction
      .insert(proofBundles)
      .values({
        id: bundle.id,
        runId: bundle.runId,
        organizationId: bundle.organizationId,
        proofType: bundle.proofType,
        proofVersion: bundle.proofVersion,
        subjectRecordId: bundle.subjectRecordId,
        proofPackage: metadata,
        proofHash: envelopeHash,
        verificationState: "locally_verified",
      })
      .returning();
    if (payrollProfile) {
      const [updatedRun] = await transaction
        .update(payrollRuns)
        .set({
          state: "proven",
          agreementRoot,
          manifestRoot,
          policyRoot,
          fxRoot,
          runNullifier,
          updatedAt: new Date(),
          version: sql`${payrollRuns.version} + 1`,
        })
        .where(and(eq(payrollRuns.id, bundle.runId), eq(payrollRuns.state, "calculated")))
        .returning({ id: payrollRuns.id });
      if (!updatedRun) throw new ApiError(409, "Payroll state changed during proof storage.", "RUN_STATE_CONFLICT");
    }
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: bundle.organizationId,
      actorId: principal.principalId,
      action: "proof_bundle.locally_verified",
      subjectId: bundle.id,
      metadata: {
        runId: bundle.runId,
        proofVersion: bundle.proofVersion,
        publicInputsHash: bundle.publicInputsHash,
        envelopeHash,
      },
    });
    return { ...stored, replayed: false };
  });
}


export async function getEncryptedProofBundle(input: {
  proofBundleId: string;
  principal: AuthenticatedPrincipal;
}) {
  const database = getDatabase();
  const [bundle] = await database
    .select()
    .from(proofBundles)
    .where(eq(proofBundles.id, input.proofBundleId))
    .limit(1);
  if (!bundle) {
    throw new ApiError(404, "Encrypted proof bundle not found.", "PROOF_BUNDLE_NOT_FOUND");
  }
  const [record] = await database
    .select({ revision: vaultRecords.revision, envelope: vaultRecords.envelope })
    .from(vaultRecords)
    .where(and(
      eq(vaultRecords.organizationId, bundle.organizationId),
      eq(vaultRecords.id, bundle.id),
      eq(vaultRecords.recordType, "proof-bundle"),
      isNull(vaultRecords.supersededAt),
    ))
    .orderBy(desc(vaultRecords.revision))
    .limit(1);
  if (!record) {
    throw new ApiError(409, "The active encrypted proof payload is missing.", "PROOF_ENVELOPE_MISSING");
  }
  const envelope = encryptedVaultRecordSchema.parse(record.envelope);
  if (!envelope.wrappedKeys.some(({ principalId }) =>
    principalId === input.principal.principalId)) {
    throw new ApiError(403, "This proof is not encrypted to the authenticated principal.", "PROOF_BUNDLE_FORBIDDEN");
  }

  const [membership] = await database
    .select({ role: organizationMembers.role })
    .from(organizationMembers)
    .where(and(
      eq(organizationMembers.organizationId, bundle.organizationId),
      eq(organizationMembers.principalId, input.principal.principalId),
      isNull(organizationMembers.revokedAt),
    ))
    .limit(1);
  let ownsSubject = false;
  if (bundle.proofType === "wage_claim") {
    const [claim] = await database
      .select({ claimantPrincipalId: workerClaims.claimantPrincipalId })
      .from(workerClaims)
      .where(and(
        eq(workerClaims.id, bundle.subjectRecordId),
        eq(workerClaims.proofBundleId, bundle.id),
      ))
      .limit(1);
    ownsSubject = claim?.claimantPrincipalId === input.principal.principalId;
  } else if (bundle.proofType === "wage_remediation") {
    const [remediation] = await database
      .select({ claimantPrincipalId: wageRemediations.claimantPrincipalId })
      .from(wageRemediations)
      .where(and(
        eq(wageRemediations.id, bundle.subjectRecordId),
        eq(wageRemediations.proofBundleId, bundle.id),
      ))
      .limit(1);
    ownsSubject = remediation?.claimantPrincipalId === input.principal.principalId;
  }
  if (!membership && !ownsSubject) {
    throw new ApiError(403, "You cannot read this encrypted proof bundle.", "PROOF_BUNDLE_FORBIDDEN");
  }

  return {
    id: bundle.id,
    organizationId: bundle.organizationId,
    runId: bundle.runId,
    proofType: bundle.proofType,
    proofVersion: bundle.proofVersion,
    subjectRecordId: bundle.subjectRecordId,
    proofPackage: bundle.proofPackage,
    verificationState: bundle.verificationState,
    verificationTransactionHash: bundle.verificationTransactionHash,
    createdAt: bundle.createdAt.toISOString(),
    revision: record.revision,
    envelope,
  };
}
