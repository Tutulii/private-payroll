import "server-only";

import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import type { EncryptedPayrollIntegrityBundleCreate } from "@/lib/domain/proof-bundle";
import { assertOperationalMetadataSafe } from "@/lib/domain/privacy";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import type { PayoDeploymentConfig } from "@/lib/server/payo-deployment";
import { getDatabase } from "./db";
import {
  auditEvents,
  organizationMembers,
  organizations,
  payrollRuns,
  proofBundles,
  settlements,
  vaultRecords,
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

function assertDeploymentBound(
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

export async function storeEncryptedPayrollIntegrityBundle(input: {
  bundle: EncryptedPayrollIntegrityBundleCreate;
  principal: AuthenticatedPrincipal;
  deployment: PayoDeploymentConfig;
}) {
  const { bundle, principal, deployment } = input;
  assertDeploymentBound(bundle, deployment);
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
