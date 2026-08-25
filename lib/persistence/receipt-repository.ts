import "server-only";

import { and, desc, eq } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { encryptedVaultRecordSchema, type EncryptedVaultRecord } from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole, requireOrganizationRoleWith } from "./repository";
import {
  auditEvents,
  disclosureGrants,
  payrollRuns,
  receipts,
  settlements,
  vaultRecords,
} from "./schema";

function assertEnvelopeIdentity(input: {
  organizationId: string;
  recordId: string;
  recordType: "receipt" | "disclosure-grant";
  envelope: EncryptedVaultRecord;
}): EncryptedVaultRecord {
  const envelope = encryptedVaultRecordSchema.parse(input.envelope);
  if (
    envelope.aad.organizationId !== input.organizationId
    || envelope.aad.recordId !== input.recordId
    || envelope.aad.recordType !== input.recordType
    || envelope.aad.revision !== 1
  ) {
    throw new ApiError(400, "Encrypted record AAD does not match its receipt identity.", "AAD_MISMATCH");
  }
  return envelope;
}

export async function createEncryptedReceipt(input: {
  id: string;
  organizationId: string;
  runId: string;
  settlementId: string;
  scope: "employer" | "worker" | "auditor" | "tax";
  granteePrincipalId: string;
  packageCommitment: string;
  expiresAt?: Date;
  envelope: EncryptedVaultRecord;
  principal: AuthenticatedPrincipal;
}) {
  const envelope = assertEnvelopeIdentity({ ...input, recordId: input.id, recordType: "receipt" });
  const envelopeHash = hashCanonicalJson(envelope);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin", "operator"]);
    const [settlement] = await transaction
      .select({ organizationId: settlements.organizationId, runId: settlements.runId, state: settlements.state })
      .from(settlements)
      .where(eq(settlements.id, input.settlementId))
      .limit(1)
      .for("update");
    if (
      !settlement
      || settlement.organizationId !== input.organizationId
      || settlement.runId !== input.runId
    ) throw new ApiError(404, "Confirmed settlement not found for this receipt.", "SETTLEMENT_NOT_FOUND");
    if (!["confirmed", "finalized", "reconciled"].includes(settlement.state)) {
      throw new ApiError(409, "A receipt requires a confirmed settlement.", "SETTLEMENT_NOT_CONFIRMED");
    }
    const [existing] = await transaction
      .select({ receipt: receipts, envelopeHash: vaultRecords.envelopeHash })
      .from(receipts)
      .innerJoin(vaultRecords, and(
        eq(vaultRecords.id, receipts.envelopeRecordId),
        eq(vaultRecords.organizationId, receipts.organizationId),
        eq(vaultRecords.revision, 1),
      ))
      .where(eq(receipts.id, input.id))
      .limit(1);
    if (existing) {
      if (
        existing.envelopeHash !== envelopeHash
        || existing.receipt.organizationId !== input.organizationId
        || existing.receipt.packageCommitment !== input.packageCommitment.toLowerCase()
      ) throw new ApiError(409, "Receipt identifier already contains different evidence.", "RECEIPT_CONFLICT");
      return { ...existing.receipt, replayed: true };
    }
    await transaction.insert(vaultRecords).values({
      id: input.id,
      organizationId: input.organizationId,
      recordType: "receipt",
      revision: 1,
      ciphertext: envelope.ciphertext,
      envelope,
      envelopeHash,
      createdBy: input.principal.principalId,
    });
    const [receipt] = await transaction.insert(receipts).values({
      id: input.id,
      organizationId: input.organizationId,
      runId: input.runId,
      settlementId: input.settlementId,
      scope: input.scope,
      granteePrincipalId: input.granteePrincipalId,
      envelopeRecordId: input.id,
      packageCommitment: input.packageCommitment.toLowerCase(),
      expiresAt: input.expiresAt,
    }).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "receipt.created",
      subjectId: input.id,
      metadata: { scope: input.scope, packageCommitment: input.packageCommitment.toLowerCase() },
    });
    return { ...receipt, replayed: false };
  });
}

export async function listEncryptedReceipts(
  organizationId: string,
  principal: AuthenticatedPrincipal,
) {
  await requireOrganizationRole(organizationId, principal, ["admin", "operator", "reviewer"]);
  return getDatabase().select().from(receipts)
    .where(eq(receipts.organizationId, organizationId))
    .orderBy(desc(receipts.createdAt));
}

export async function createDisclosureGrant(input: {
  id: string;
  organizationId: string;
  runId: string;
  granteePrincipalId: string;
  fieldScope: string[];
  validAfter: Date;
  expiresAt: Date;
  envelope: EncryptedVaultRecord;
  principal: AuthenticatedPrincipal;
}) {
  if (input.expiresAt <= input.validAfter) {
    throw new ApiError(400, "Disclosure expiry must follow activation.", "DISCLOSURE_WINDOW_INVALID");
  }
  const envelope = assertEnvelopeIdentity({ ...input, recordId: input.id, recordType: "disclosure-grant" });
  const envelopeHash = hashCanonicalJson(envelope);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin", "operator"]);
    const [run] = await transaction.select({ organizationId: payrollRuns.organizationId })
      .from(payrollRuns).where(eq(payrollRuns.id, input.runId)).limit(1);
    if (!run || run.organizationId !== input.organizationId) {
      throw new ApiError(404, "Payroll run not found for this disclosure.", "RUN_NOT_FOUND");
    }
    const [existing] = await transaction.select().from(disclosureGrants)
      .where(eq(disclosureGrants.id, input.id)).limit(1);
    if (existing) return { ...existing, replayed: true };
    await transaction.insert(vaultRecords).values({
      id: input.id,
      organizationId: input.organizationId,
      recordType: "disclosure-grant",
      revision: 1,
      ciphertext: envelope.ciphertext,
      envelope,
      envelopeHash,
      createdBy: input.principal.principalId,
    });
    const [grant] = await transaction.insert(disclosureGrants).values({
      id: input.id,
      organizationId: input.organizationId,
      runId: input.runId,
      granteePrincipalId: input.granteePrincipalId,
      fieldScope: input.fieldScope,
      envelopeRecordId: input.id,
      validAfter: input.validAfter,
      expiresAt: input.expiresAt,
    }).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "disclosure.created",
      subjectId: input.id,
      metadata: { fieldCount: input.fieldScope.length, expiresAt: input.expiresAt.toISOString() },
    });
    return { ...grant, replayed: false };
  });
}

export async function revokeDisclosureGrant(input: {
  organizationId: string;
  grantId: string;
  principal: AuthenticatedPrincipal;
}) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin", "operator"]);
    const now = new Date();
    const [grant] = await transaction.update(disclosureGrants)
      .set({ revokedAt: now })
      .where(and(
        eq(disclosureGrants.id, input.grantId),
        eq(disclosureGrants.organizationId, input.organizationId),
      )).returning();
    if (!grant) throw new ApiError(404, "Disclosure grant not found.", "DISCLOSURE_NOT_FOUND");
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "disclosure.revoked",
      subjectId: input.grantId,
      metadata: {},
    });
    return grant;
  });
}
