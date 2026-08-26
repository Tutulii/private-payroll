import type { VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  generateUuidV7,
  remediationRecordSchema,
  wageClaimRecordSchema,
} from "@/lib/domain/records";
import { randomCommitmentSalt } from "@/lib/proof/input-builder";
import type { PayoClient } from "./payo-client";
import {
  loadCanonicalEncryptedRecords,
  storeCanonicalEncryptedRecord,
} from "./encrypted-records";

export type WageClaimRecord = ReturnType<typeof wageClaimRecordSchema.parse>;
export type RemediationRecord = ReturnType<typeof remediationRecordSchema.parse>;

export async function createEncryptedWageClaimDraft(input: {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  organizationId: string;
  agreementId: string;
  runId: string;
  claimKind: "missing_obligation" | "below_committed_floor" | "incomplete_final_pay";
  disputedReferenceValueAtomic?: string;
  disputedFinalIncludedMask?: number;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<WageClaimRecord> {
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const claimSalt = randomCommitmentSalt();
  const record = wageClaimRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    agreementId: input.agreementId,
    runId: input.runId,
    claimSalt,
    claimKind: input.claimKind,
    disputedReferenceValueAtomic: input.disputedReferenceValueAtomic,
    disputedFinalIncludedMask: input.disputedFinalIncludedMask,
    state: "draft",
  });
  return storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "wage-claim",
    record,
    principals: [input.principal],
  });
}

export async function createEncryptedRemediationDraft(input: {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  organizationId: string;
  claim: WageClaimRecord;
  amountAtomic?: string;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<RemediationRecord> {
  const claim = wageClaimRecordSchema.parse(input.claim);
  if (
    claim.organizationId !== input.organizationId
    || !claim.claimNullifier
    || !claim.shortfallAtomic
    || !claim.token
    || !["submitted", "accepted"].includes(claim.state)
  ) {
    throw new Error("Remediation requires a proved, submitted claim from this organization.");
  }
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const remediationSalt = randomCommitmentSalt();
  const amountAtomic = input.amountAtomic ?? claim.shortfallAtomic;
  if (BigInt(amountAtomic) < BigInt(claim.shortfallAtomic)) {
    throw new Error("Remediation cannot be below the proved private shortfall.");
  }
  const record = remediationRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    claimId: claim.id,
    runId: claim.runId,
    agreementId: claim.agreementId,
    claimNullifier: claim.claimNullifier,
    amountAtomic,
    token: claim.token,
    remediationSalt,
    state: "draft",
  });
  return storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "remediation",
    record,
    principals: [input.principal],
  });
}

export async function loadEncryptedClaims(input: {
  client: Pick<PayoClient, "listEncryptedRecords" | "getEncryptedRecord">;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
}) {
  return loadCanonicalEncryptedRecords({ ...input, recordType: "wage-claim" });
}

export async function loadEncryptedRemediations(input: {
  client: Pick<PayoClient, "listEncryptedRecords" | "getEncryptedRecord">;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
}) {
  return loadCanonicalEncryptedRecords({ ...input, recordType: "remediation" });
}
