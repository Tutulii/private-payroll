import { hashCanonicalJson } from "@/lib/crypto/digest";
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
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<WageClaimRecord> {
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const claimSalt = randomCommitmentSalt();
  const claimNullifier = hashCanonicalJson({
    domain: "PAYO_WAGE_CLAIM_V1",
    organizationId: input.organizationId,
    agreementId: input.agreementId,
    runId: input.runId,
    claimKind: input.claimKind,
    claimSalt,
  });
  const record = wageClaimRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    agreementId: input.agreementId,
    runId: input.runId,
    claimNullifier,
    claimSalt,
    claimKind: input.claimKind,
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
  claimId: string;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<RemediationRecord> {
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const remediationSalt = randomCommitmentSalt();
  const remediationNullifier = hashCanonicalJson({
    domain: "PAYO_REMEDIATION_V1",
    organizationId: input.organizationId,
    claimId: input.claimId,
    remediationSalt,
  });
  const record = remediationRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    claimId: input.claimId,
    remediationNullifier,
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
