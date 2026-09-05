import type { z } from "zod";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  type EncryptedVaultRecord,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import {
  agentCapabilityRecordSchema,
  disclosureGrantRecordSchema,
  payAgreementRecordSchema,
  payeeRecordSchema,
  payrollLineRecordSchema,
  payrollRunRecordSchema,
  principalRecordSchema,
  proofBundleRecordSchema,
  receiptRecordSchema,
  remediationRecordSchema,
  settlementRecordSchema,
  wageClaimRecordSchema,
} from "@/lib/domain/records";
import { payrollReportRecordSchema } from "@/lib/disclosure/payroll-book-report";
import type { EncryptedRecordType } from "@/lib/persistence/vault-repository";
import type { PayoClient } from "./payo-client";

const encryptedRecordSchemas = {
  principal: principalRecordSchema,
  payee: payeeRecordSchema,
  "pay-agreement": payAgreementRecordSchema,
  "payroll-run": payrollRunRecordSchema,
  "payroll-line": payrollLineRecordSchema,
  "proof-bundle": proofBundleRecordSchema,
  settlement: settlementRecordSchema,
  receipt: receiptRecordSchema,
  "disclosure-grant": disclosureGrantRecordSchema,
  "payroll-report": payrollReportRecordSchema,
  "agent-capability": agentCapabilityRecordSchema,
  "wage-claim": wageClaimRecordSchema,
  remediation: remediationRecordSchema,
} as const satisfies Record<EncryptedRecordType, z.ZodType>;

export type CanonicalEncryptedRecordType = keyof typeof encryptedRecordSchemas;
export type CanonicalEncryptedRecord<T extends CanonicalEncryptedRecordType> =
  z.infer<(typeof encryptedRecordSchemas)[T]>;

type EncryptedRecordMetadata = {
  id: string;
  recordType: string;
  revision: number;
};

function assertStorageIdentity(input: {
  organizationId: string;
  metadata: EncryptedRecordMetadata;
  record: { id: string; organizationId: string; revision: number };
  recordType: CanonicalEncryptedRecordType;
}): void {
  if (
    input.metadata.recordType !== input.recordType
    || input.record.organizationId !== input.organizationId
    || input.record.id !== input.metadata.id
    || input.record.revision !== input.metadata.revision
  ) {
    throw new Error(`A decrypted ${input.recordType} record does not match its authenticated storage identity.`);
  }
}

export function prepareCanonicalEncryptedRecord<T extends CanonicalEncryptedRecordType>(input: {
  organizationId: string;
  recordType: T;
  record: unknown;
  principals: readonly VaultPrincipal[];
}): { record: CanonicalEncryptedRecord<T>; envelope: EncryptedVaultRecord } {
  const record = encryptedRecordSchemas[input.recordType].parse(input.record) as CanonicalEncryptedRecord<T>;
  if (record.organizationId !== input.organizationId) {
    throw new Error(`The ${input.recordType} record belongs to another organization.`);
  }
  const envelope = encryptVaultRecord(
    record,
    {
      schemaVersion: 1,
      organizationId: record.organizationId,
      recordType: input.recordType,
      recordId: record.id,
      revision: record.revision,
    },
    input.principals,
  );
  return { record, envelope };
}

export async function storeCanonicalEncryptedRecord<T extends CanonicalEncryptedRecordType>(input: {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  organizationId: string;
  recordType: T;
  record: unknown;
  principals: readonly VaultPrincipal[];
}): Promise<CanonicalEncryptedRecord<T>> {
  const prepared = prepareCanonicalEncryptedRecord(input);
  await input.client.storeEncryptedRecord({
    organizationId: input.organizationId,
    recordId: prepared.record.id,
    recordType: input.recordType,
    revision: prepared.record.revision,
    envelope: prepared.envelope,
  });
  return prepared.record;
}

export async function loadCanonicalEncryptedRecords<T extends CanonicalEncryptedRecordType>(input: {
  client: Pick<PayoClient, "listEncryptedRecords" | "getEncryptedRecord">;
  organizationId: string;
  recordType: T;
  principal: VaultPrincipalKeyPair;
}): Promise<Array<CanonicalEncryptedRecord<T>>> {
  const listing = await input.client.listEncryptedRecords(input.organizationId, input.recordType) as {
    records: EncryptedRecordMetadata[];
  };
  return Promise.all(listing.records.map(async (metadata) => {
    if (metadata.recordType !== input.recordType) {
      throw new Error(`The PAYO API returned a non-${input.recordType} record in a filtered listing.`);
    }
    const response = await input.client.getEncryptedRecord({
      organizationId: input.organizationId,
      recordId: metadata.id,
      revision: metadata.revision,
    }) as { record: { envelope?: EncryptedVaultRecord } };
    if (!response.record.envelope) throw new Error(`An encrypted ${input.recordType} envelope is missing.`);
    const plaintext = decryptVaultRecord(response.record.envelope, input.principal);
    const record = encryptedRecordSchemas[input.recordType].parse(plaintext) as CanonicalEncryptedRecord<T>;
    assertStorageIdentity({
      organizationId: input.organizationId,
      metadata,
      record,
      recordType: input.recordType,
    });
    return record;
  }));
}
