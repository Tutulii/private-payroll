import type { VaultPrincipal, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { disclosureGrantRecordSchema, generateUuidV7 } from "@/lib/domain/records";
import type { PayoClient } from "./payo-client";
import { prepareCanonicalEncryptedRecord } from "./encrypted-records";

export const aggregateDisclosureFields = ["aggregate", "token", "settlement"] as const;

export async function createEncryptedDisclosureGrant(input: {
  client: Pick<PayoClient, "createDisclosureGrant">;
  organizationId: string;
  runId: string;
  granteePrincipalId: string;
  granteePublicKey: string;
  issuerPrincipal: VaultPrincipalKeyPair;
  fieldScope?: Array<(typeof aggregateDisclosureFields)[number]>;
  validAfter?: string;
  expiresAt: string;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const grantee: VaultPrincipal = {
    principalId: input.granteePrincipalId,
    publicKey: input.granteePublicKey,
  };
  const record = disclosureGrantRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    runId: input.runId,
    granteePrincipalId: input.granteePrincipalId,
    fieldScope: input.fieldScope ?? [...aggregateDisclosureFields],
    recipientEncryptionKey: input.granteePublicKey,
    validAfter: input.validAfter ? new Date(input.validAfter).toISOString() : timestamp,
    expiresAt: new Date(input.expiresAt).toISOString(),
  });
  if (new Date(record.expiresAt) <= new Date(record.validAfter)) {
    throw new Error("Disclosure expiry must follow its activation time.");
  }
  const prepared = prepareCanonicalEncryptedRecord({
    organizationId: input.organizationId,
    recordType: "disclosure-grant",
    record,
    principals: [input.issuerPrincipal, grantee],
  });
  await input.client.createDisclosureGrant({
    id: record.id,
    organizationId: record.organizationId,
    runId: record.runId,
    granteePrincipalId: record.granteePrincipalId,
    fieldScope: record.fieldScope,
    validAfter: record.validAfter,
    expiresAt: record.expiresAt,
    envelope: prepared.envelope,
  });
  return { record, envelope: prepared.envelope, grantee };
}
