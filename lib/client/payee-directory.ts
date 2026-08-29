import {
  decryptVaultRecord,
  encryptVaultRecord,
  type EncryptedVaultRecord,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import {
  generateUuidV7,
  payeeRecordSchema,
  principalRecordSchema,
} from "@/lib/domain/records";
import type { PayrollTokenSymbol } from "@/lib/starknet/tokens";
import type { PayoClient } from "./payo-client";
import { validateAndParseAddress } from "starknet";

export type PayeeDirectoryRecord = ReturnType<typeof payeeRecordSchema.parse>;

export type PayeeClaimIdentity = {
  principalId: string;
  publicKey: string;
  claimCapabilityCommitment: `0x${string}`;
};

export function prepareEncryptedPayee(input: {
  organizationId: string;
  displayName: string;
  principalKind: "human" | "agent";
  recipientAddress: string;
  tokenPreference: PayrollTokenSymbol;
  jurisdictionCode: string;
  claimIdentity?: PayeeClaimIdentity;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const payeeId = generateUuidV7(now.getTime());
  const principalId = generateUuidV7(now.getTime() + 1);
  let recipientAddress: string;
  try {
    recipientAddress = validateAndParseAddress(input.recipientAddress.trim());
  } catch {
    throw new Error("Enter a valid Starknet payout address.");
  }
  const record = payeeRecordSchema.parse({
    schemaVersion: 1,
    id: payeeId,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    principalId,
    principalKind: input.principalKind,
    displayName: input.displayName.trim(),
    recipientAddress,
    tokenPreference: input.tokenPreference,
    jurisdictionCode: input.jurisdictionCode.trim().toUpperCase(),
    ...(input.claimIdentity ? {
      claimIdentityPrincipalId: input.claimIdentity.principalId,
      claimIdentityPublicKey: input.claimIdentity.publicKey,
      claimCapabilityCommitment: input.claimIdentity.claimCapabilityCommitment,
    } : {}),
    status: "active",
  });
  const principalRecord = principalRecordSchema.parse({
    schemaVersion: 1,
    id: principalId,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    kind: input.principalKind === "agent" ? "agent" : "worker",
    displayName: input.displayName.trim(),
    accessState: "directory_only",
    status: "active",
  });
  const envelope = encryptVaultRecord(
    record,
    {
      schemaVersion: 1,
      organizationId: record.organizationId,
      recordType: "payee",
      recordId: record.id,
      revision: record.revision,
    },
    [input.principal],
  );
  const principalEnvelope = encryptVaultRecord(
    principalRecord,
    {
      schemaVersion: 1,
      organizationId: record.organizationId,
      recordType: "principal",
      recordId: principalRecord.id,
      revision: principalRecord.revision,
    },
    [input.principal],
  );
  return { record, envelope, principalRecord, principalEnvelope };
}

export async function storeEncryptedPayee(input: {
  client: Pick<PayoClient, "storeEncryptedRecords">;
  organizationId: string;
  displayName: string;
  principalKind: "human" | "agent";
  recipientAddress: string;
  tokenPreference: PayrollTokenSymbol;
  jurisdictionCode: string;
  claimIdentity?: PayeeClaimIdentity;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<PayeeDirectoryRecord> {
  const { client, ...recordInput } = input;
  const prepared = prepareEncryptedPayee(recordInput);
  await client.storeEncryptedRecords({
    organizationId: prepared.record.organizationId,
    records: [{
      recordId: prepared.principalRecord.id,
      recordType: "principal",
      revision: prepared.principalRecord.revision,
      envelope: prepared.principalEnvelope,
    }, {
      recordId: prepared.record.id,
      recordType: "payee",
      revision: prepared.record.revision,
      envelope: prepared.envelope,
    }],
  });
  return prepared.record;
}

type EncryptedRecordMetadata = {
  id: string;
  recordType: string;
  revision: number;
};

type EncryptedRecordResponse = {
  record: {
    id?: string;
    recordType?: string;
    revision?: number;
    envelope?: EncryptedVaultRecord;
  };
};

export async function loadEncryptedPayees(input: {
  client: Pick<PayoClient, "listEncryptedRecords" | "getEncryptedRecord">;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
}): Promise<PayeeDirectoryRecord[]> {
  const listing = await input.client.listEncryptedRecords(input.organizationId, "payee") as {
    records: EncryptedRecordMetadata[];
  };
  const records = await Promise.all(listing.records.map(async (metadata) => {
    if (metadata.recordType !== "payee") {
      throw new Error("The PAYO API returned a non-payee record in the encrypted payee listing.");
    }
    const response = await input.client.getEncryptedRecord({
      organizationId: input.organizationId,
      recordId: metadata.id,
      revision: metadata.revision,
    }) as EncryptedRecordResponse;
    if (!response.record.envelope) throw new Error("An encrypted payee envelope is missing.");
    const plaintext = decryptVaultRecord(response.record.envelope, input.principal);
    const payee = payeeRecordSchema.parse(plaintext);
    if (
      payee.organizationId !== input.organizationId
      || payee.id !== metadata.id
      || payee.revision !== metadata.revision
    ) {
      throw new Error("A decrypted payee does not match its authenticated storage identity.");
    }
    return payee;
  }));
  return records.sort((left, right) => left.displayName.localeCompare(right.displayName));
}
