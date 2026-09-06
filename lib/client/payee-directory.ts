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
import { hashCanonicalJson } from "@/lib/crypto/digest";
import type { PayoClient } from "./payo-client";
import { validateAndParseAddress } from "starknet";

export type PayeeDirectoryRecord = ReturnType<typeof payeeRecordSchema.parse>;

export type PayeeClaimIdentity = {
  principalId: string;
  publicKey: string;
  claimCapabilityCommitment: `0x${string}`;
};

export function normalizeContributorWalletAddress(value: string): string {
  try {
    return validateAndParseAddress(value.trim());
  } catch {
    throw new Error("Enter a valid Starknet payout address.");
  }
}

export function contributorWalletAddressCommitment(input: {
  organizationId: string;
  recipientAddress: string;
}): `0x${string}` {
  return hashCanonicalJson({
    domain: "PAYO_CONTRIBUTOR_WALLET_V1",
    organizationId: input.organizationId,
    recipientAddress: normalizeContributorWalletAddress(input.recipientAddress),
  });
}

export function assertContributorWalletAvailable(
  recipientAddress: string,
  payees: readonly PayeeDirectoryRecord[],
): string {
  const normalized = normalizeContributorWalletAddress(recipientAddress);
  const duplicate = payees.find((payee) =>
    payee.status === "active"
    && normalizeContributorWalletAddress(payee.recipientAddress) === normalized);
  if (duplicate) {
    throw new Error(`This wallet is already assigned to ${duplicate.displayName}. One wallet can belong to only one active contributor.`);
  }
  return normalized;
}

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
  const recipientAddress = normalizeContributorWalletAddress(input.recipientAddress);
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
  existingPayees?: readonly PayeeDirectoryRecord[];
  now?: Date;
}): Promise<PayeeDirectoryRecord> {
  const { client, existingPayees = [], ...recordInput } = input;
  assertContributorWalletAvailable(input.recipientAddress, existingPayees);
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
    contributorWalletConstraint: {
      action: "claim",
      payeeRecordId: prepared.record.id,
      addressCommitment: contributorWalletAddressCommitment({
        organizationId: prepared.record.organizationId,
        recipientAddress: prepared.record.recipientAddress,
      }),
    },
  });
  return prepared.record;
}

export async function deactivateEncryptedPayee(input: {
  client: Pick<PayoClient, "storeEncryptedRecords">;
  record: PayeeDirectoryRecord;
  directoryPrincipal?: ReturnType<typeof principalRecordSchema.parse>;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<{
  record: PayeeDirectoryRecord;
  directoryPrincipal: ReturnType<typeof principalRecordSchema.parse> | null;
}> {
  if (input.record.status === "inactive") {
    return { record: input.record, directoryPrincipal: input.directoryPrincipal ?? null };
  }
  if (
    input.directoryPrincipal
    && (input.directoryPrincipal.organizationId !== input.record.organizationId
      || input.directoryPrincipal.id !== input.record.principalId)
  ) {
    throw new Error("The contributor and directory identity do not match.");
  }
  const now = input.now ?? new Date();
  const updatedAt = now.toISOString();
  const record = payeeRecordSchema.parse({
    ...input.record,
    revision: input.record.revision + 1,
    updatedAt,
    status: "inactive",
  });
  const directoryPrincipal = input.directoryPrincipal?.status === "revoked"
    ? input.directoryPrincipal
    : input.directoryPrincipal
      ? principalRecordSchema.parse({
          ...input.directoryPrincipal,
          revision: input.directoryPrincipal.revision + 1,
          updatedAt,
          status: "revoked",
        })
      : null;
  const records = [{
    recordId: record.id,
    recordType: "payee",
    revision: record.revision,
    envelope: encryptVaultRecord(record, {
      schemaVersion: 1,
      organizationId: record.organizationId,
      recordType: "payee",
      recordId: record.id,
      revision: record.revision,
    }, [input.principal]),
  }];
  if (directoryPrincipal && directoryPrincipal !== input.directoryPrincipal) {
    records.push({
      recordId: directoryPrincipal.id,
      recordType: "principal",
      revision: directoryPrincipal.revision,
      envelope: encryptVaultRecord(directoryPrincipal, {
        schemaVersion: 1,
        organizationId: directoryPrincipal.organizationId,
        recordType: "principal",
        recordId: directoryPrincipal.id,
        revision: directoryPrincipal.revision,
      }, [input.principal]),
    });
  }
  await input.client.storeEncryptedRecords({
    organizationId: record.organizationId,
    records,
    contributorWalletConstraint: {
      action: "release",
      payeeRecordId: record.id,
      addressCommitment: contributorWalletAddressCommitment({
        organizationId: record.organizationId,
        recipientAddress: record.recipientAddress,
      }),
    },
  });
  return { record, directoryPrincipal };
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
