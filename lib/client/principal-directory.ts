import type { VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { generateUuidV7, principalRecordSchema } from "@/lib/domain/records";
import type { PayoClient } from "./payo-client";
import type { PayeeDirectoryRecord } from "./payee-directory";
import {
  loadCanonicalEncryptedRecords,
  prepareCanonicalEncryptedRecord,
} from "./encrypted-records";

export type PrincipalDirectoryRecord = ReturnType<typeof principalRecordSchema.parse>;

export async function loadEncryptedPrincipals(input: {
  client: Pick<PayoClient, "listEncryptedRecords" | "getEncryptedRecord">;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
}): Promise<PrincipalDirectoryRecord[]> {
  return loadCanonicalEncryptedRecords({ ...input, recordType: "principal" });
}

export async function completeEncryptedPrincipalDirectory(input: {
  client: Pick<PayoClient, "storeEncryptedRecords">;
  organizationId: string;
  vaultPrincipal: VaultPrincipalKeyPair;
  existingPrincipals: readonly PrincipalDirectoryRecord[];
  payees: readonly PayeeDirectoryRecord[];
  currentPrincipalKind?: "admin" | "operator" | "reviewer";
  currentPrincipalDisplayName?: string;
  now?: Date;
}): Promise<PrincipalDirectoryRecord[]> {
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const records: PrincipalDirectoryRecord[] = [];
  if (!input.existingPrincipals.some(({ vaultPrincipalId }) =>
    vaultPrincipalId === input.vaultPrincipal.principalId)) {
    records.push(principalRecordSchema.parse({
      schemaVersion: 1,
      id: generateUuidV7(now.getTime()),
      organizationId: input.organizationId,
      revision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
      kind: input.currentPrincipalKind ?? "admin",
      displayName: input.currentPrincipalDisplayName?.trim() || "Workspace administrator",
      accessState: "vault_grantee",
      vaultPrincipalId: input.vaultPrincipal.principalId,
      vaultPublicKey: input.vaultPrincipal.publicKey,
      status: "active",
    }));
  }
  const existingIds = new Set(input.existingPrincipals.map(({ id }) => id));
  for (const payee of input.payees) {
    if (payee.organizationId !== input.organizationId) {
      throw new Error("A contributor from another organization cannot enter this principal directory.");
    }
    if (existingIds.has(payee.principalId)) continue;
    records.push(principalRecordSchema.parse({
      schemaVersion: 1,
      id: payee.principalId,
      organizationId: input.organizationId,
      revision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
      kind: payee.principalKind === "agent" ? "agent" : "worker",
      displayName: payee.displayName,
      accessState: "directory_only",
      status: payee.status === "inactive" ? "revoked" : "active",
    }));
    existingIds.add(payee.principalId);
  }
  if (records.length === 0) return [];
  const prepared = records.map((record) => prepareCanonicalEncryptedRecord({
    organizationId: input.organizationId,
    recordType: "principal",
    record,
    principals: [input.vaultPrincipal],
  }));
  await input.client.storeEncryptedRecords({
    organizationId: input.organizationId,
    records: prepared.map(({ record, envelope }) => ({
      recordId: record.id,
      recordType: "principal",
      revision: record.revision,
      envelope,
    })),
  });
  return records;
}
