import { randomBytes } from "@noble/ciphers/utils.js";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { toHex } from "@/lib/crypto/encoding";
import {
  createVaultRecoveryPackage,
  encryptVaultRecord,
  rotateVaultRecordKey,
  type EncryptedVaultRecord,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import type { PayoClient } from "./payo-client";

type VaultState = {
  keyVersion: number;
  members: Array<{
    principalId: string;
    role: "admin" | "operator" | "reviewer";
    vaultPublicKey: string;
    keyVersion: number;
    revokedAt: string | null;
  }>;
};

export async function rotateClientVault(input: {
  client: PayoClient;
  organizationId: string;
  currentPrincipal: VaultPrincipalKeyPair;
  currentEncryptedProfile: EncryptedVaultRecord;
  newRecoveryPassword: string;
  revokePrincipalIds?: readonly string[];
}) {
  const revokePrincipalIds = [...new Set(input.revokePrincipalIds ?? [])];
  if (revokePrincipalIds.includes(input.currentPrincipal.principalId)) {
    throw new Error("The rotating administrator cannot revoke itself.");
  }
  const { vault } = await input.client.getVaultState(input.organizationId) as { vault: VaultState };
  if (!Number.isInteger(vault.keyVersion) || vault.keyVersion < 1) {
    throw new Error("PAYO returned an invalid vault key version.");
  }
  const activeMembers = vault.members.filter((member) =>
    !member.revokedAt && !revokePrincipalIds.includes(member.principalId));
  const memberKeys = new Map(activeMembers.map((member) => [
    member.principalId,
    { principalId: member.principalId, publicKey: member.vaultPublicKey } satisfies VaultPrincipal,
  ]));
  if (!memberKeys.has(input.currentPrincipal.principalId)) {
    throw new Error("The current administrator is not an active vault member.");
  }
  const recipientsFor = (record: EncryptedVaultRecord): VaultPrincipal[] => {
    const principalIds = new Set(record.wrappedKeys.map(({ principalId }) => principalId));
    const recipients = [...principalIds]
      .filter((principalId) => !revokePrincipalIds.includes(principalId))
      .map((principalId) => memberKeys.get(principalId));
    if (recipients.some((principal) => !principal)) {
      throw new Error("A vault record contains a recipient without an active organization key.");
    }
    if (!principalIds.has(input.currentPrincipal.principalId)) {
      throw new Error("The current administrator cannot rotate one or more encrypted records.");
    }
    return recipients as VaultPrincipal[];
  };

  const { records: summaries } = await input.client.listEncryptedRecords(input.organizationId);
  const records = await Promise.all(summaries.map(async (summary) => {
    const { record } = await input.client.getEncryptedRecord({
      organizationId: input.organizationId,
      recordId: summary.id,
      revision: summary.revision,
    });
    const envelope = (record as { envelope?: EncryptedVaultRecord }).envelope;
    if (!envelope) throw new Error(`Encrypted vault record ${summary.id} is missing its envelope.`);
    const revision = summary.revision + 1;
    return {
      recordId: summary.id,
      recordType: summary.recordType,
      revision,
      envelope: rotateVaultRecordKey(
        envelope,
        input.currentPrincipal,
        recipientsFor(envelope),
        revision,
      ),
    };
  }));
  const encryptedProfile = rotateVaultRecordKey(
    input.currentEncryptedProfile,
    input.currentPrincipal,
    recipientsFor(input.currentEncryptedProfile),
    input.currentEncryptedProfile.aad.revision + 1,
  );
  const organizationSecret = toHex(randomBytes(32));
  const nextKeyVersion = vault.keyVersion + 1;
  const recoveryPackage = await createVaultRecoveryPackage(
    input.organizationId,
    { organizationSecret, principal: input.currentPrincipal },
    input.newRecoveryPassword,
  );
  const grants = activeMembers
    .filter(({ role, principalId }) => role === "admin" && principalId !== input.currentPrincipal.principalId)
    .map((member) => {
      const grantId = generateUuidV7();
      return {
        grantId,
        granteePrincipalId: member.principalId,
        envelope: encryptVaultRecord(
          { organizationSecret, keyVersion: nextKeyVersion },
          {
            schemaVersion: 1,
            organizationId: input.organizationId,
            recordType: "vault-key-grant",
            recordId: grantId,
            revision: nextKeyVersion,
          },
          [memberKeys.get(member.principalId)!],
        ),
      };
    });
  await input.client.rotateVault(input.organizationId, {
    expectedKeyVersion: vault.keyVersion,
    recoveryPackageHash: hashCanonicalJson(recoveryPackage),
    encryptedProfile,
    records,
    grants,
    revokePrincipalIds,
  });
  return {
    organizationId: input.organizationId,
    organizationSecret,
    principal: input.currentPrincipal,
    encryptedProfile,
    recoveryPackage,
    keyVersion: nextKeyVersion,
  };
}
