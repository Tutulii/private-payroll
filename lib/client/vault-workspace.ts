import { randomBytes } from "@noble/ciphers/utils.js";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { toHex } from "@/lib/crypto/encoding";
import {
  createVaultRecoveryPackage,
  encryptVaultRecord,
  generateVaultPrincipal,
  recoverVaultRecoveryPackage,
  type EncryptedVaultRecord,
  type VaultPrincipalKeyPair,
  type VaultRecoveryPackage,
} from "@/lib/crypto/vault";
import {
  generateUuidV7,
  organizationRecordSchema,
  principalRecordSchema,
} from "@/lib/domain/records";

export type VaultWorkspace = {
  organizationId: string;
  organizationSecret: string;
  principal: VaultPrincipalKeyPair;
  encryptedProfile: EncryptedVaultRecord;
  initialPrincipal: {
    recordId: string;
    envelope: EncryptedVaultRecord;
  };
  recoveryPackage: VaultRecoveryPackage;
  recoveryPackageHash: `0x${string}`;
};

export async function createVaultWorkspace(input: {
  principalId: string;
  organizationName: string;
  recoveryPassword: string;
  now?: Date;
}): Promise<VaultWorkspace> {
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const organizationId = generateUuidV7(now.getTime());
  const principal = generateVaultPrincipal(input.principalId);
  const organizationSecret = toHex(randomBytes(32));
  const profile = organizationRecordSchema.parse({
    schemaVersion: 1,
    id: organizationId,
    name: input.organizationName.trim(),
    enabledTokens: ["STRK", "USDC"],
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  const encryptedProfile = encryptVaultRecord(
    profile,
    {
      schemaVersion: 1,
      organizationId,
      recordType: "organization-profile",
      recordId: organizationId,
      revision: 1,
    },
    [principal],
  );
  const principalRecord = principalRecordSchema.parse({
    schemaVersion: 1,
    id: generateUuidV7(now.getTime() + 1),
    organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    kind: "admin",
    displayName: "Workspace administrator",
    accessState: "vault_grantee",
    vaultPrincipalId: principal.principalId,
    vaultPublicKey: principal.publicKey,
    status: "active",
  });
  const principalEnvelope = encryptVaultRecord(
    principalRecord,
    {
      schemaVersion: 1,
      organizationId,
      recordType: "principal",
      recordId: principalRecord.id,
      revision: 1,
    },
    [principal],
  );
  const recoveryPackage = await createVaultRecoveryPackage(
    organizationId,
    { organizationSecret, principal },
    input.recoveryPassword,
    timestamp,
  );
  return {
    organizationId,
    organizationSecret,
    principal,
    encryptedProfile,
    initialPrincipal: { recordId: principalRecord.id, envelope: principalEnvelope },
    recoveryPackage,
    recoveryPackageHash: hashCanonicalJson(recoveryPackage),
  };
}

export async function unlockVaultWorkspace(
  recoveryPackage: VaultRecoveryPackage,
  password: string,
) {
  const material = await recoverVaultRecoveryPackage(recoveryPackage, password);
  return {
    organizationId: recoveryPackage.organizationId,
    organizationSecret: material.organizationSecret,
    principal: material.principal,
  };
}
