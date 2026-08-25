import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  createVaultRecoveryPackage,
  decryptVaultRecord,
  encryptVaultRecord,
  recoverSecondAdminEnrollment,
  rewrapVaultRecord,
  type EncryptedVaultRecord,
  type VaultPrincipalKeyPair,
  type VaultRecoveryPackage,
  type VaultSecondAdminEnrollment,
} from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import type { PayoClient } from "./payo-client";

export function prepareSecondAdminGrant(input: {
  organizationId: string;
  organizationSecret: string;
  authorizingPrincipal: VaultPrincipalKeyPair;
  encryptedProfile: EncryptedVaultRecord;
  enrollment: VaultSecondAdminEnrollment;
  keyVersion: number;
}) {
  if (input.enrollment.organizationId !== input.organizationId) {
    throw new Error("The second-admin enrollment belongs to another organization.");
  }
  if (input.enrollment.principalId === input.authorizingPrincipal.principalId) {
    throw new Error("A second administrator must use a different authenticated principal.");
  }
  if (!Number.isInteger(input.keyVersion) || input.keyVersion < 1) {
    throw new Error("The organization key version is invalid.");
  }
  const grantee = {
    principalId: input.enrollment.principalId,
    publicKey: input.enrollment.publicKey,
  };
  const grantId = generateUuidV7();
  const envelope = encryptVaultRecord(
    { organizationSecret: input.organizationSecret, keyVersion: input.keyVersion },
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "vault-key-grant",
      recordId: grantId,
      revision: input.keyVersion,
    },
    [grantee],
  );
  const encryptedProfile = rewrapVaultRecord(
    input.encryptedProfile,
    input.authorizingPrincipal,
    [input.authorizingPrincipal, grantee],
  );
  return {
    grantId,
    granteePrincipalId: grantee.principalId,
    vaultPublicKey: grantee.publicKey,
    keyVersion: input.keyVersion,
    envelope,
    encryptedProfile,
  };
}

export async function finishSecondAdminRecovery(input: {
  client: PayoClient;
  enrollment: VaultSecondAdminEnrollment;
  password: string;
}): Promise<{
  organizationId: string;
  organizationSecret: string;
  principal: VaultPrincipalKeyPair;
  recoveryPackage: VaultRecoveryPackage;
  recoveryPackageHash: string;
}> {
  const principal = await recoverSecondAdminEnrollment(input.enrollment, input.password);
  const { grant } = await input.client.getVaultKeyGrant(input.enrollment.organizationId);
  const material = decryptVaultRecord<{ organizationSecret: string; keyVersion: number }>(
    grant.envelope,
    principal,
  );
  if (material.keyVersion !== grant.keyVersion || material.keyVersion < 1) {
    throw new Error("The second-admin grant has an invalid key version.");
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(material.organizationSecret)) {
    throw new Error("The second-admin grant contains an invalid organization key.");
  }
  const recoveryPackage = await createVaultRecoveryPackage(
    input.enrollment.organizationId,
    { organizationSecret: material.organizationSecret, principal },
    input.password,
  );
  return {
    organizationId: input.enrollment.organizationId,
    organizationSecret: material.organizationSecret,
    principal,
    recoveryPackage,
    recoveryPackageHash: hashCanonicalJson(recoveryPackage),
  };
}
