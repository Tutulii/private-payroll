import { describe, expect, it, vi } from "vitest";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  generateVaultPrincipal,
  recoverVaultRecoveryPackage,
} from "@/lib/crypto/vault";
import type { PayoClient } from "./payo-client";
import { rotateClientVault } from "./vault-rotation";

const organizationId = "0198ddf0-9c00-7000-8000-000000000001";
const recordId = "0198ddf0-9c00-7000-8000-000000000002";

describe("client vault rotation", () => {
  it("freshly encrypts every record and cryptographically removes a revoked administrator", async () => {
    const first = generateVaultPrincipal("did:privy:first");
    const second = generateVaultPrincipal("did:privy:second");
    const profile = encryptVaultRecord(
      { name: "Private company" },
      { schemaVersion: 1, organizationId, recordType: "organization-profile", recordId: organizationId, revision: 1 },
      [first, second],
    );
    const record = encryptVaultRecord(
      { salaryAtomic: "9000000" },
      { schemaVersion: 1, organizationId, recordType: "payee", recordId, revision: 1 },
      [first, second],
    );
    const rotateVault = vi.fn().mockResolvedValue({ vault: { keyVersion: 2, recoveryState: "package_downloaded" } });
    const client = {
      getVaultState: vi.fn().mockResolvedValue({ vault: {
        keyVersion: 1,
        members: [
          { principalId: first.principalId, role: "admin", vaultPublicKey: first.publicKey, keyVersion: 1, revokedAt: null },
          { principalId: second.principalId, role: "admin", vaultPublicKey: second.publicKey, keyVersion: 1, revokedAt: null },
        ],
      } }),
      listEncryptedRecords: vi.fn().mockResolvedValue({ records: [{
        id: recordId,
        recordType: "payee",
        revision: 1,
        envelopeHash: "0x1",
        supersededAt: null,
        createdAt: new Date().toISOString(),
      }] }),
      getEncryptedRecord: vi.fn().mockResolvedValue({ record: { envelope: record } }),
      rotateVault,
    } as unknown as PayoClient;
    const result = await rotateClientVault({
      client,
      organizationId,
      currentPrincipal: first,
      currentEncryptedProfile: profile,
      newRecoveryPassword: "new recovery password",
      revokePrincipalIds: [second.principalId],
    });
    const rotation = rotateVault.mock.calls[0][1];
    expect(rotation.records).toHaveLength(1);
    expect(rotation.records[0].envelope.ciphertext).not.toBe(record.ciphertext);
    expect(rotation.records[0].envelope.aad.revision).toBe(2);
    expect(rotation.grants).toEqual([]);
    expect(decryptVaultRecord(rotation.records[0].envelope, first)).toMatchObject({ salaryAtomic: "9000000" });
    expect(() => decryptVaultRecord(rotation.records[0].envelope, second)).toThrow(/not authorized/i);
    await expect(recoverVaultRecoveryPackage(result.recoveryPackage, "new recovery password"))
      .resolves.toMatchObject({ organizationSecret: result.organizationSecret });
  }, 30_000);
});
