import { describe, expect, it, vi } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  loadCanonicalEncryptedRecords,
  prepareCanonicalEncryptedRecord,
  storeCanonicalEncryptedRecord,
} from "./encrypted-records";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const now = "2026-08-24T12:00:00.000Z";

function principalRecord() {
  return {
    schemaVersion: 1 as const,
    id: generateUuidV7(),
    organizationId,
    revision: 1,
    createdAt: now,
    updatedAt: now,
    kind: "worker" as const,
    displayName: "Private worker",
    accessState: "vault_grantee" as const,
    vaultPrincipalId: "worker:test",
    vaultPublicKey: "x25519-public-key-material",
    status: "active" as const,
  };
}

describe("canonical encrypted-record client", () => {
  it("validates before encryption and sends no plaintext fields", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const record = principalRecord();
    await expect(storeCanonicalEncryptedRecord({
      client: { storeEncryptedRecord } as never,
      organizationId,
      recordType: "principal",
      record,
      principals: [principal],
    })).resolves.toEqual(record);
    const request = storeEncryptedRecord.mock.calls[0][0];
    expect(request).toMatchObject({ recordId: record.id, recordType: "principal", revision: 1 });
    expect(JSON.stringify(request.envelope)).not.toContain(record.displayName);
  });

  it("decrypts a filtered listing and rejects storage-identity substitution", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const record = principalRecord();
    const prepared = prepareCanonicalEncryptedRecord({
      organizationId,
      recordType: "principal",
      record,
      principals: [principal],
    });
    const client = {
      listEncryptedRecords: vi.fn().mockResolvedValue({
        records: [{ id: record.id, recordType: "principal", revision: 1 }],
      }),
      getEncryptedRecord: vi.fn().mockResolvedValue({ record: { envelope: prepared.envelope } }),
    };
    await expect(loadCanonicalEncryptedRecords({
      client: client as never,
      organizationId,
      recordType: "principal",
      principal,
    })).resolves.toEqual([record]);

    client.listEncryptedRecords.mockResolvedValueOnce({
      records: [{ id: generateUuidV7(), recordType: "principal", revision: 1 }],
    });
    await expect(loadCanonicalEncryptedRecords({
      client: client as never,
      organizationId,
      recordType: "principal",
      principal,
    })).rejects.toThrow(/storage identity/i);
  });
});
