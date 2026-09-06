import { describe, expect, it, vi } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  deactivateEncryptedPayee,
  loadEncryptedPayees,
  prepareEncryptedPayee,
  storeEncryptedPayee,
} from "./payee-directory";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const now = new Date("2026-08-24T12:00:00.000Z");

describe("encrypted payee directory", () => {
  it("validates and encrypts a human or agent without server plaintext", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const storeEncryptedRecords = vi.fn().mockResolvedValue({ records: [] });
    const record = await storeEncryptedPayee({
      client: { storeEncryptedRecords } as never,
      organizationId,
      displayName: "  Scout  ",
      principalKind: "agent",
      recipientAddress: "0x123",
      tokenPreference: "USDC",
      jurisdictionCode: "us-ca",
      principal,
      now,
    });
    expect(record).toMatchObject({ displayName: "Scout", principalKind: "agent", jurisdictionCode: "US-CA" });
    const request = storeEncryptedRecords.mock.calls[0][0];
    expect(request.records.map(({ recordType }: { recordType: string }) => recordType)).toEqual(["principal", "payee"]);
    expect(JSON.stringify(request.records)).not.toContain("Scout");
  });

  it("stores encrypted inactive payee and revoked principal revisions when removing a contributor", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const prepared = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "GB",
      principal,
      now,
    });
    const storeEncryptedRecords = vi.fn().mockResolvedValue({ records: [] });
    const removedAt = new Date("2026-08-25T18:30:00.000Z");
    const result = await deactivateEncryptedPayee({
      client: { storeEncryptedRecords } as never,
      record: prepared.record,
      directoryPrincipal: prepared.principalRecord,
      principal,
      now: removedAt,
    });

    expect(result.record).toMatchObject({ revision: 2, status: "inactive", updatedAt: removedAt.toISOString() });
    expect(result.directoryPrincipal).toMatchObject({ revision: 2, status: "revoked", updatedAt: removedAt.toISOString() });
    const request = storeEncryptedRecords.mock.calls[0][0];
    expect(request.records.map(({ recordType }: { recordType: string }) => recordType)).toEqual(["payee", "principal"]);
    expect(decryptVaultRecord(request.records[0].envelope, principal)).toMatchObject({ status: "inactive", revision: 2 });
    expect(decryptVaultRecord(request.records[1].envelope, principal)).toMatchObject({ status: "revoked", revision: 2 });
    expect(JSON.stringify(request.records)).not.toContain("Maya");
  });

  it("decrypts only authenticated payee envelopes and binds storage identity", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const prepared = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "STRK",
      jurisdictionCode: "GB",
      principal,
      now,
    });
    const client = {
      listEncryptedRecords: vi.fn().mockResolvedValue({
        records: [{ id: prepared.record.id, recordType: "payee", revision: 1 }],
      }),
      getEncryptedRecord: vi.fn().mockResolvedValue({
        record: { id: prepared.record.id, recordType: "payee", revision: 1, envelope: prepared.envelope },
      }),
    };
    await expect(loadEncryptedPayees({ client: client as never, organizationId, principal }))
      .resolves.toEqual([prepared.record]);
    await expect(loadEncryptedPayees({
      client: client as never,
      organizationId,
      principal: generateVaultPrincipal("admin:wrong"),
    })).rejects.toThrow(/not authorized/i);
  });
});
