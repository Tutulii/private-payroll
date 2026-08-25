import { describe, expect, it, vi } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import {
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
