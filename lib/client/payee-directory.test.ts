import { describe, expect, it, vi } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  assertContributorWalletAvailable,
  contributorWalletAddressCommitment,
  deactivateEncryptedPayee,
  loadEncryptedPayees,
  prepareEncryptedPayee,
  reconcileEncryptedPayeeReferences,
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
    expect(request.contributorWalletConstraint).toEqual({
      action: "claim",
      payeeRecordId: record.id,
      addressCommitment: contributorWalletAddressCommitment({ organizationId, recipientAddress: "0x123" }),
    });
    expect(JSON.stringify(request.records)).not.toContain("Scout");
    expect(JSON.stringify(request)).not.toContain(record.recipientAddress);
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
    expect(request.contributorWalletConstraint).toEqual({
      action: "release",
      payeeRecordId: prepared.record.id,
      addressCommitment: contributorWalletAddressCommitment({ organizationId, recipientAddress: "0x456" }),
    });
    expect(decryptVaultRecord(request.records[0].envelope, principal)).toMatchObject({ status: "inactive", revision: 2 });
    expect(decryptVaultRecord(request.records[1].envelope, principal)).toMatchObject({ status: "revoked", revision: 2 });
    expect(JSON.stringify(request.records)).not.toContain("Maya");
  });

  it("rejects a second active contributor that uses the same normalized wallet", async () => {
    const principal = generateVaultPrincipal("admin:unique-wallet");
    const existing = prepareEncryptedPayee({
      organizationId,
      displayName: "Safik",
      principalKind: "human",
      recipientAddress: "0x123",
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      now,
    }).record;
    expect(() => assertContributorWalletAvailable("0x0123", [existing]))
      .toThrow(/already assigned to Safik/i);
    await expect(storeEncryptedPayee({
      client: { storeEncryptedRecords: vi.fn() } as never,
      organizationId,
      displayName: "Rakib",
      principalKind: "human",
      recipientAddress: "0x0123",
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      existingPayees: [existing],
      now,
    })).rejects.toThrow(/one wallet/i);
  });

  it("atomically reconciles historical names while preserving encrypted alias history", async () => {
    const principal = generateVaultPrincipal("admin:reference-resolution");
    const former = prepareEncryptedPayee({
      organizationId,
      displayName: "Simson",
      principalKind: "human",
      recipientAddress: "0x789",
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      now,
    });
    const current = prepareEncryptedPayee({
      organizationId,
      displayName: "Vesting canary",
      principalKind: "human",
      recipientAddress: "0x0789",
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      now: new Date(now.getTime() + 10),
    });
    const storeEncryptedRecords = vi.fn().mockResolvedValue({ records: [] });
    const result = await reconcileEncryptedPayeeReferences({
      client: { storeEncryptedRecords } as never,
      organizationId,
      records: [former.record, current.record],
      directoryPrincipals: [former.principalRecord, current.principalRecord],
      recipientAddress: former.record.recipientAddress,
      canonicalReference: "Simson",
      principal,
      now: new Date("2026-08-26T09:00:00.000Z"),
    });

    expect(result.records).toHaveLength(2);
    expect(result.records.every(({ displayName, revision }) => displayName === "Simson" && revision === 2)).toBe(true);
    expect(result.resolution).toMatchObject({
      resolutionVersion: "payo-recipient-reference-resolution-v1",
      recipientAddress: former.record.recipientAddress,
      canonicalReference: "Simson",
      historicalReferences: ["Simson", "Vesting canary"],
    });
    expect(result.records.every(({ recipientReferenceResolution }) =>
      recipientReferenceResolution?.resolutionId === result.resolution.resolutionId)).toBe(true);
    expect(result.directoryPrincipals.every(({ displayName }) => displayName === "Simson")).toBe(true);
    const request = storeEncryptedRecords.mock.calls[0][0];
    expect(request.records).toHaveLength(3);
    expect(request).not.toHaveProperty("contributorWalletConstraint");
    expect(request.records.map(({ recordType }: { recordType: string }) => recordType))
      .toEqual(["payee", "payee", "principal"]);
    expect(decryptVaultRecord(request.records[0].envelope, principal)).toMatchObject({
      displayName: "Simson",
      revision: 2,
      recipientReferenceResolution: {
        historicalReferences: ["Simson", "Vesting canary"],
      },
    });
    expect(JSON.stringify(request.records)).not.toContain("Vesting canary");
    expect(current.record.displayName).toBe("Vesting canary");
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
