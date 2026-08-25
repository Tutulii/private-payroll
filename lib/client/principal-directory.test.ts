import { describe, expect, it, vi } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import { prepareEncryptedPayee } from "./payee-directory";
import { completeEncryptedPrincipalDirectory } from "./principal-directory";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const now = new Date("2026-08-24T12:00:00.000Z");

describe("encrypted principal directory", () => {
  it("atomically backfills the vault administrator and legacy payee identities", async () => {
    const vaultPrincipal = generateVaultPrincipal("did:privy:admin");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Scout",
      principalKind: "agent",
      recipientAddress: "0x123",
      tokenPreference: "STRK",
      jurisdictionCode: "US",
      principal: vaultPrincipal,
      now,
    }).record;
    const storeEncryptedRecords = vi.fn().mockResolvedValue({ records: [] });
    const records = await completeEncryptedPrincipalDirectory({
      client: { storeEncryptedRecords } as never,
      organizationId,
      vaultPrincipal,
      existingPrincipals: [],
      payees: [payee],
      now,
    });
    expect(records.map(({ kind }) => kind)).toEqual(["admin", "agent"]);
    expect(records[1]).toMatchObject({ id: payee.principalId, accessState: "directory_only" });
    const request = storeEncryptedRecords.mock.calls[0][0];
    expect(request.records).toHaveLength(2);
    expect(JSON.stringify(request.records)).not.toContain("Scout");
    expect(request.records[0].envelope.ciphertext).not.toContain("did:privy:admin");
  });

  it("does not rewrite an already complete directory", async () => {
    const vaultPrincipal = generateVaultPrincipal("did:privy:admin");
    const existing = {
      schemaVersion: 1 as const,
      id: "018f1000-0000-7000-8000-000000000002",
      organizationId,
      revision: 1,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      kind: "admin" as const,
      displayName: "Admin",
      accessState: "vault_grantee" as const,
      vaultPrincipalId: vaultPrincipal.principalId,
      vaultPublicKey: vaultPrincipal.publicKey,
      status: "active" as const,
    };
    const storeEncryptedRecords = vi.fn();
    await expect(completeEncryptedPrincipalDirectory({
      client: { storeEncryptedRecords } as never,
      organizationId,
      vaultPrincipal,
      existingPrincipals: [existing],
      payees: [],
      now,
    })).resolves.toEqual([]);
    expect(storeEncryptedRecords).not.toHaveBeenCalled();
  });
});
