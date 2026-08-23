import { describe, expect, it } from "vitest";
import { decryptVaultRecord, encryptVaultRecord, generateVaultPrincipal } from "./vault";

const aad = {
  schemaVersion: 1 as const,
  organizationId: "organization-0001",
  recordType: "payroll-run",
  recordId: "payroll-run-0001",
  revision: 1,
};

describe("client vault", () => {
  it("round-trips an encrypted record for every authorized principal", () => {
    const admin = generateVaultPrincipal("admin-0001");
    const worker = generateVaultPrincipal("worker-0001");
    const plaintext = { salary: "private", amountAtomic: "1500000" };
    const record = encryptVaultRecord(plaintext, aad, [admin, worker]);

    expect(record.ciphertext).not.toContain("private");
    expect(decryptVaultRecord(record, admin)).toEqual(plaintext);
    expect(decryptVaultRecord(record, worker)).toEqual(plaintext);
  });

  it("fails when associated data is moved to another organization", () => {
    const admin = generateVaultPrincipal("admin-0001");
    const record = encryptVaultRecord({ salary: "private" }, aad, [admin]);
    const tampered = {
      ...record,
      aad: { ...record.aad, organizationId: "organization-0002" },
    };

    expect(() => decryptVaultRecord(tampered, admin)).toThrow();
  });

  it("does not decrypt for an unwrapped principal", () => {
    const admin = generateVaultPrincipal("admin-0001");
    const stranger = generateVaultPrincipal("stranger-0001");
    const record = encryptVaultRecord({ salary: "private" }, aad, [admin]);

    expect(() => decryptVaultRecord(record, stranger)).toThrow("not authorized");
  });
});
