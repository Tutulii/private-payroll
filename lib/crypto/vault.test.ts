import { describe, expect, it } from "vitest";
import {
  createVaultRecoveryPackage,
  decryptVaultRecord,
  encryptVaultRecord,
  generateVaultPrincipal,
  recoverVaultRecoveryPackage,
  rewrapVaultRecord,
  createSecondAdminEnrollment,
  recoverSecondAdminEnrollment,
  rotateVaultRecordKey,
} from "./vault";

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

describe("vault key lifecycle", () => {
  it("password-protects a second-admin enrollment key and binds its public identity", async () => {
    const enrollment = await createSecondAdminEnrollment({
      organizationId: "0198ddf0-9c00-7000-8000-000000000001",
      principalId: "did:privy:second-admin",
      password: "a separate recovery password",
      createdAt: "2026-08-24T12:00:00.000Z",
    });
    expect(JSON.stringify(enrollment)).not.toContain("secretKey");
    await expect(recoverSecondAdminEnrollment(enrollment, "wrong password value"))
      .rejects.toThrow(/invalid/i);
    await expect(recoverSecondAdminEnrollment(enrollment, "a separate recovery password"))
      .resolves.toMatchObject({
        principalId: enrollment.principalId,
        publicKey: enrollment.publicKey,
      });
  }, 30_000);

  it("adds a second administrator without exposing plaintext", () => {
    const firstAdmin = generateVaultPrincipal("admin-one");
    const secondAdmin = generateVaultPrincipal("admin-two");
    const record = encryptVaultRecord({ salary: "5000000" }, aad, [firstAdmin]);

    const rewrapped = rewrapVaultRecord(record, firstAdmin, [firstAdmin, secondAdmin]);
    expect(rewrapped.ciphertext).toBe(record.ciphertext);
    expect(rewrapped.wrappedKeys).toHaveLength(2);
    expect(decryptVaultRecord(rewrapped, secondAdmin)).toEqual({ salary: "5000000" });
  });

  it("rotates the DEK and fails closed for a revoked principal", () => {
    const admin = generateVaultPrincipal("admin");
    const reviewer = generateVaultPrincipal("reviewer");
    const record = encryptVaultRecord({ net: "4200000" }, aad, [admin, reviewer]);

    const rotated = rotateVaultRecordKey(record, admin, [admin], 2);
    expect(rotated.ciphertext).not.toBe(record.ciphertext);
    expect(rotated.aad.revision).toBe(2);
    expect(decryptVaultRecord(rotated, admin)).toEqual({ net: "4200000" });
    expect(() => decryptVaultRecord(rotated, reviewer)).toThrow(/not authorized/i);
    expect(() => rotateVaultRecordKey(record, admin, [admin], 1)).toThrow(/newer/i);
  });

  it("rejects duplicate principals and malformed X25519 public keys", () => {
    const admin = generateVaultPrincipal("admin");
    expect(() => encryptVaultRecord({}, aad, [admin, admin])).toThrow(/unique/i);
    expect(() => encryptVaultRecord({}, aad, [{ principalId: "bad", publicKey: "AAAA" }])).toThrow(/32-byte/i);
  });
});

describe("vault recovery", () => {
  it("round-trips organization recovery material with Argon2id", async () => {
    const principal = generateVaultPrincipal("owner");
    const material = {
      organizationSecret: `0x${"ab".repeat(32)}`,
      principal,
    };
    const pkg = await createVaultRecoveryPackage(
      "organization-001",
      material,
      "correct horse battery staple",
      "2026-08-24T00:00:00.000Z",
    );

    expect(pkg.algorithm).toBe("ARGON2ID+XCHACHA20-POLY1305");
    expect(pkg.kdf.memoryKiB).toBeGreaterThanOrEqual(65_536);
    expect(JSON.stringify(pkg)).not.toContain(material.organizationSecret);
    expect(JSON.stringify(pkg)).not.toContain(principal.secretKey);
    await expect(recoverVaultRecoveryPackage(pkg, "correct horse battery staple")).resolves.toEqual(material);
  }, 30_000);

  it("fails closed for a wrong password, tampering, and weak passwords", async () => {
    const material = {
      organizationSecret: `0x${"cd".repeat(32)}`,
      principal: generateVaultPrincipal("owner"),
    };
    const pkg = await createVaultRecoveryPackage(
      "organization-001",
      material,
      "a sufficiently long password",
    );
    await expect(recoverVaultRecoveryPackage(pkg, "a different long password")).rejects.toThrow(/invalid/i);
    await expect(recoverVaultRecoveryPackage({ ...pkg, organizationId: "organization-002" }, "a sufficiently long password")).rejects.toThrow(/invalid/i);
    await expect(createVaultRecoveryPackage("organization-001", material, "short")).rejects.toThrow(/12/);
  }, 30_000);
});
