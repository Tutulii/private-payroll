import { describe, expect, it } from "vitest";
import { generateUuidV7, uuidV7Schema, vaultRecoveryPackageSchema } from "./records";

describe("canonical record schemas", () => {
  it("generates deterministic RFC 9562 UUIDv7 identifiers", () => {
    const identifier = generateUuidV7(
      Date.parse("2026-08-24T12:34:56.789Z"),
      Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
    );
    expect(identifier).toBe("01a033c4-4895-7001-8203-040506070809");
    expect(uuidV7Schema.parse(identifier)).toBe(identifier);
  });

  it("rejects UUIDv4 identifiers at the persistent-record boundary", () => {
    expect(() => uuidV7Schema.parse("550e8400-e29b-41d4-a716-446655440000")).toThrow();
  });

  it("requires memory-hard encrypted recovery packages", () => {
    const organizationId = generateUuidV7(1_775_000_000_000, new Uint8Array(10));
    expect(() => vaultRecoveryPackageSchema.parse({
      packageVersion: "payo-vault-recovery-v1",
      organizationId,
      algorithm: "ARGON2ID+XCHACHA20-POLY1305",
      kdf: { salt: "c2FsdC1mb3ItcGF5bw==", memoryKiB: 1024, iterations: 1, parallelism: 1 },
      nonce: "bm9uY2UtZm9yLXBheW8=",
      ciphertext: "Y2lwaGVydGV4dC1mb3ItcGF5by1yZWNvdmVyeQ==",
      createdAt: "2026-08-24T00:00:00.000Z",
    })).toThrow();
  });
});
