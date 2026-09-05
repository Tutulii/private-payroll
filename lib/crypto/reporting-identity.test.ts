import { describe, expect, it } from "vitest";
import { encryptVaultRecord, decryptVaultRecord, generateVaultPrincipal } from "./vault";
import {
  assertReportingIdentityKeyPair,
  createReadyReportingIdentity,
  deriveDirectStrk20ReportingIdentity,
  parsePayoReportingIdentity,
} from "./reporting-identity";

const context = {
  chainId: "0x534e5f4d41494e" as const,
  poolAddress: "0x40337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a" as const,
  recipientAddress: "0x789" as const,
};

describe("STRK20 reporting identities", () => {
  it("deterministically derives a context-bound reporting key without exporting the viewing key", () => {
    const first = deriveDirectStrk20ReportingIdentity({
      viewingKey: "0x123456",
      context,
      createdAt: new Date("2026-09-05T00:00:00.000Z"),
    });
    const second = deriveDirectStrk20ReportingIdentity({
      viewingKey: "0x123456",
      context,
      createdAt: new Date("2026-09-06T00:00:00.000Z"),
    });
    expect(first.principal).toEqual(second.principal);
    expect(first.identity.fingerprint).toBe(second.identity.fingerprint);
    expect(first.identity.createdAt).not.toBe(second.identity.createdAt);
    expect(first.identity.mode).toBe("direct_strk20_viewing_key");
    expect(JSON.stringify(first.identity)).not.toContain("123456");
    expect(first.identity).toHaveProperty("ownershipProof.scheme", "stark-ecdsa-v1");
    expect(() => assertReportingIdentityKeyPair(first)).not.toThrow();
  });

  it("separates reporting keys by recipient and deployment context", () => {
    const first = deriveDirectStrk20ReportingIdentity({ viewingKey: "0x123456", context });
    const anotherRecipient = deriveDirectStrk20ReportingIdentity({
      viewingKey: "0x123456",
      context: { ...context, recipientAddress: "0x790" },
    });
    const anotherPool = deriveDirectStrk20ReportingIdentity({
      viewingKey: "0x123456",
      context: { ...context, poolAddress: "0x123" },
    });
    expect(anotherRecipient.principal.secretKey).not.toBe(first.principal.secretKey);
    expect(anotherPool.principal.secretKey).not.toBe(first.principal.secretKey);
  });

  it("accepts and canonicalizes the official zero-padded Mainnet pool address", () => {
    const derived = deriveDirectStrk20ReportingIdentity({
      viewingKey: "0x123456",
      context: {
        ...context,
        poolAddress: "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a",
      },
    });
    expect(derived.identity.context.poolAddress).toBe(context.poolAddress);
  });

  it("decrypts only with the matching direct reporting identity", () => {
    const worker = deriveDirectStrk20ReportingIdentity({ viewingKey: "0x123456", context });
    const stranger = deriveDirectStrk20ReportingIdentity({ viewingKey: "0x123457", context });
    const envelope = encryptVaultRecord(
      { incomeAtomic: "100" },
      {
        schemaVersion: 1,
        organizationId: "01991f00-1000-7000-8000-000000000001",
        recordType: "worker-income-source",
        recordId: "01991f00-1001-7000-8000-000000000002",
        revision: 1,
      },
      [worker.identity],
    );
    expect(decryptVaultRecord(envelope, worker.principal)).toEqual({ incomeAtomic: "100" });
    expect(() => decryptVaultRecord(envelope, stranger.principal)).toThrow(/not authorized/i);
  });

  it("rejects invalid viewing scalars and mutated public identities", () => {
    expect(() => deriveDirectStrk20ReportingIdentity({ viewingKey: "0x0", context }))
      .toThrow(/scalar range/i);
    const derived = deriveDirectStrk20ReportingIdentity({ viewingKey: "0x123456", context });
    expect(() => parsePayoReportingIdentity({
      ...derived.identity,
      context: { ...derived.identity.context, recipientAddress: "0x999" },
    })).toThrow(/fingerprint/i);
    const directIdentity = derived.identity;
    if (directIdentity.mode !== "direct_strk20_viewing_key") throw new Error("Expected direct identity.");
    expect(() => parsePayoReportingIdentity({
      ...directIdentity,
      ownershipProof: { ...directIdentity.ownershipProof, r: "0x1" },
    })).toThrow(/ownership proof/i);
  });

  it("labels Ready as an explicit PAYO-X25519 fallback without claiming viewing-key access", () => {
    const principal = generateVaultPrincipal("ready-worker");
    const ready = createReadyReportingIdentity({ principal, context });
    expect(ready.identity).toMatchObject({
      mode: "ready_payo_x25519",
      readyViewingKeyAccess: "not_available",
      principalId: principal.principalId,
      publicKey: principal.publicKey,
    });
    expect(ready.principal).toBe(principal);
    expect(() => assertReportingIdentityKeyPair(ready)).not.toThrow();
  });
});
