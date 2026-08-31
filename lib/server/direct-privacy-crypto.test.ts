import { describe, expect, it } from "vitest";
import { emptyDirectPrivacyState } from "@/lib/domain/direct-privacy";
import {
  decryptDirectPrivacyPayload,
  encryptDirectPrivacyPayload,
} from "./direct-privacy-crypto";

const key = `0x${"11".repeat(32)}`;
const otherKey = `0x${"22".repeat(32)}`;
const base = {
  accountId: "account-00000001",
  organizationId: "organization-00000001",
  capabilityId: "capability-00000001",
} as const;

describe("direct private account encryption", () => {
  it("round-trips encrypted local spend/viewing material", () => {
    const secrets = {
      version: "payo-direct-privacy-secrets-v1" as const,
      sessionPrivateKey: `0x${"01".repeat(32)}` as `0x${string}`,
      viewingKey: "0x123" as const,
      proofPrincipal: {
        principalId: "agent-proof-principal-1",
        publicKey: "A".repeat(44),
        secretKey: "B".repeat(44),
      },
    };
    const encrypted = encryptDirectPrivacyPayload(
      secrets,
      { ...base, purpose: "secrets" },
      key,
    );
    expect(JSON.stringify(encrypted)).not.toContain(secrets.sessionPrivateKey);
    expect(JSON.stringify(encrypted)).not.toContain(secrets.viewingKey);
    expect(decryptDirectPrivacyPayload(
      encrypted,
      { ...base, purpose: "secrets" },
      key,
    )).toEqual(secrets);
  });

  it("binds private state to its monotonic version", () => {
    const encrypted = encryptDirectPrivacyPayload(
      emptyDirectPrivacyState(),
      { ...base, purpose: "state", stateVersion: 3 },
      key,
    );
    expect(() => decryptDirectPrivacyPayload(
      encrypted,
      { ...base, purpose: "state", stateVersion: 4 },
      key,
    )).toThrow(/could not be decrypted/);
  });

  it("rejects cross-tenant substitution, tampering and a wrong key", () => {
    const encrypted = encryptDirectPrivacyPayload(
      emptyDirectPrivacyState(),
      { ...base, purpose: "state", stateVersion: 1 },
      key,
    );
    expect(() => decryptDirectPrivacyPayload(
      encrypted,
      { ...base, organizationId: "organization-00000002", purpose: "state", stateVersion: 1 },
      key,
    )).toThrow(/could not be decrypted/);
    expect(() => decryptDirectPrivacyPayload(
      { ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -2)}AA` },
      { ...base, purpose: "state", stateVersion: 1 },
      key,
    )).toThrow(/could not be decrypted/);
    expect(() => decryptDirectPrivacyPayload(
      encrypted,
      { ...base, purpose: "state", stateVersion: 1 },
      otherKey,
    )).toThrow(/does not match/);
  });
});
