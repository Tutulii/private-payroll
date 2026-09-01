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
const treasury = {
  policyAccountAddress: "0x123",
  organizationId: "organization-00000001",
  poolAddress: "0x456",
} as const;

describe("direct private account encryption", () => {
  it("round-trips encrypted capability and treasury secrets independently", () => {
    const secrets = {
      version: "payo-direct-privacy-secrets-v2" as const,
      sessionPrivateKey: `0x${"01".repeat(32)}` as `0x${string}`,
      proofPrincipal: {
        principalId: "agent-proof-principal-1",
        publicKey: "A".repeat(44),
        secretKey: "B".repeat(44),
      },
    };
    const treasurySecrets = {
      version: "payo-direct-privacy-treasury-secrets-v1" as const,
      viewingKey: "0x123" as const,
    };
    const encrypted = encryptDirectPrivacyPayload(
      secrets,
      { ...base, purpose: "secrets" },
      key,
    );
    const encryptedTreasury = encryptDirectPrivacyPayload(
      treasurySecrets,
      { ...treasury, purpose: "treasury-secrets" },
      key,
    );
    expect(JSON.stringify(encrypted)).not.toContain(secrets.sessionPrivateKey);
    expect(JSON.stringify(encryptedTreasury)).not.toContain(treasurySecrets.viewingKey);
    expect(decryptDirectPrivacyPayload(
      encrypted,
      { ...base, purpose: "secrets" },
      key,
    )).toEqual(secrets);
    expect(decryptDirectPrivacyPayload(
      encryptedTreasury,
      { ...treasury, purpose: "treasury-secrets" },
      key,
    )).toEqual(treasurySecrets);
  });

  it("binds private state to its monotonic version", () => {
    const encrypted = encryptDirectPrivacyPayload(
      emptyDirectPrivacyState(),
      { ...treasury, purpose: "treasury-state", stateVersion: 3 },
      key,
    );
    expect(() => decryptDirectPrivacyPayload(
      encrypted,
      { ...treasury, purpose: "treasury-state", stateVersion: 4 },
      key,
    )).toThrow(/could not be decrypted/);
  });

  it("keeps recovered private transaction history inside treasury encryption", () => {
    const state = emptyDirectPrivacyState();
    state.history = [{
      blockNumber: 42,
      transactionHash: "0xabc",
      notes: [{
        channelKind: "outgoing",
        token: "0x111",
        noteIndex: 3,
        noteId: "0x222",
        counterparty: "0x333",
        amount: "987654321012345678",
        salt: "0x444",
      }],
      deposits: [],
      withdrawals: [],
      openNoteDeposits: [],
      registeredPubkey: null,
    }];
    const encrypted = encryptDirectPrivacyPayload(
      state,
      { ...treasury, purpose: "treasury-state", stateVersion: 5 },
      key,
    );
    expect(JSON.stringify(encrypted)).not.toContain("987654321012345678");
    expect(JSON.stringify(encrypted)).not.toContain("0x333");
    expect(decryptDirectPrivacyPayload(
      encrypted,
      { ...treasury, purpose: "treasury-state", stateVersion: 5 },
      key,
    )).toEqual(state);
  });

  it("rejects cross-tenant substitution, tampering and a wrong key", () => {
    const encrypted = encryptDirectPrivacyPayload(
      emptyDirectPrivacyState(),
      { ...treasury, purpose: "treasury-state", stateVersion: 1 },
      key,
    );
    expect(() => decryptDirectPrivacyPayload(
      encrypted,
      { ...treasury, organizationId: "organization-00000002", purpose: "treasury-state", stateVersion: 1 },
      key,
    )).toThrow(/could not be decrypted/);
    expect(() => decryptDirectPrivacyPayload(
      { ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -2)}AA` },
      { ...treasury, purpose: "treasury-state", stateVersion: 1 },
      key,
    )).toThrow(/could not be decrypted/);
    expect(() => decryptDirectPrivacyPayload(
      encrypted,
      { ...treasury, purpose: "treasury-state", stateVersion: 1 },
      otherKey,
    )).toThrow(/does not match/);
  });
});
