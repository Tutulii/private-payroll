import { describe, expect, it } from "vitest";
import { validateAndParseAddress } from "starknet";
import { READY_AUTH_CHAIN_ID } from "@/lib/auth/ready-session";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  createPayoPublicIdentity,
  proofPackageIdentityFingerprint,
} from "./proof-package-files";
import { verifyWalletBoundPublicIdentity } from "./wallet-bound-identity";

const reviewerWallet = "0x987";
const reviewer = generateVaultPrincipal("wallet-bound-reviewer");
const identity = createPayoPublicIdentity(
  reviewer,
  new Date("2026-09-07T00:00:00.000Z"),
);

function directoryRecord(overrides: Record<string, unknown> = {}) {
  return {
    chainId: READY_AUTH_CHAIN_ID,
    walletAddress: reviewerWallet,
    principalId: identity.principalId,
    fingerprint: identity.fingerprint,
    identity,
    firstPublishedAt: "2026-09-07T00:00:00.000Z",
    updatedAt: "2026-09-07T00:00:00.000Z",
    ...overrides,
  };
}

describe("wallet-bound PAYO identity verification", () => {
  it("accepts only public v2 material bound to the requested chain and wallet", () => {
    const verified = verifyWalletBoundPublicIdentity({
      expectedChainId: READY_AUTH_CHAIN_ID,
      expectedWalletAddress: "0x0987",
      record: directoryRecord(),
    });

    expect(verified.identity).toEqual(identity);
    expect(verified.walletAddress).toBe(validateAndParseAddress(reviewerWallet));
    expect(JSON.stringify(verified)).not.toContain(reviewer.secretKey);
  });

  it.each([
    ["another deployment", { chainId: "0x1" }, /another Starknet deployment/i],
    ["another wallet", { walletAddress: "0x988" }, /another Ready wallet/i],
    ["another principal", { principalId: "starknet:other" }, /principal/i],
    [
      "another outer fingerprint",
      { fingerprint: "0x" + "ab".repeat(32) },
      /fingerprint/i,
    ],
  ])("rejects %s", (_label, overrides, message) => {
    expect(() => verifyWalletBoundPublicIdentity({
      expectedChainId: READY_AUTH_CHAIN_ID,
      expectedWalletAddress: reviewerWallet,
      record: directoryRecord(overrides),
    })).toThrow(message);
  });

  it("rejects a self-consistent legacy identity", () => {
    const legacyBase = {
      format: "payo-public-identity-v1" as const,
      principalId: reviewer.principalId,
      publicKey: reviewer.publicKey,
      createdAt: "2026-09-07T00:00:00.000Z",
    };
    const legacy = {
      ...legacyBase,
      fingerprint: proofPackageIdentityFingerprint(legacyBase),
    };

    expect(() => verifyWalletBoundPublicIdentity({
      expectedChainId: READY_AUTH_CHAIN_ID,
      expectedWalletAddress: reviewerWallet,
      record: directoryRecord({
        principalId: legacy.principalId,
        fingerprint: legacy.fingerprint,
        identity: legacy,
      }),
    })).toThrow(/version 2/i);
  });

  it.each([
    null,
    {},
    directoryRecord({ unexpected: true }),
    directoryRecord({ fingerprint: "0x123" }),
    directoryRecord({ updatedAt: "yesterday" }),
  ])("rejects malformed directory records", (record) => {
    expect(() => verifyWalletBoundPublicIdentity({
      expectedChainId: READY_AUTH_CHAIN_ID,
      expectedWalletAddress: reviewerWallet,
      record,
    })).toThrow(/malformed/i);
  });

  it("rejects an invalid requested wallet before returning identity material", () => {
    expect(() => verifyWalletBoundPublicIdentity({
      expectedChainId: READY_AUTH_CHAIN_ID,
      expectedWalletAddress: "reviewer@example.com",
      record: directoryRecord(),
    })).toThrow(/requested wallet/i);
  });
});
