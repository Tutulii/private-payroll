import { describe, expect, it } from "vitest";
import { typedData } from "starknet";
import {
  buildReadyAuthTypedData,
  READY_AUTH_CHAIN_ID,
  readyAuthChallengeRequestSchema,
  readyWalletPrincipalId,
} from "./ready-session";

const address = "0x0126a7a572cf8935d069af937e9f7b27a24949e271e1fbccfe4de0c0d8dc8ea9";

describe("Ready PAYO session protocol", () => {
  it("normalizes Mainnet addresses and derives a wallet-scoped principal", () => {
    const parsed = readyAuthChallengeRequestSchema.parse({ walletAddress: address, chainId: READY_AUTH_CHAIN_ID });
    expect(parsed.walletAddress).toBe(address);
    expect(readyWalletPrincipalId(parsed.chainId, parsed.walletAddress)).toBe(`starknet:${READY_AUTH_CHAIN_ID}:${address}`);
  });

  it("binds the signature hash to wallet, nonce, expiry and audience", () => {
    const base = { walletAddress: address, nonce: "0x1234", audience: "https://payo.test", issuedAt: 100, expiresAt: 400 };
    const first = typedData.getMessageHash(buildReadyAuthTypedData(base), address);
    const changedNonce = typedData.getMessageHash(buildReadyAuthTypedData({ ...base, nonce: "0x1235" }), address);
    const changedAudience = typedData.getMessageHash(buildReadyAuthTypedData({ ...base, audience: "https://evil.test" }), address);
    expect(first).toMatch(/^0x[0-9a-f]+$/);
    expect(changedNonce).not.toBe(first);
    expect(changedAudience).not.toBe(first);
  });

  it("rejects unsupported networks and malformed addresses", () => {
    expect(() => readyAuthChallengeRequestSchema.parse({ walletAddress: "0xno", chainId: READY_AUTH_CHAIN_ID })).toThrow();
    expect(() => readyAuthChallengeRequestSchema.parse({ walletAddress: address, chainId: "SN_SEPOLIA" })).toThrow();
  });
});
