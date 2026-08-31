import { ec } from "starknet";
import { describe, expect, it } from "vitest";
import type { DirectPrivacyAccountConfig } from "@/lib/domain/direct-privacy";
import {
  buildConfigurePolicyCall,
  buildRevokePolicyCall,
  buildRotatePolicyOwnerCall,
  buildRotatePolicySessionKeyCall,
  buildSetPolicyAccountPausedCall,
  computePolicyOwnerAcceptanceHash,
} from "./policy-account-configuration";

const root = `0x${"ab".repeat(32)}` as `0x${string}`;

const config: DirectPrivacyAccountConfig = {
  version: "payo-direct-privacy-account-v1",
  chainId: "0x1",
  policyAccountAddress: "0x111",
  policyId: "0x222",
  sessionPublicKey: "0x333",
  sealMode: 0,
  proofVersion: 2,
  schemaVersion: 1,
  payrollPolicyRoot: root,
  tokenSetCommitment: "0x444",
  recipientSetCommitment: "0x555",
  purposeCommitment: "0x666",
  amountLimitCommitment: "0x777",
  authorizedRunsRoot: "0x888",
  validAfterUnix: "100",
  validBeforeUnix: "200",
  periodSeconds: "60",
  maxCallsPerPeriod: 2,
  maxCallCount: 3,
  poolAddress: "0x999",
  sealAddress: "0xaaa",
  tokenAddresses: { STRK: "0xbbb", USDC: "0xccc" },
  sdkVersion: "0.14.3-rc.5",
  sdkRevision: "66e3caae8c0201227a6719696d004e30d90aea65",
};

describe("policy-account configuration call", () => {
  it("serializes the exact Cairo PolicyConfig without any secret material", () => {
    const call = buildConfigurePolicyCall(config);
    const policyRoot = BigInt(root);
    expect(call).toEqual({
      contractAddress: "0x111",
      entrypoint: "configure_policy",
      calldata: [
        "0x222",
        "0x333",
        "0x999",
        "0xaaa",
        "0x0",
        "0x2",
        "0x1",
        `0x${(policyRoot >> 128n).toString(16)}`,
        `0x${(policyRoot & ((1n << 128n) - 1n)).toString(16)}`,
        "0x444",
        "0x555",
        "0x666",
        "0x777",
        "0x888",
        "0x64",
        "0xc8",
        "0x3c",
        "0x2",
        "0x3",
      ],
    });
    expect(JSON.stringify(call)).not.toContain("private");
    expect(call.calldata).toHaveLength(19);
  });

  it("builds exact owner-only pause, rotation and revocation self-calls", () => {
    expect(buildSetPolicyAccountPausedCall({ policyAccountAddress: "0x111", paused: true }))
      .toEqual({ contractAddress: "0x111", entrypoint: "set_policy_account_paused", calldata: ["0x1"] });
    expect(buildRotatePolicySessionKeyCall({
      policyAccountAddress: "0x111",
      policyId: "0x222",
      newSessionPublicKey: "0xabc",
    })).toEqual({
      contractAddress: "0x111",
      entrypoint: "rotate_session_key",
      calldata: ["0x222", "0xabc"],
    });
    expect(buildRevokePolicyCall({ policyAccountAddress: "0x111", policyId: "0x222" }))
      .toEqual({ contractAddress: "0x111", entrypoint: "revoke_policy", calldata: ["0x222"] });
    expect(() => buildRotatePolicySessionKeyCall({
      policyAccountAddress: "0x111",
      policyId: "0x222",
      newSessionPublicKey: "0x0",
    })).toThrow(/cannot be zero/);
  });

  it("requires a valid new-owner acceptance signature for owner recovery", () => {
    const newOwnerPrivateKey = "0x12345";
    const newOwnerPublicKey = ec.starkCurve.getStarkKey(newOwnerPrivateKey);
    const digest = computePolicyOwnerAcceptanceHash({
      policyAccountAddress: "0x111",
      currentOwnerPublicKey: "0x222",
    });
    const signed = ec.starkCurve.sign(digest, newOwnerPrivateKey);
    expect(buildRotatePolicyOwnerCall({
      policyAccountAddress: "0x111",
      currentOwnerPublicKey: "0x222",
      newOwnerPublicKey,
      newOwnerAcceptanceSignature: [signed.r.toString(), signed.s.toString()],
    })).toEqual({
      contractAddress: "0x111",
      entrypoint: "set_public_key",
      calldata: [
        `0x${BigInt(newOwnerPublicKey).toString(16)}`,
        "0x2",
        `0x${signed.r.toString(16)}`,
        `0x${signed.s.toString(16)}`,
      ],
    });
    expect(() => buildRotatePolicyOwnerCall({
      policyAccountAddress: "0x111",
      currentOwnerPublicKey: "0x222",
      newOwnerPublicKey,
      newOwnerAcceptanceSignature: ["0x1", "0x2"],
    })).toThrow(/did not sign/);
  });
});
