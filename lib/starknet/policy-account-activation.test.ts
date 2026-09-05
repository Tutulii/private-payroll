import { describe, expect, it } from "vitest";
import type { DirectPrivacyAccountConfig } from "@/lib/domain/direct-privacy";
import {
  assertPolicyAccountActivation,
  decodePolicyAccountState,
  type PolicyAccountActivationSnapshot,
} from "./policy-account-activation";

const ROOT = `0x${"12".repeat(32)}` as const;
const rootValue = BigInt(ROOT);
const rootHigh = rootValue >> 128n;
const rootLow = rootValue & ((1n << 128n) - 1n);

const config: DirectPrivacyAccountConfig = {
  version: "payo-direct-privacy-account-v1",
  chainId: "0x534e5f5345504f4c4941",
  policyAccountAddress: "0x111",
  policyId: "0x222",
  sessionPublicKey: "0x333",
  sealMode: 0,
  proofVersion: 1,
  schemaVersion: 1,
  payrollPolicyRoot: ROOT,
  tokenSetCommitment: "0x444",
  recipientSetCommitment: "0x555",
  purposeCommitment: "0x666",
  amountLimitCommitment: "0x777",
  authorizedRunsRoot: "0x888",
  validAfterUnix: "1000",
  validBeforeUnix: "2000",
  periodSeconds: "600",
  maxCallsPerPeriod: 2,
  maxCallCount: 4,
  poolAddress: "0x999",
  sealAddress: "0xaaa",
  tokenAddresses: { STRK: "0xbbb", USDC: "0xccc" },
  sdkVersion: "0.14.3-rc.5",
  sdkRevision: "66e3caae8c0201227a6719696d004e30d90aea65",
};

const encoded = [
  "0x1", "0x0", "0x333", "0x999", "0xaaa", "0x0", "0x0", "0x1", "0x1",
  `0x${rootHigh.toString(16)}`, `0x${rootLow.toString(16)}`,
  "0x444", "0x555", "0x666", "0x777", "0x888",
  "0x3e8", "0x7d0", "0x258", "0x2", "0x4", "0x3e8", "0x0", "0x0",
];

function snapshot(): PolicyAccountActivationSnapshot {
  return {
    chainId: config.chainId,
    classHash: "0xabc",
    blockNumber: 42n,
    blockHash: "0xdef",
    blockTimestamp: 1_500n,
    active: true,
    paused: false,
    policy: decodePolicyAccountState(encoded),
  };
}

describe("policy-account activation", () => {
  it("accepts one exact, unused, pinned policy account snapshot", () => {
    expect(() => assertPolicyAccountActivation({
      config,
      snapshot: snapshot(),
      expectedClassHash: "0xabc",
    })).not.toThrow();
  });

  it("rejects malformed ABI responses and every security-relevant substitution", () => {
    expect(() => decodePolicyAccountState(encoded.slice(1))).toThrow("unexpected PolicyState shape");
    expect(() => assertPolicyAccountActivation({
      config,
      snapshot: { ...snapshot(), classHash: "0xabd" },
      expectedClassHash: "0xabc",
    })).toThrow("class hash");
    expect(() => assertPolicyAccountActivation({
      config,
      snapshot: {
        ...snapshot(),
        policy: { ...snapshot().policy, authorizedRunsRoot: "0x889" },
      },
      expectedClassHash: "0xabc",
    })).toThrow("authorized-runs root");
    expect(() => assertPolicyAccountActivation({
      config,
      snapshot: {
        ...snapshot(),
        policy: { ...snapshot().policy, usedCallCount: 1 },
      },
      expectedClassHash: "0xabc",
    })).toThrow("used before verification");
  });
});
