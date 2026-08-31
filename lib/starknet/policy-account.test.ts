import { describe, expect, it } from "vitest";
import type { AgentCapability } from "@/lib/domain/capability";
import {
  buildAuthorizedPolicyRunTree,
  commitPolicyCapability,
  computePolicyRunLeaf,
  verifyPolicyRunProof,
  type PolicyLeafContext,
  type PolicyRunBinding,
} from "./policy-account";

const root = (high: bigint, low: bigint) =>
  `0x${((high << 128n) | low).toString(16).padStart(64, "0")}` as `0x${string}`;

const capability: AgentCapability = {
  capabilityVersion: "payo-agent-capability-v1",
  id: "capability-0001",
  organizationId: "organization-0001",
  principalId: "agent-1",
  allowedActions: ["request_execution"],
  allowedTokens: ["STRK", "USDC"],
  recipientScope: { mode: "allowlist", addresses: ["0x33", "0x22"] },
  purposeCodes: ["bonus", "private_payroll"],
  limits: [
    {
      token: "STRK",
      maxPerPaymentAtomic: "1000",
      maxPerPeriodAtomic: "5000",
      spentThisPeriodAtomic: "0",
      periodStartsAt: "2026-08-30T00:00:00.000Z",
      periodEndsAt: "2026-08-31T00:00:00.000Z",
      approvalThresholdAtomic: "900",
    },
    {
      token: "USDC",
      maxPerPaymentAtomic: "2000",
      maxPerPeriodAtomic: "6000",
      spentThisPeriodAtomic: "0",
      periodStartsAt: "2026-08-30T00:00:00.000Z",
      periodEndsAt: "2026-08-31T00:00:00.000Z",
      approvalThresholdAtomic: "1800",
    },
  ],
  executionMode: "autonomous_bounded",
  maxCallCount: 4,
  usedCallCount: 0,
  validAfter: "2026-08-30T00:00:00.000Z",
  expiresAt: "2026-08-31T00:00:00.000Z",
  nonce: "0x1111111111111111",
};

const context: PolicyLeafContext = {
  policyId: "0x5041594f",
  sealMode: 0,
  proofVersion: 1,
  schemaVersion: 1,
  payrollPolicyRoot: root(41n, 42n),
  tokenSetCommitment: "0x33",
  recipientSetCommitment: "0x34",
  purposeCommitment: "0x35",
  amountLimitCommitment: "0x36",
};

const run = (offset: bigint): PolicyRunBinding => ({
  agreementRoot: root(11n, 12n + offset),
  manifestRoot: root(21n, 22n + offset),
  runNullifier: root(31n, 32n + offset),
});

describe("policy-account commitments", () => {
  it("matches the Cairo run-leaf vector", () => {
    expect(computePolicyRunLeaf(context, run(0n))).toBe(
      "0x37caed23da62c77c20fe581f9360c834aad52fcf558d6c2f2f8e3d743796462",
    );
  });

  it("commits exact autonomous capability scope deterministically", () => {
    const first = commitPolicyCapability(capability);
    const reordered = commitPolicyCapability({
      ...capability,
      allowedTokens: [...capability.allowedTokens].reverse(),
      purposeCodes: [...capability.purposeCodes].reverse(),
      limits: [...capability.limits].reverse(),
      recipientScope: {
        mode: "allowlist",
        addresses: [...(capability.recipientScope.mode === "allowlist" ? capability.recipientScope.addresses : [])].reverse(),
      },
    });
    expect(reordered).toEqual(first);
    expect(Object.values(first).every((value) => BigInt(value) !== 0n)).toBe(true);
  });

  it("refuses human approval and wildcard recipients as autonomous policy", () => {
    expect(() => commitPolicyCapability({ ...capability, executionMode: "request_approval" }))
      .toThrow(/explicitly autonomous/);
    expect(() => commitPolicyCapability({ ...capability, recipientScope: { mode: "any" } }))
      .toThrow(/exact recipient allowlist/);
  });

  it("builds and verifies every fixed-depth proof and rejects mutation", () => {
    const runs = [run(0n), run(1n), run(2n)];
    const tree = buildAuthorizedPolicyRunTree(context, runs);
    expect(tree.proofs).toHaveLength(3);
    for (const proof of tree.proofs) expect(verifyPolicyRunProof(tree.root, proof)).toBe(true);
    expect(verifyPolicyRunProof(tree.root, {
      ...tree.proofs[1],
      siblings: ["0x123", ...tree.proofs[1].siblings.slice(1)],
    })).toBe(false);
    expect(() => buildAuthorizedPolicyRunTree(context, [runs[0], runs[0]]))
      .toThrow(/same run nullifier/);
  });
});
