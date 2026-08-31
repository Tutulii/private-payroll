import { describe, expect, it } from "vitest";
import type { AgentCapability } from "@/lib/domain/capability";
import { verifyPolicyRunProof, computePolicyRunLeaf } from "./policy-account";
import { buildDirectPrivacyAccountProvisioningPlan } from "./direct-privacy-account-plan";

const root = (value: string) => `0x${value.repeat(64)}` as `0x${string}`;
const capability: AgentCapability = {
  capabilityVersion: "payo-agent-capability-v1",
  id: "capability-00000001",
  organizationId: "organization-0001",
  principalId: "principal-0000001",
  allowedActions: ["request_execution"],
  allowedTokens: ["STRK", "USDC"],
  recipientScope: { mode: "allowlist", addresses: ["0x456"] },
  purposeCodes: ["private_payroll"],
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
      maxPerPaymentAtomic: "1000",
      maxPerPeriodAtomic: "5000",
      spentThisPeriodAtomic: "0",
      periodStartsAt: "2026-08-30T00:00:00.000Z",
      periodEndsAt: "2026-08-31T00:00:00.000Z",
      approvalThresholdAtomic: "900",
    },
  ],
  executionMode: "autonomous_bounded",
  maxCallCount: 3,
  usedCallCount: 0,
  validAfter: "2026-08-30T00:00:00.000Z",
  expiresAt: "2026-08-31T00:00:00.000Z",
  nonce: "direct-privacy-capability-nonce-0001",
};
const deployment = {
  chainId: "0x534e5f5345504f4c4941" as const,
  sealAddress: "0x444" as const,
  poolAddress: "0x333" as const,
  policyAccountClassHash: "0xabc" as const,
  policyAccountAddress: "0x111" as const,
  tokenAddresses: { STRK: "0x555" as const, USDC: "0x666" as const },
};
const request = {
  policyAccountAddress: "0x111",
  policyId: "0x222",
  validForSeconds: 600,
  periodSeconds: 300,
  maxCallsPerPeriod: 1,
  maxCallCount: 1,
};
const runs = [{
  runId: "payroll-run-0001",
  runVersion: 1,
  agreementRoot: root("1"),
  manifestRoot: root("2"),
  payrollPolicyRoot: root("3"),
  runNullifier: root("4"),
  proofVersion: 2 as const,
}];

describe("direct privacy account provisioning plan", () => {
  it("derives an exact bounded policy and verifiable run path", () => {
    const plan = buildDirectPrivacyAccountProvisioningPlan({
      capability,
      runs,
      request,
      deployment,
      now: new Date("2026-08-30T11:00:00.000Z"),
    });
    expect(plan.config).toMatchObject({
      policyAccountAddress: "0x111",
      policyId: "0x222",
      sealMode: 0,
      proofVersion: 2,
      schemaVersion: 1,
      maxCallCount: 1,
      poolAddress: "0x333",
      sealAddress: "0x444",
    });
    const authorization = plan.authorizedRuns[0];
    const leaf = computePolicyRunLeaf({
      policyId: plan.config.policyId,
      sealMode: plan.config.sealMode,
      proofVersion: plan.config.proofVersion,
      schemaVersion: plan.config.schemaVersion,
      payrollPolicyRoot: plan.config.payrollPolicyRoot,
      tokenSetCommitment: plan.config.tokenSetCommitment,
      recipientSetCommitment: plan.config.recipientSetCommitment,
      purposeCommitment: plan.config.purposeCommitment,
      amountLimitCommitment: plan.config.amountLimitCommitment,
    }, authorization);
    expect(verifyPolicyRunProof(plan.config.authorizedRunsRoot, { ...authorization, leaf })).toBe(true);
  });

  it("rejects broadened call limits and mixed proof/policy profiles", () => {
    expect(() => buildDirectPrivacyAccountProvisioningPlan({
      capability,
      runs,
      request: { ...request, maxCallCount: 2 },
      deployment,
      now: new Date("2026-08-30T11:00:00.000Z"),
    })).toThrow("authorized runs");
    expect(() => buildDirectPrivacyAccountProvisioningPlan({
      capability,
      runs: [...runs, { ...runs[0], runId: "payroll-run-0002", proofVersion: 1 }],
      request: { ...request, maxCallCount: 2 },
      deployment,
      now: new Date("2026-08-30T11:00:00.000Z"),
    })).toThrow("one proof version");
  });

  it("rejects a policy-account address outside the reviewed deployment", () => {
    expect(() => buildDirectPrivacyAccountProvisioningPlan({
      capability,
      runs,
      request: { ...request, policyAccountAddress: "0x999" },
      deployment,
      now: new Date("2026-08-30T11:00:00.000Z"),
    })).toThrow("not the reviewed PAYO deployment");
  });
});
