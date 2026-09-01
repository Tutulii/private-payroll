import { describe, expect, it } from "vitest";
import {
  MAX_POLICY_POOL_FEE_ALLOWANCE_FRI,
  POLICY_POOL_FEE_CALL_BUDGET,
  policyPoolFeeAllowancePlan,
} from "./policy-pool-fee";

describe("policyPoolFeeAllowancePlan", () => {
  it("bounds the live six-STRK fee to three calls", () => {
    const plan = policyPoolFeeAllowancePlan(6_000_000_000_000_000_000n, 0n);
    expect(plan).toEqual({
      feeCallBudget: 3n,
      targetAllowanceFri: 18_000_000_000_000_000_000n,
      approvalRequired: true,
      expectedAllowanceAfterRegistrationFri: 12_000_000_000_000_000_000n,
    });
  });

  it("does not issue a redundant approval at the exact target", () => {
    const target = 2n * POLICY_POOL_FEE_CALL_BUDGET;
    expect(policyPoolFeeAllowancePlan(2n, target).approvalRequired).toBe(false);
  });

  it.each([0n, -1n])("rejects invalid fee %s", (fee) => {
    expect(() => policyPoolFeeAllowancePlan(fee, 0n)).toThrow(/must be positive/);
  });

  it("rejects a negative allowance", () => {
    expect(() => policyPoolFeeAllowancePlan(1n, -1n)).toThrow(/cannot be negative/);
  });

  it("rejects a three-call target above the hard ceiling", () => {
    const fee = MAX_POLICY_POOL_FEE_ALLOWANCE_FRI / 3n + 1n;
    expect(() => policyPoolFeeAllowancePlan(fee, 0n)).toThrow(/20 STRK/);
  });
});
