export const POLICY_POOL_FEE_CALL_BUDGET = 3n;
export const MAX_POLICY_POOL_FEE_ALLOWANCE_FRI = 20_000_000_000_000_000_000n;

export function policyPoolFeeAllowancePlan(
  feeFri: bigint,
  currentAllowanceFri: bigint,
) {
  if (feeFri <= 0n) {
    throw new Error("The STRK20 pool fee must be positive.");
  }
  if (currentAllowanceFri < 0n) {
    throw new Error("The STRK20 pool allowance cannot be negative.");
  }
  const targetAllowanceFri = feeFri * POLICY_POOL_FEE_CALL_BUDGET;
  if (targetAllowanceFri > MAX_POLICY_POOL_FEE_ALLOWANCE_FRI) {
    throw new Error("The STRK20 pool fee exceeds PAYO's 20 STRK allowance ceiling.");
  }
  return {
    feeCallBudget: POLICY_POOL_FEE_CALL_BUDGET,
    targetAllowanceFri,
    approvalRequired: currentAllowanceFri !== targetAllowanceFri,
    expectedAllowanceAfterRegistrationFri: targetAllowanceFri - feeFri,
  };
}
