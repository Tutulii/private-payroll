export const MAX_POLICY_GAS_TARGET_FRI = 20_000_000_000_000_000_000n;

export function parsePolicyGasTargetFri(value) {
  const normalized = value?.trim();
  if (!normalized || !/^[1-9][0-9]*$/.test(normalized)) {
    throw new Error("PAYO_POLICY_GAS_TARGET_FRI must be a positive base-10 integer.");
  }
  const target = BigInt(normalized);
  if (target > MAX_POLICY_GAS_TARGET_FRI) {
    throw new Error("PAYO_POLICY_GAS_TARGET_FRI exceeds the 20 STRK safety ceiling.");
  }
  return target;
}

export function policyGasFundingDelta(currentBalance, targetBalance) {
  if (currentBalance < 0n || targetBalance <= 0n) {
    throw new Error("Policy gas balances must be non-negative with a positive target.");
  }
  return currentBalance >= targetBalance ? 0n : targetBalance - currentBalance;
}

export function hasFundingBalance(relayerBalance, transferAmount, feeAmount) {
  if (relayerBalance < 0n || transferAmount < 0n || feeAmount < 0n) {
    throw new Error("Funding values cannot be negative.");
  }
  return relayerBalance >= transferAmount + feeAmount;
}
