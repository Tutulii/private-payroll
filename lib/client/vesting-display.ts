import {
  advancedPaymentPlanSchema,
  proofScheduleForAdvancedPlan,
  vestedAtomic,
  type AdvancedPaymentPlan,
} from "@/lib/domain/obligations";

type PrivateVestingPlan = Extract<AdvancedPaymentPlan, { kind: "private_vesting" }>;

export type VestingDisplayStatus = {
  vestedAtomic: bigint;
  releasedAtomic: bigint;
  availableAtomic: bigint;
  nextRelease:
    | { state: "scheduled"; at: string }
    | { state: "available_now"; at: string }
    | { state: "needs_schedule" }
    | { state: "complete" };
};

/**
 * Produces the human-readable vesting state from the encrypted canonical plan.
 * `availableAtomic` is vested but unreleased value. A release is executable only
 * when the current checkpoint itself has unpaid entitlement.
 */
export function vestingDisplayStatus(
  planInput: PrivateVestingPlan,
  at = new Date(),
): VestingDisplayStatus {
  const parsed = advancedPaymentPlanSchema.parse(planInput);
  if (parsed.kind !== "private_vesting") throw new Error("Expected a private vesting plan.");
  const plan = parsed as PrivateVestingPlan;
  const schedule = proofScheduleForAdvancedPlan(plan);
  if (schedule.kind !== "vesting") throw new Error("Expected a vesting proof schedule.");

  const releasedAtomic = BigInt(plan.releasedAtomic);
  const vestedNow = vestedAtomic(schedule, at);
  const vestedAtRelease = vestedAtomic(schedule, new Date(plan.releaseAt));
  const availableAtomic = vestedNow > releasedAtomic ? vestedNow - releasedAtomic : 0n;
  const checkpointPayable = vestedAtRelease > releasedAtomic
    ? vestedAtRelease - releasedAtomic
    : 0n;

  if (releasedAtomic >= BigInt(plan.totalAtomic)) {
    return { vestedAtomic: vestedNow, releasedAtomic, availableAtomic: 0n, nextRelease: { state: "complete" } };
  }
  if (checkpointPayable === 0n) {
    return { vestedAtomic: vestedNow, releasedAtomic, availableAtomic, nextRelease: { state: "needs_schedule" } };
  }
  return {
    vestedAtomic: vestedNow,
    releasedAtomic,
    availableAtomic,
    nextRelease: at >= new Date(plan.releaseAt)
      ? { state: "available_now", at: plan.releaseAt }
      : { state: "scheduled", at: plan.releaseAt },
  };
}
