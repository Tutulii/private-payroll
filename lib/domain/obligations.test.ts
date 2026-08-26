import { describe, expect, it } from "vitest";
import {
  advancedPlanEntitlement,
  assertFxFloor,
  advanceRecurringSchedule,
  calculateOffboardingNetAtomic,
  isScheduleDue,
  settleAdvancedPaymentPlan,
  streamAccruedAtomic,
  vestedAtomic,
} from "./obligations";

describe("advanced payroll obligations", () => {
  it("accrues streams deterministically with integer arithmetic", () => {
    const schedule = {
      kind: "stream" as const,
      startsAt: "2026-08-01T00:00:00.000Z",
      endsAt: "2026-08-11T00:00:00.000Z",
      totalAtomic: "1000",
      claimedAtomic: "400",
    };
    expect(streamAccruedAtomic(schedule, new Date("2026-08-06T00:00:00.000Z"))).toBe(500n);
    expect(isScheduleDue(schedule, new Date("2026-08-06T00:00:00.000Z"))).toBe(true);
  });

  it("enforces vesting cliffs", () => {
    const schedule = {
      kind: "vesting" as const,
      startsAt: "2026-01-01T00:00:00.000Z",
      cliffAt: "2026-07-01T00:00:00.000Z",
      releaseAt: "2026-07-02T00:00:00.000Z",
      endsAt: "2027-01-01T00:00:00.000Z",
      totalAtomic: "1200",
      releasedAtomic: "0",
    };
    expect(vestedAtomic(schedule, new Date("2026-06-30T00:00:00.000Z"))).toBe(0n);
    expect(vestedAtomic(schedule, new Date("2026-07-02T00:00:00.000Z"))).toBeGreaterThan(0n);
  });

  it("rejects incomplete final pay and calculates a complete one", () => {
    const pay = {
      ordinaryPayAtomic: "100",
      accruedLeaveAtomic: "25",
      noticeAtomic: "50",
      severanceAtomic: "200",
      adjustmentsAtomic: "5",
      deductionsAtomic: "20",
      requiredComponents: { accruedLeave: true, notice: true, severance: true },
      includedComponents: { accruedLeave: true, notice: true, severance: true },
    };
    expect(calculateOffboardingNetAtomic(pay)).toBe(360n);
    expect(() => calculateOffboardingNetAtomic({
      ...pay,
      includedComponents: { ...pay.includedComponents, severance: false },
    })).toThrow("severance");
  });

  it("enforces a reference-currency floor without floating point", () => {
    expect(assertFxFloor({
      settlementAtomic: "100",
      rateNumerator: "11",
      rateDenominator: "10",
      minimumReferenceAtomic: "105",
    })).toBe(110n);
    expect(() => assertFxFloor({
      settlementAtomic: "100",
      rateNumerator: "10",
      rateDenominator: "10",
      minimumReferenceAtomic: "101",
    })).toThrow("reference-currency floor");
  });

  it("advances recurring dates once per settled cycle and clamps calendar month ends", () => {
    expect(advanceRecurringSchedule({
      kind: "recurring",
      cadence: "weekly",
      nextDueAt: "2026-08-24T12:30:00.000Z",
    }).nextDueAt).toBe("2026-08-31T12:30:00.000Z");
    expect(advanceRecurringSchedule({
      kind: "recurring",
      cadence: "biweekly",
      nextDueAt: "2026-08-24T12:30:00.000Z",
    }).nextDueAt).toBe("2026-09-07T12:30:00.000Z");
    expect(advanceRecurringSchedule({
      kind: "recurring",
      cadence: "monthly",
      nextDueAt: "2028-01-31T12:30:00.000Z",
    }).nextDueAt).toBe("2028-02-29T12:30:00.000Z");
  });

  it("settles only a proof-bound checkpoint entitlement", () => {
    const plan = {
      planVersion: "payo-payment-plan-v1" as const,
      kind: "checkpoint_stream" as const,
      startsAt: "2026-08-01T00:00:00.000Z",
      endsAt: "2026-08-11T00:00:00.000Z",
      totalAtomic: "1000",
      settledAtomic: "200",
      minimumCheckpointSeconds: 86_400,
      lastCheckpointAt: "2026-08-02T00:00:00.000Z",
      checkpoint: {
        sequence: 2,
        checkpointAt: "2026-08-06T00:00:00.000Z",
        cumulativeEntitlementAtomic: "500",
        attestationCommitment: `0x${"11".repeat(32)}`,
      },
    };
    expect(advancedPlanEntitlement(plan, new Date("2026-08-06T00:00:01.000Z")))
      .toMatchObject({ due: true, payableAtomic: 300n, sequence: 2 });
    expect(settleAdvancedPaymentPlan({
      plan,
      paidAtomic: "300",
      at: new Date("2026-08-06T00:00:01.000Z"),
    })).toMatchObject({ settledAtomic: "500", lastCheckpointAt: plan.checkpoint.checkpointAt });
    expect(() => settleAdvancedPaymentPlan({
      plan,
      paidAtomic: "299",
      at: new Date("2026-08-06T00:00:01.000Z"),
    })).toThrow("proof-bound plan entitlement");
  });

  it("rejects forged checkpoint accrual and premature checkpoints", () => {
    const base = {
      planVersion: "payo-payment-plan-v1" as const,
      kind: "checkpoint_stream" as const,
      startsAt: "2026-08-01T00:00:00.000Z",
      endsAt: "2026-08-11T00:00:00.000Z",
      totalAtomic: "1000",
      settledAtomic: "100",
      minimumCheckpointSeconds: 86_400,
      lastCheckpointAt: "2026-08-05T12:00:00.000Z",
      checkpoint: {
        sequence: 3,
        checkpointAt: "2026-08-06T00:00:00.000Z",
        cumulativeEntitlementAtomic: "999",
        attestationCommitment: `0x${"22".repeat(32)}`,
      },
    };
    expect(() => advancedPlanEntitlement({
      ...base,
      minimumCheckpointSeconds: 1,
    }, new Date("2026-08-06T00:00:01.000Z"))).toThrow("deterministic stream accrual");
    expect(() => advancedPlanEntitlement(base, new Date("2026-08-06T00:00:01.000Z")))
      .toThrow("earlier than the committed interval");
  });

  it("requires committed milestone approval and enforces private vesting deltas", () => {
    const milestone = {
      planVersion: "payo-payment-plan-v1" as const,
      kind: "milestone" as const,
      dueAt: "2026-08-20T00:00:00.000Z",
      milestoneCommitment: `0x${"33".repeat(32)}`,
      approverCommitment: `0x${"44".repeat(32)}`,
      attestationCommitment: `0x${"55".repeat(32)}`,
      approvedAt: "2026-08-19T00:00:00.000Z",
    };
    expect(advancedPlanEntitlement(milestone, new Date("2026-08-20T00:00:00.000Z")).due).toBe(true);
    expect(() => advancedPlanEntitlement({ ...milestone, attestationCommitment: undefined }))
      .toThrow("requires both");

    const vesting = {
      planVersion: "payo-payment-plan-v1" as const,
      kind: "private_vesting" as const,
      startsAt: "2026-01-01T00:00:00.000Z",
      cliffAt: "2026-07-01T00:00:00.000Z",
      releaseAt: "2026-07-02T00:00:00.000Z",
      endsAt: "2027-01-01T00:00:00.000Z",
      totalAtomic: "1200",
      releasedAtomic: "0",
      releaseSequence: 0,
    };
    const entitlement = advancedPlanEntitlement(vesting, new Date("2026-07-02T00:00:00.000Z"));
    expect(entitlement.due).toBe(true);
    const settled = settleAdvancedPaymentPlan({
      plan: vesting,
      paidAtomic: entitlement.payableAtomic.toString(),
      at: new Date("2026-07-02T00:00:00.000Z"),
    });
    expect(settled).toMatchObject({ releaseSequence: 1 });
  });
});
