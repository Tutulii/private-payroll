import { describe, expect, it } from "vitest";
import {
  assertFxFloor,
  calculateOffboardingNetAtomic,
  isScheduleDue,
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
});
