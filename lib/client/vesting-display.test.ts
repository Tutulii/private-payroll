import { describe, expect, it } from "vitest";
import type { AdvancedPaymentPlan } from "@/lib/domain/obligations";
import { vestingDisplayStatus } from "./vesting-display";

const plan = (overrides: Partial<Extract<AdvancedPaymentPlan, { kind: "private_vesting" }>> = {}) => ({
  planVersion: "payo-payment-plan-v1" as const,
  kind: "private_vesting" as const,
  startsAt: "2026-09-04T00:00:00.000Z",
  cliffAt: "2026-09-04T02:00:00.000Z",
  releaseAt: "2026-09-04T05:00:00.000Z",
  endsAt: "2026-09-04T10:00:00.000Z",
  totalAtomic: "1000",
  releasedAtomic: "0",
  releaseSequence: 0,
  ...overrides,
});

describe("vestingDisplayStatus", () => {
  it("shows zero vested before the cliff and the configured next release", () => {
    expect(vestingDisplayStatus(plan(), new Date("2026-09-04T01:00:00.000Z"))).toEqual({
      vestedAtomic: 0n,
      releasedAtomic: 0n,
      availableAtomic: 0n,
      nextRelease: { state: "scheduled", at: "2026-09-04T05:00:00.000Z" },
    });
  });

  it("shows the exact linearly vested, released and available amounts", () => {
    expect(vestingDisplayStatus(
      plan({ releasedAtomic: "200", releaseSequence: 1, releaseAt: "2026-09-04T08:00:00.000Z" }),
      new Date("2026-09-04T06:00:00.000Z"),
    )).toEqual({
      vestedAtomic: 600n,
      releasedAtomic: 200n,
      availableAtomic: 400n,
      nextRelease: { state: "scheduled", at: "2026-09-04T08:00:00.000Z" },
    });
  });

  it("distinguishes a due checkpoint from one that must be rescheduled", () => {
    expect(vestingDisplayStatus(plan(), new Date("2026-09-04T06:00:00.000Z")).nextRelease.state)
      .toBe("available_now");
    expect(vestingDisplayStatus(
      plan({ releasedAtomic: "500", releaseSequence: 1 }),
      new Date("2026-09-04T06:00:00.000Z"),
    ).nextRelease.state).toBe("needs_schedule");
  });

  it("marks a fully released schedule complete", () => {
    const status = vestingDisplayStatus(
      plan({ releasedAtomic: "1000", releaseSequence: 2 }),
      new Date("2026-09-04T10:00:00.000Z"),
    );
    expect(status.availableAtomic).toBe(0n);
    expect(status.nextRelease.state).toBe("complete");
  });
});
