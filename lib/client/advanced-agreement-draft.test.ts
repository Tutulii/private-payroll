import { describe, expect, it } from "vitest";
import { buildAdvancedPaymentPlanDraft } from "./advanced-agreement-draft";

const commitment = `0x${"11".repeat(32)}`;

describe("advanced agreement draft", () => {
  it("derives the exact checkpoint entitlement instead of trusting a browser amount", () => {
    const plan = buildAdvancedPaymentPlanDraft({
      kind: "checkpoint_stream",
      startsAt: "2026-08-26T08:00:00.000Z",
      endsAt: "2026-08-26T12:00:00.000Z",
      checkpointAt: "2026-08-26T09:00:00.000Z",
      totalAtomic: 1_000_000n,
      minimumCheckpointSeconds: 900,
      attestationCommitment: commitment,
    });
    expect(plan).toMatchObject({
      kind: "checkpoint_stream",
      checkpoint: { cumulativeEntitlementAtomic: "250000" },
    });
  });

  it("rejects a zero-accrual checkpoint", () => {
    expect(() => buildAdvancedPaymentPlanDraft({
      kind: "checkpoint_stream",
      startsAt: "2026-08-26T08:00:00.000Z",
      endsAt: "2026-08-26T12:00:00.000Z",
      checkpointAt: "2026-08-26T08:00:00.000Z",
      totalAtomic: 1_000_000n,
      minimumCheckpointSeconds: 900,
      attestationCommitment: commitment,
    })).toThrow(/positive payment/i);
  });

  it("rejects a milestone approved after its committed due time", () => {
    expect(() => buildAdvancedPaymentPlanDraft({
      kind: "milestone",
      dueAt: "2026-08-26T09:00:00.000Z",
      approvedAt: "2026-08-26T09:01:00.000Z",
      milestoneCommitment: commitment,
      approverCommitment: commitment,
      attestationCommitment: commitment,
    })).toThrow(/no later/i);
  });

  it("rejects vesting releases before the cliff", () => {
    expect(() => buildAdvancedPaymentPlanDraft({
      kind: "private_vesting",
      startsAt: "2026-08-26T08:00:00.000Z",
      cliffAt: "2026-08-26T10:00:00.000Z",
      releaseAt: "2026-08-26T09:00:00.000Z",
      endsAt: "2026-08-26T12:00:00.000Z",
      totalAtomic: 1_000_000n,
    })).toThrow(/vesting window/i);
  });


  it("starts a private vesting schedule at the seal's empty state", () => {
    const plan = buildAdvancedPaymentPlanDraft({
      kind: "private_vesting",
      startsAt: "2026-08-26T08:00:00.000Z",
      cliffAt: "2026-08-26T09:00:00.000Z",
      releaseAt: "2026-08-26T10:00:00.000Z",
      endsAt: "2026-08-26T12:00:00.000Z",
      totalAtomic: 1_000_000n,
    });

    expect(plan).toMatchObject({ releasedAtomic: "0", releaseSequence: 0 });
  });
});
