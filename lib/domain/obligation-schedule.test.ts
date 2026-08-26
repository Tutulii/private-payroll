import { describe, expect, it } from "vitest";
import type { EmploymentAgreement } from "./obligations";
import { agreementOperationalDueAt, obligationScheduleBatchSchema } from "./obligation-schedule";

const common = {
  agreementVersion: "payo-agreement-v2",
} as const;

describe("opaque obligation scheduling", () => {
  it.each([
    [{ kind: "recurring", nextDueAt: "2026-09-01T00:00:00.000Z" }, "2026-09-01T00:00:00.000Z"],
    [{ kind: "checkpoint_stream", checkpoint: { checkpointAt: "2026-09-02T00:00:00.000Z" } }, "2026-09-02T00:00:00.000Z"],
    [{ kind: "milestone", dueAt: "2026-09-03T00:00:00.000Z" }, "2026-09-03T00:00:00.000Z"],
    [{ kind: "private_vesting", releaseAt: "2026-09-04T00:00:00.000Z" }, "2026-09-04T00:00:00.000Z"],
  ] as const)("derives the operational due time for %s", (paymentPlan, expected) => {
    expect(agreementOperationalDueAt({ ...common, paymentPlan } as unknown as EmploymentAgreement)).toBe(expected);
  });

  it("accepts commitments and due time but rejects plaintext scheduling fields", () => {
    const safe = {
      organizationId: "0198e148-2420-7ae0-8000-000000000001",
      schedules: [{
        vaultRecordId: "0198e148-2420-7ae0-8000-000000000003",
        agreementId: "0198e148-2420-7ae0-8000-000000000002",
        agreementRevision: 1,
        scheduleCommitment: `0x${"ab".repeat(32)}`,
        dueAt: "2026-09-01T00:00:00.000Z",
      }],
    };
    expect(obligationScheduleBatchSchema.parse(safe)).toEqual(safe);
    expect(() => obligationScheduleBatchSchema.parse({
      ...safe,
      schedules: [{ ...safe.schedules[0], amount: "1000", token: "STRK", recipient: "0x123" }],
    })).toThrow();
  });
});
