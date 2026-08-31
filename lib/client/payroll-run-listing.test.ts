import { describe, expect, it } from "vitest";
import {
  isUnmaterializedSnapshotReservation,
  materializedPayrollRuns,
} from "./payroll-run-listing";

describe("payroll run listing", () => {
  const reservation = {
    id: "run:reserved",
    state: "draft",
    obligationSnapshotPlanId: "snapshot:protected",
    manifestRoot: null,
  };

  it("keeps a protected-payday reservation out of encrypted payroll history", () => {
    expect(isUnmaterializedSnapshotReservation(reservation)).toBe(true);
    expect(materializedPayrollRuns([
      reservation,
      {
        id: "run:materialized",
        state: "draft",
        obligationSnapshotPlanId: "snapshot:protected",
        manifestRoot: `0x${"11".repeat(32)}`,
      },
    ])).toEqual([expect.objectContaining({ id: "run:materialized" })]);
  });

  it("does not hide ordinary or submitted payroll runs", () => {
    expect(isUnmaterializedSnapshotReservation({
      id: "run:ordinary",
      state: "draft",
      obligationSnapshotPlanId: null,
      manifestRoot: `0x${"22".repeat(32)}`,
    })).toBe(false);
    expect(isUnmaterializedSnapshotReservation({
      ...reservation,
      state: "submitted",
    })).toBe(false);
  });

  it("fails visibly for malformed snapshot rows instead of silently hiding them", () => {
    expect(isUnmaterializedSnapshotReservation({
      ...reservation,
      manifestRoot: undefined,
    })).toBe(false);
  });
});
