import { describe, expect, it } from "vitest";
import type { ObligationSnapshotPlanSummary } from "@/lib/domain/obligation-snapshot-plan";
import {
  exactPayrollSnapshotReady,
  resolveExactPayrollSnapshotStatus,
} from "./payroll-snapshot-status";

function plan(
  cycleId: string,
  state: ObligationSnapshotPlanSummary["state"] = "registered",
  revision = 1,
): ObligationSnapshotPlanSummary {
  return {
    id: "0198ddf0-9c00-7000-8000-000000000001",
    runId: "0198ddf0-9c00-7000-8000-000000000002",
    organizationId: "0198ddf0-9c00-7000-8000-000000000003",
    cycleId,
    revision,
    ownerAddress: "0x123",
    agreementRoot: ("0x" + "11".repeat(32)) as ObligationSnapshotPlanSummary["agreementRoot"],
    claimRoot: ("0x" + "22".repeat(32)) as ObligationSnapshotPlanSummary["claimRoot"],
    policyRoot: ("0x" + "33".repeat(32)) as ObligationSnapshotPlanSummary["policyRoot"],
    runNullifier: ("0x" + "44".repeat(32)) as ObligationSnapshotPlanSummary["runNullifier"],
    snapshotFact: ("0x" + "55".repeat(32)) as ObligationSnapshotPlanSummary["snapshotFact"],
    dueAt: "2026-09-02T05:43:00.000Z",
    graceEndsAt: "2026-09-02T05:58:00.000Z",
    claimEndsAt: "2026-12-01T05:43:00.000Z",
    state,
    registrationTransactionHash: state === "prepared" ? null : "0xabc",
    registeredAt: state === "prepared" ? null : "2026-09-02T05:30:00.000Z",
    consumedAt: state === "consumed" ? "2026-09-02T05:44:00.000Z" : null,
    createdAt: "2026-09-02T05:20:00.000Z",
    updatedAt: "2026-09-02T05:30:00.000Z",
  };
}

describe("exact payroll snapshot status", () => {
  it("does not treat a different future payday as protection for the selected batch", () => {
    const status = resolveExactPayrollSnapshotStatus({
      cycleId: "snapshot:selected-due-batch",
      requiresSnapshot: true,
      plans: [plan("snapshot:different-future-payday")],
    });
    expect(status).toEqual({ kind: "missing", plan: null });
    expect(exactPayrollSnapshotReady(status)).toBe(false);
  });

  it("accepts only a registered snapshot for the exact cycle", () => {
    const status = resolveExactPayrollSnapshotStatus({
      cycleId: "snapshot:selected-due-batch",
      requiresSnapshot: true,
      plans: [plan("snapshot:selected-due-batch")],
    });
    expect(status.kind).toBe("registered");
    expect(exactPayrollSnapshotReady(status)).toBe(true);
  });

  it("keeps a consumed exact snapshot blocked and selects the latest revision", () => {
    const status = resolveExactPayrollSnapshotStatus({
      cycleId: "snapshot:selected-due-batch",
      requiresSnapshot: true,
      plans: [
        plan("snapshot:selected-due-batch", "registered", 1),
        plan("snapshot:selected-due-batch", "consumed", 2),
      ],
    });
    expect(status.kind).toBe("consumed");
    expect(status.plan?.revision).toBe(2);
    expect(exactPayrollSnapshotReady(status)).toBe(false);
  });

  it("does not require a snapshot for a legacy proof profile", () => {
    const status = resolveExactPayrollSnapshotStatus({
      cycleId: "payroll:legacy",
      requiresSnapshot: false,
      plans: [],
    });
    expect(status.kind).toBe("not_required");
    expect(exactPayrollSnapshotReady(status)).toBe(true);
  });
});
