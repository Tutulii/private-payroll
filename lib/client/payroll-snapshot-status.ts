import type { ObligationSnapshotPlanSummary } from "@/lib/domain/obligation-snapshot-plan";

export type ExactPayrollSnapshotStatus =
  | { kind: "empty" | "not_required" | "missing"; plan: null }
  | {
      kind: ObligationSnapshotPlanSummary["state"];
      plan: ObligationSnapshotPlanSummary;
    };

/**
 * Resolves protection only for the cryptographic cycle derived from the exact
 * selected agreement revisions and schedules. A registered snapshot for a
 * different (including future) payday must never make this batch look ready.
 */
export function resolveExactPayrollSnapshotStatus(input: {
  cycleId: string | null;
  requiresSnapshot: boolean;
  plans: readonly ObligationSnapshotPlanSummary[];
}): ExactPayrollSnapshotStatus {
  if (!input.cycleId) return { kind: "empty", plan: null };
  if (!input.requiresSnapshot) return { kind: "not_required", plan: null };
  const plan = input.plans
    .filter(({ cycleId }) => cycleId === input.cycleId)
    .sort((left, right) => right.revision - left.revision)[0] ?? null;
  return plan ? { kind: plan.state, plan } : { kind: "missing", plan: null };
}

export function exactPayrollSnapshotReady(status: ExactPayrollSnapshotStatus): boolean {
  return status.kind === "not_required" || status.kind === "registered";
}
