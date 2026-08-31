/**
 * A protected payday reserves its immutable run ID before an executable
 * payroll manifest exists. The reservation must remain visible to claim and
 * remediation workflows, but Payroll must not try to decrypt it as a run.
 */
export function isUnmaterializedSnapshotReservation(
  run: Readonly<Record<string, unknown>>,
): boolean {
  return run.state === "draft"
    && typeof run.obligationSnapshotPlanId === "string"
    && run.obligationSnapshotPlanId.length > 0
    && run.manifestRoot === null;
}

export function materializedPayrollRuns(
  runs: readonly Readonly<Record<string, unknown>>[],
): Readonly<Record<string, unknown>>[] {
  return runs.filter((run) => !isUnmaterializedSnapshotReservation(run));
}
