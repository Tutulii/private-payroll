export function activityOperationErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message.trim() ? error.message : fallback;
}

/** Refresh may clear page-level errors. Report the operation failure only after
 * that refresh finishes so the local workflow result cannot disappear. */
export async function reportActivityOperationFailure(input: {
  error: unknown;
  fallback: string;
  refresh: () => Promise<unknown>;
  report: (message: string) => void;
}): Promise<string> {
  const message = activityOperationErrorMessage(input.error, input.fallback);
  try {
    await input.refresh();
  } catch {
    // The workflow error remains the actionable result even if refresh also fails.
  }
  input.report(message);
  return message;
}
