export type ProgressiveTask = {
  label: string;
  run: () => Promise<void>;
};

export type ProgressiveTaskResult =
  | { label: string; status: "fulfilled" }
  | { label: string; status: "rejected"; reason: unknown };

function withDeadline<T>(promise: Promise<T>, label: string, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`${label} did not respond within ${Math.ceil(timeoutMs / 1_000)} seconds.`)),
      timeoutMs,
    );
    promise.then(resolve, reject).finally(() => clearTimeout(timeout));
  });
}

/** Runs independent reads progressively without flooding a small web machine. */
export async function runProgressiveTasks(
  tasks: readonly ProgressiveTask[],
  options: { concurrency?: number; timeoutMs?: number } = {},
): Promise<ProgressiveTaskResult[]> {
  const concurrency = Math.max(1, Math.min(options.concurrency ?? 3, tasks.length || 1));
  const timeoutMs = options.timeoutMs ?? 12_000;
  const results: ProgressiveTaskResult[] = new Array(tasks.length);
  let cursor = 0;

  const worker = async () => {
    while (cursor < tasks.length) {
      const index = cursor;
      cursor += 1;
      const task = tasks[index];
      try {
        await withDeadline(task.run(), task.label, timeoutMs);
        results[index] = { label: task.label, status: "fulfilled" };
      } catch (reason) {
        results[index] = { label: task.label, status: "rejected", reason };
      }
    }
  };

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return results;
}
