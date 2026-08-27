import { describe, expect, it } from "vitest";
import { runProgressiveTasks } from "./progressive-tasks";

describe("runProgressiveTasks", () => {
  it("shows successful sections even when another Activity request never resolves", async () => {
    const completed: string[] = [];
    const results = await runProgressiveTasks([
      { label: "Settlements", run: () => new Promise<void>(() => undefined) },
      { label: "Audit events", run: async () => { completed.push("audit"); } },
      { label: "Paydays", run: async () => { completed.push("paydays"); } },
    ], { concurrency: 2, timeoutMs: 20 });

    expect(completed).toEqual(["audit", "paydays"]);
    expect(results).toEqual([
      expect.objectContaining({ label: "Settlements", status: "rejected" }),
      { label: "Audit events", status: "fulfilled" },
      { label: "Paydays", status: "fulfilled" },
    ]);
  });

  it("bounds concurrent requests to protect the web machine", async () => {
    let active = 0;
    let maximumActive = 0;
    const tasks = Array.from({ length: 7 }, (_, index) => ({
      label: `section-${index}`,
      run: async () => {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await new Promise((resolve) => setTimeout(resolve, 3));
        active -= 1;
      },
    }));

    const results = await runProgressiveTasks(tasks, { concurrency: 3, timeoutMs: 100 });
    expect(maximumActive).toBe(3);
    expect(results.every(({ status }) => status === "fulfilled")).toBe(true);
  });

  it("uses one batch deadline instead of multiplying the timeout across queued sections", async () => {
    const started: string[] = [];
    const before = Date.now();
    const results = await runProgressiveTasks(
      Array.from({ length: 8 }, (_, index) => ({
        label: `stuck-${index}`,
        run: () => {
          started.push(`stuck-${index}`);
          return new Promise<void>(() => undefined);
        },
      })),
      { concurrency: 2, timeoutMs: 20 },
    );

    expect(Date.now() - before).toBeLessThan(100);
    expect(started).toHaveLength(2);
    expect(results).toHaveLength(8);
    expect(results.every(({ status }) => status === "rejected")).toBe(true);
  });
});
