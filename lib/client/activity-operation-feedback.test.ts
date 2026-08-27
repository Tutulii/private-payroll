import { describe, expect, it, vi } from "vitest";
import {
  activityOperationErrorMessage,
  reportActivityOperationFailure,
} from "./activity-operation-feedback";

describe("Activity operation feedback", () => {
  it("keeps the workflow error visible after refresh clears earlier state", async () => {
    let visible = "";
    const report = vi.fn((message: string) => { visible = message; });

    await reportActivityOperationFailure({
      error: new Error("The claim agreement is absent from this payday."),
      fallback: "Claim failed.",
      refresh: async () => { visible = ""; },
      report,
    });

    expect(visible).toBe("The claim agreement is absent from this payday.");
    expect(report).toHaveBeenCalledOnce();
  });

  it("reports the original workflow error even when refresh also fails", async () => {
    let visible = "";
    await reportActivityOperationFailure({
      error: new Error("Ready did not return a transaction hash."),
      fallback: "Claim failed.",
      refresh: async () => { throw new Error("Refresh failed."); },
      report: (message) => { visible = message; },
    });
    expect(visible).toBe("Ready did not return a transaction hash.");
  });

  it("uses the fallback for non-error failures", () => {
    expect(activityOperationErrorMessage(null, "Claim failed.")).toBe("Claim failed.");
  });
});
