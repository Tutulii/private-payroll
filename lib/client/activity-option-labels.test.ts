import { describe, expect, it } from "vitest";
import {
  activityAgreementOptionLabel,
  activityRunOptionLabel,
} from "./activity-option-labels";

describe("activity selector labels", () => {
  it("replaces encrypted agreement identifiers with a short numbered contributor label", () => {
    expect(activityAgreementOptionLabel({
      classification: "agent_service",
      payeeName: "Scout",
    }, 1)).toBe("Agreement 2 · Scout");
  });

  it("does not expose a raw agreement identifier when a contributor is unavailable", () => {
    expect(activityAgreementOptionLabel({ classification: "contractor" }, 0))
      .toBe("Agreement 1 · Contractor");
  });

  it("replaces opaque cycle identifiers with a short numbered payday label", () => {
    expect(activityRunOptionLabel({ state: "onchain_verified" }, 0))
      .toBe("Payday 1 · Onchain Verified");
  });
});
