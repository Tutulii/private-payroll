import { describe, expect, it } from "vitest";
import {
  DEFAULT_DISCLOSURE_LIFETIME_MS,
  disclosureFormDefaults,
  resolveDisclosureSelection,
} from "./disclosure-form";

describe("scoped disclosure form", () => {
  it("uses the unlocked principal's public identity and a 24-hour expiry", () => {
    const now = new Date("2026-08-28T08:00:00.000Z");
    const result = disclosureFormDefaults({
      principalId: "01a041f3-bdf5-7696-aa05-e65faed68d84",
      publicKey: "KsD1+YKrizU8vEyTJQ2MrSbRreOHGeXtvoaLYUXVoF8=",
    }, now);

    expect(result.principalId).toBe("01a041f3-bdf5-7696-aa05-e65faed68d84");
    expect(result.publicKey).toBe("KsD1+YKrizU8vEyTJQ2MrSbRreOHGeXtvoaLYUXVoF8=");
    expect(new Date(result.expiresAtInput).getTime() - now.getTime())
      .toBe(DEFAULT_DISCLOSURE_LIFETIME_MS);
  });

  it("keeps the explicitly selected verified workflow", () => {
    const settlements = [
      { id: "payroll", workflowType: "payroll" },
      { id: "remediation", workflowType: "wage_remediation" },
    ];

    expect(resolveDisclosureSelection(settlements, "remediation"))
      .toEqual(settlements[1]);
    expect(resolveDisclosureSelection(settlements, ""))
      .toEqual(settlements[0]);
  });
});
