import { describe, expect, it } from "vitest";
import {
  assertUnambiguousAuthorityRecipientReferences,
  authorityReadinessTaxYear,
} from "./authority-readiness";

describe("authority-readiness release boundaries", () => {
  it("accepts exactly one complete UTC calendar year and rejects a partial period", () => {
    const start = String(Date.UTC(2026, 0, 1) / 1_000);
    const end = String(Date.UTC(2027, 0, 1) / 1_000);
    expect(authorityReadinessTaxYear(start, end)).toBe(2026);
    expect(() => authorityReadinessTaxYear(start, String(Number(end) - 1)))
      .toThrow(/complete calendar-year/i);
  });

  it("rejects ambiguous contributor references before an authority manifest is created", () => {
    expect(() => assertUnambiguousAuthorityRecipientReferences([{
      code: "conflicting_recipient_references",
      recipientAddress: "0x123",
      jurisdictionCode: "US",
      token: "USDC",
      recipientReferences: ["old alias", "current alias"],
    }])).toThrow(/rejects conflicting recipient references/i);
    expect(() => assertUnambiguousAuthorityRecipientReferences([])).not.toThrow();
  });
});
