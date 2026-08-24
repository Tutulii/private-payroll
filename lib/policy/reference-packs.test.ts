import { describe, expect, it } from "vitest";
import { compilePolicyPack, evaluatePolicyPack, policyPackCommitment } from "./engine";
import {
  REFERENCE_POLICY_RELEASES,
  UK_2026_27_MONTHLY_NI_CATEGORY_A,
  US_2026_SUPPLEMENTAL_FLAT,
} from "./reference-packs";

describe("official-source reference policy releases", () => {
  it("keeps every pack bounded, versioned, source-linked, and review-gated", () => {
    for (const release of REFERENCE_POLICY_RELEASES) {
      const compiled = compilePolicyPack(release.pack);
      expect(compiled.instructionCount).toBeGreaterThan(0);
      expect(compiled.instructionCount).toBeLessThanOrEqual(16);
      expect(release.pack.sourceUri).toMatch(/^https:\/\/(www\.)?(irs\.gov|gov\.uk)/);
      expect(release.pack.legalReviewRequired).toBe(true);
      expect(release.unsupportedCases.length).toBeGreaterThan(0);
      expect(policyPackCommitment(release.pack)).toMatch(/^0x[0-9a-f]{64}$/);
    }
  });

  it("evaluates the narrow US supplemental-wage example", () => {
    expect(evaluatePolicyPack(US_2026_SUPPLEMENTAL_FLAT.pack, { gross: "10000" }))
      .toEqual({ statutoryWithholding: "2200" });
    expect(policyPackCommitment(US_2026_SUPPLEMENTAL_FLAT.pack))
      .toBe("0x325087e383de44739727f5614ebeb57356b9208d54ca87c7cc41ffdfd61c917e");
  });

  it("evaluates UK category-A monthly employee NI across both paid bands", () => {
    expect(evaluatePolicyPack(UK_2026_27_MONTHLY_NI_CATEGORY_A.pack, { gross: "500000" }))
      .toEqual({ statutoryDeduction: "26750" });
    expect(compilePolicyPack(UK_2026_27_MONTHLY_NI_CATEGORY_A.pack).instructionCount).toBe(16);
    expect(policyPackCommitment(UK_2026_27_MONTHLY_NI_CATEGORY_A.pack))
      .toBe("0x213b26fd90e85e4c6d75edf40b5c0cb641cdd4a4a03459d129b345c01328dc14");
  });
});
