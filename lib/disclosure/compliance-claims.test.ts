import { describe, expect, it } from "vitest";
import {
  PAYROLL_EVIDENCE_COPY,
  createPayrollEvidenceClaimCoverage,
  payrollEvidenceClaimCoverageSchema,
} from "./compliance-claims";

describe("payroll evidence truth contract", () => {
  it("states the exact cryptographic coverage and its real-world limits", () => {
    const coverage = createPayrollEvidenceClaimCoverage("authorized_tax_reviewer");

    expect(coverage.establishes).toEqual({
      recipientConfidentiality: "recipient_data_encrypted_to_selected_identity",
      selectedBookCompleteness: "all_selected_onchain_book_entries_and_lines_reconstructed",
      committedDataIntegrity: "post_commitment_mutation_substitution_duplication_and_reordering_detected",
    });
    expect(coverage.doesNotEstablish).toEqual({
      sourceFactTruth: "employer_supplied_source_facts_may_be_incorrect",
      outsideBookCompleteness: "payroll_outside_selected_payo_book_is_not_observed",
      governmentAuthority: "recipient_is_not_verified_as_a_government_authority",
      officialFiling: "evidence_is_not_submitted_or_accepted_as_an_official_filing",
    });
  });

  it("rejects attempts to upgrade supporting evidence into an official filing", () => {
    const coverage = createPayrollEvidenceClaimCoverage("authorized_tax_reviewer");
    expect(() => payrollEvidenceClaimCoverageSchema.parse({
      ...coverage,
      doesNotEstablish: { ...coverage.doesNotEstablish, officialFiling: "official_filing" },
    })).toThrow();
  });

  it("keeps judge-facing copy free from absolute or priority claims", () => {
    const copy = Object.values(PAYROLL_EVIDENCE_COPY).join(" ").toLowerCase();
    for (const prohibited of [
      "fully disclosed to the tax authority",
      "no fabrication",
      "no omission",
      "first treasury model",
      "single largest barrier",
    ]) expect(copy).not.toContain(prohibited);
  });

  it.each(["employer", "authorized_tax_reviewer", "worker", "governance_committee"] as const)(
    "creates valid %s coverage",
    (audience) => expect(payrollEvidenceClaimCoverageSchema.parse(
      createPayrollEvidenceClaimCoverage(audience),
    ).audience).toBe(audience),
  );
});
