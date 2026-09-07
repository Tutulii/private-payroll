import { z } from "zod";

export const PAYROLL_EVIDENCE_COPY = Object.freeze({
  reviewerAudience: "Authorized tax reviewer",
  familiarEvidence: "Familiar W-2/P60/T4-style verified income evidence",
  confidentiality: "Recipient-level payroll data is encrypted to the selected identity.",
  completeness: "Every entry and payroll line in the selected on-chain PAYO book is reconstructed.",
  integrity: "Mutation, substitution, duplication and reordering after commitment are detected.",
  sourceTruthLimit: "The proof does not establish that employer-supplied source facts were truthful when entered.",
  outsideBookLimit: "The proof does not establish that no payroll occurred outside the selected PAYO book.",
  reviewerLimit: "PAYO verifies the recipient wallet and encryption identity, not government authority or employment.",
  filingLimit: "Supporting evidence only — official filing remains on the relevant government channel.",
  publicAggregateLimit: "Public summaries expose only values explicitly disclosed by the on-chain payroll-book entry.",
  downloadedAccessLimit: "A downloaded encrypted package cannot be remotely revoked.",
  committeeAccessLimit: "Each selected member can decrypt independently; this is not threshold access.",
  networkScaleLimit: "Each proved payroll run supports 1–50 contributors.",
  talentClaim: "Salary privacy is a major barrier for on-chain companies competing for senior talent.",
});

const audienceSchema = z.enum([
  "employer",
  "authorized_tax_reviewer",
  "worker",
  "governance_committee",
]);

export const payrollEvidenceClaimCoverageSchema = z.object({
  claimVersion: z.literal("payo-evidence-claims-v1"),
  audience: audienceSchema,
  establishes: z.object({
    recipientConfidentiality: z.literal("recipient_data_encrypted_to_selected_identity"),
    selectedBookCompleteness: z.literal("all_selected_onchain_book_entries_and_lines_reconstructed"),
    committedDataIntegrity: z.literal("post_commitment_mutation_substitution_duplication_and_reordering_detected"),
  }).strict(),
  doesNotEstablish: z.object({
    sourceFactTruth: z.literal("employer_supplied_source_facts_may_be_incorrect"),
    outsideBookCompleteness: z.literal("payroll_outside_selected_payo_book_is_not_observed"),
    governmentAuthority: z.literal("recipient_is_not_verified_as_a_government_authority"),
    officialFiling: z.literal("evidence_is_not_submitted_or_accepted_as_an_official_filing"),
  }).strict(),
  readable: z.object({
    confidentiality: z.literal(PAYROLL_EVIDENCE_COPY.confidentiality),
    completeness: z.literal(PAYROLL_EVIDENCE_COPY.completeness),
    integrity: z.literal(PAYROLL_EVIDENCE_COPY.integrity),
    sourceTruthLimit: z.literal(PAYROLL_EVIDENCE_COPY.sourceTruthLimit),
    outsideBookLimit: z.literal(PAYROLL_EVIDENCE_COPY.outsideBookLimit),
    reviewerLimit: z.literal(PAYROLL_EVIDENCE_COPY.reviewerLimit),
    filingLimit: z.literal(PAYROLL_EVIDENCE_COPY.filingLimit),
  }).strict(),
}).strict();

export type PayrollEvidenceClaimCoverage = z.infer<typeof payrollEvidenceClaimCoverageSchema>;

export function createPayrollEvidenceClaimCoverage(
  audience: z.infer<typeof audienceSchema>,
): PayrollEvidenceClaimCoverage {
  return payrollEvidenceClaimCoverageSchema.parse({
    claimVersion: "payo-evidence-claims-v1",
    audience,
    establishes: {
      recipientConfidentiality: "recipient_data_encrypted_to_selected_identity",
      selectedBookCompleteness: "all_selected_onchain_book_entries_and_lines_reconstructed",
      committedDataIntegrity: "post_commitment_mutation_substitution_duplication_and_reordering_detected",
    },
    doesNotEstablish: {
      sourceFactTruth: "employer_supplied_source_facts_may_be_incorrect",
      outsideBookCompleteness: "payroll_outside_selected_payo_book_is_not_observed",
      governmentAuthority: "recipient_is_not_verified_as_a_government_authority",
      officialFiling: "evidence_is_not_submitted_or_accepted_as_an_official_filing",
    },
    readable: {
      confidentiality: PAYROLL_EVIDENCE_COPY.confidentiality,
      completeness: PAYROLL_EVIDENCE_COPY.completeness,
      integrity: PAYROLL_EVIDENCE_COPY.integrity,
      sourceTruthLimit: PAYROLL_EVIDENCE_COPY.sourceTruthLimit,
      outsideBookLimit: PAYROLL_EVIDENCE_COPY.outsideBookLimit,
      reviewerLimit: PAYROLL_EVIDENCE_COPY.reviewerLimit,
      filingLimit: PAYROLL_EVIDENCE_COPY.filingLimit,
    },
  });
}
