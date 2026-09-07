import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { payrollTokenSchema } from "@/lib/domain/payroll";
import {
  commitmentSchema,
  recipientReferenceResolutionSchema,
  starknetAddressSchema,
  uuidV7Schema,
} from "@/lib/domain/records";
import {
  completePayrollBookReportSchema,
  payrollReportPayloadCommitment,
  trustedPayrollBookSnapshotSchema,
  verifyCompletePayrollBookReport,
  type CompletePayrollBookReport,
  type TrustedPayrollBookSnapshot,
} from "./payroll-book-report";
import {
  createVerifiedIncomeEvidence,
  renderFamiliarTaxDocumentsWithDiagnostics,
  type FamiliarTaxRenderIssue,
} from "./tax-evidence";
import {
  createPayrollEvidenceClaimCoverage,
  payrollEvidenceClaimCoverageSchema,
} from "./compliance-claims";

const unixSecondsSchema = z.string().regex(/^(0|[1-9]\d*)$/);
const recipientIdentitySchema = z.object({
  principalId: z.string().min(1).max(160),
  identityFingerprint: commitmentSchema,
}).strict();

const tokenTotalsSchema = z.object({
  token: payrollTokenSchema,
  grossAtomic: unixSecondsSchema,
  deductionsAtomic: unixSecondsSchema,
  netAtomic: unixSecondsSchema,
}).strict();

const authorityReadinessCoreSchema = z.object({
  packageVersion: z.literal("payo-authority-readiness-evidence-v1"),
  readinessState: z.literal("verified_evidence"),
  filingState: z.literal("exported_not_submitted"),
  generatedAt: z.string().datetime(),
  source: z.object({
    reportId: uuidV7Schema,
    reportCommitment: commitmentSchema,
    organizationId: uuidV7Schema,
    scope: z.literal("tax_authority"),
    recipients: z.array(recipientIdentitySchema).min(1).max(8),
  }).strict(),
  reporting: z.object({
    periodStart: unixSecondsSchema,
    periodEnd: unixSecondsSchema,
    taxYear: z.number().int().min(2020).max(2100),
    jurisdictionCodes: z.array(z.string().regex(/^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/)).min(1),
  }).strict(),
  coverage: z.object({
    mode: z.literal("complete_selected_onchain_book"),
    entryCount: z.number().int().positive(),
    lineCount: z.number().int().positive(),
    familiarDocumentCount: z.number().int().nonnegative(),
    familiarDocumentIssueCount: z.number().int().nonnegative(),
  }).strict(),
  totals: z.array(tokenTotalsSchema).length(2),
  recipientReferenceResolutions: z.array(recipientReferenceResolutionSchema).max(50).optional(),
  policyBindings: z.array(z.object({
    policyId: z.string().min(1).max(160),
    policyRevision: z.number().int().positive(),
    policyCommitment: commitmentSchema,
    policyCatalogRoot: commitmentSchema,
    jurisdictionCode: z.string().regex(/^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/),
    sourceUri: z.string().url(),
    legalReviewRequired: z.literal(true),
  }).strict()).min(1),
  chainEvidence: z.object({
    chainId: starknetAddressSchema,
    sealAddress: starknetAddressSchema,
    ownerAddress: starknetAddressSchema,
    accumulatorRoot: commitmentSchema,
    observedAt: z.string().datetime(),
    blockNumber: unixSecondsSchema,
    transactions: z.array(z.object({
      kind: z.enum(["integrity_proof", "settlement"]),
      transactionHash: starknetAddressSchema,
    }).strict()).min(2),
  }).strict(),
  claimCoverage: payrollEvidenceClaimCoverageSchema,
  requiredOfficialIntegration: z.tuple([
    z.literal("government_recognized_identity"),
    z.literal("authority_schema_and_business_rules"),
    z.literal("authorized_transmitter_credentials"),
    z.literal("authority_acceptance_acknowledgement"),
  ]),
}).strict();

export const authorityReadinessEvidenceSchema = authorityReadinessCoreSchema.extend({
  evidenceCommitment: commitmentSchema,
}).strict().superRefine((evidence, context) => {
  const principals = evidence.source.recipients.map(({ principalId }) => principalId);
  const fingerprints = evidence.source.recipients.map(({ identityFingerprint }) => identityFingerprint);
  if (new Set(principals).size !== principals.length) {
    context.addIssue({ code: "custom", path: ["source", "recipients"], message: "Reviewer principal IDs must be unique." });
  }
  if (new Set(fingerprints).size !== fingerprints.length) {
    context.addIssue({ code: "custom", path: ["source", "recipients"], message: "Reviewer identity fingerprints must be unique." });
  }
  if (evidence.claimCoverage.audience !== "authorized_tax_reviewer"
    && evidence.claimCoverage.audience !== "governance_committee") {
    context.addIssue({ code: "custom", path: ["claimCoverage", "audience"], message: "Authority-readiness evidence requires a reviewer audience." });
  }
});

export type AuthorityReadinessEvidence = z.infer<typeof authorityReadinessEvidenceSchema>;
export type AuthorityReadinessRecipient = z.infer<typeof recipientIdentitySchema>;

export function authorityReadinessTaxYear(periodStart: string, periodEnd: string): number {
  const start = new Date(Number(BigInt(periodStart)) * 1_000);
  const year = start.getUTCFullYear();
  const expectedStart = BigInt(Date.UTC(year, 0, 1)) / 1_000n;
  const expectedEnd = BigInt(Date.UTC(year + 1, 0, 1)) / 1_000n;
  if (BigInt(periodStart) !== expectedStart || BigInt(periodEnd) !== expectedEnd) {
    throw new Error("Authority-readiness evidence requires one complete calendar-year payroll book.");
  }
  return year;
}

export function assertUnambiguousAuthorityRecipientReferences(
  issues: readonly FamiliarTaxRenderIssue[],
): void {
  if (issues.length > 0) {
    throw new Error("Authority-readiness evidence rejects conflicting recipient references.");
  }
}

function uniqueRecipients(recipients: readonly AuthorityReadinessRecipient[]) {
  const parsed = recipients.map((recipient) => recipientIdentitySchema.parse(recipient));
  if (new Set(parsed.map(({ principalId }) => principalId)).size !== parsed.length
    || new Set(parsed.map(({ identityFingerprint }) => identityFingerprint)).size !== parsed.length) {
    throw new Error("Authority-readiness recipients must use unique principals and identity fingerprints.");
  }
  return [...parsed].sort((left, right) => left.principalId.localeCompare(right.principalId));
}

export async function createAuthorityReadinessEvidence(input: {
  report: CompletePayrollBookReport;
  trustedSnapshot: TrustedPayrollBookSnapshot;
  reportCommitment: string;
  recipients: readonly AuthorityReadinessRecipient[];
  generatedAt?: Date;
}): Promise<AuthorityReadinessEvidence> {
  const report = completePayrollBookReportSchema.parse(input.report);
  if (report.scope !== "tax_authority") {
    throw new Error("Authority-readiness evidence requires an authorized-reviewer payroll book.");
  }
  const snapshot = trustedPayrollBookSnapshotSchema.parse(input.trustedSnapshot);
  const reportCommitment = commitmentSchema.parse(input.reportCommitment);
  if (reportCommitment !== payrollReportPayloadCommitment(report)) {
    throw new Error("The readiness export report commitment does not match the verified payroll book.");
  }
  const recipients = uniqueRecipients(input.recipients);
  if (recipients.length === 0) throw new Error("Authority-readiness evidence requires a verified recipient identity.");
  if (report.recipientIdentities) {
    const expected = [...report.recipientIdentities]
      .sort((left, right) => left.principalId.localeCompare(right.principalId));
    if (hashCanonicalJson(expected) !== hashCanonicalJson(recipients)) {
      throw new Error("The readiness recipient identities differ from the encrypted report binding.");
    }
  } else {
    throw new Error("The encrypted reviewer report has no bound recipient identity fingerprints.");
  }

  const verification = await verifyCompletePayrollBookReport({ report, trustedSnapshot: snapshot });
  const income = await createVerifiedIncomeEvidence({
    report,
    trustedSnapshot: snapshot,
    generatedAt: input.generatedAt ?? new Date(report.generatedAt),
  });
  const familiar = renderFamiliarTaxDocumentsWithDiagnostics(income);
  assertUnambiguousAuthorityRecipientReferences(familiar.issues);
  const taxYear = authorityReadinessTaxYear(report.checkpoint.periodStart, report.checkpoint.periodEnd);
  const jurisdictions = [...new Set(income.lines.map(({ policy }) => policy.jurisdictionCode))].sort();
  const recipientReferenceResolutions = [...new Map(income.lines.flatMap((line) => {
    const resolution = line.recipientReferenceResolution;
    return resolution ? [[resolution.resolutionId, resolution] as const] : [];
  })).values()].sort((left, right) => left.resolutionId.localeCompare(right.resolutionId));
  const policyBindings = [...new Map(income.lines.map(({ policy }) => [
    `${policy.policyId}:${policy.policyRevision}:${policy.policyCatalogRoot}`,
    {
      policyId: policy.policyId,
      policyRevision: policy.policyRevision,
      policyCommitment: policy.policyCommitment,
      policyCatalogRoot: policy.policyCatalogRoot,
      jurisdictionCode: policy.jurisdictionCode,
      sourceUri: policy.sourceUri,
      legalReviewRequired: policy.legalReviewRequired,
    },
  ])).values()].sort((left, right) =>
    `${left.policyId}:${left.policyRevision}`.localeCompare(`${right.policyId}:${right.policyRevision}`));
  const transactions = [...new Map(report.entries.flatMap((entry) => [
    { kind: "integrity_proof" as const, transactionHash: entry.integrityVerificationTransactionHash },
    { kind: "settlement" as const, transactionHash: entry.settlementTransactionHash },
  ]).map((reference) => [`${reference.kind}:${BigInt(reference.transactionHash).toString()}`, reference])).values()];
  const generatedAt = (input.generatedAt ?? new Date()).toISOString();
  const core = authorityReadinessCoreSchema.parse({
    packageVersion: "payo-authority-readiness-evidence-v1",
    readinessState: "verified_evidence",
    filingState: "exported_not_submitted",
    generatedAt,
    source: {
      reportId: report.reportId,
      reportCommitment,
      organizationId: report.organizationId,
      scope: report.scope,
      recipients,
    },
    reporting: {
      periodStart: report.checkpoint.periodStart,
      periodEnd: report.checkpoint.periodEnd,
      taxYear,
      jurisdictionCodes: jurisdictions,
    },
    coverage: {
      mode: "complete_selected_onchain_book",
      entryCount: verification.entryCount,
      lineCount: income.lines.length,
      familiarDocumentCount: familiar.documents.length,
      familiarDocumentIssueCount: familiar.issues.length,
    },
    totals: (["STRK", "USDC"] as const).map((token) => ({ token, ...verification.totals[token] })),
    ...(recipientReferenceResolutions.length > 0 ? { recipientReferenceResolutions } : {}),
    policyBindings,
    chainEvidence: {
      chainId: report.checkpoint.chainId,
      sealAddress: report.checkpoint.sealAddress,
      ownerAddress: report.checkpoint.ownerAddress,
      accumulatorRoot: report.checkpoint.accumulatorRoot,
      observedAt: snapshot.observedAt,
      blockNumber: snapshot.blockNumber,
      transactions,
    },
    claimCoverage: createPayrollEvidenceClaimCoverage(
      recipients.length > 1 ? "governance_committee" : "authorized_tax_reviewer",
    ),
    requiredOfficialIntegration: [
      "government_recognized_identity",
      "authority_schema_and_business_rules",
      "authorized_transmitter_credentials",
      "authority_acceptance_acknowledgement",
    ],
  });
  return authorityReadinessEvidenceSchema.parse({
    ...core,
    evidenceCommitment: hashCanonicalJson({
      domain: "PAYO_AUTHORITY_READINESS_EVIDENCE_V1",
      evidence: core,
    }),
  });
}

export function verifyAuthorityReadinessEvidence(input: unknown): AuthorityReadinessEvidence {
  const evidence = authorityReadinessEvidenceSchema.parse(input);
  const { evidenceCommitment, ...core } = evidence;
  const expected = hashCanonicalJson({
    domain: "PAYO_AUTHORITY_READINESS_EVIDENCE_V1",
    evidence: core,
  });
  if (evidenceCommitment !== expected) {
    throw new Error("The authority-readiness evidence was mutated after verification.");
  }
  return evidence;
}

export function authorityReadinessFilename(evidence: AuthorityReadinessEvidence): string {
  return `payo-authority-readiness-${evidence.reporting.taxYear}-${evidence.evidenceCommitment.slice(2, 10)}.json`;
}
