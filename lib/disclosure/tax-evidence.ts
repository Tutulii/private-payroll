import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { atomicAmountSchema, payrollTokenSchema } from "@/lib/domain/payroll";
import { commitmentSchema, starknetAddressSchema, uuidV7Schema } from "@/lib/domain/records";
import { policyPackCommitment, type PolicyPack } from "@/lib/policy/engine";
import {
  payrollReportPayloadSchema,
  trustedPayrollBookSnapshotSchema,
  verifyCompletePayrollBookReport,
  verifyWorkerIncomeStatement,
  type PayrollReportPayload,
  type TrustedPayrollBookSnapshot,
} from "./payroll-book-report";

const unixSecondsSchema = z.string().regex(/^(0|[1-9]\d*)$/);
const u32Schema = z.number().int().nonnegative().max(0xffff_ffff);
const workerTypeSchema = z.enum(["employee", "contractor", "agent_service"]);

export const verifiedIncomePolicyBindingSchema = z.object({
  policyId: z.string().min(1).max(160),
  policyRevision: z.number().int().positive(),
  policyCommitment: commitmentSchema,
  policyCatalogRoot: commitmentSchema,
  jurisdictionCode: z.string().regex(/^[A-Z]{2}(-[A-Z0-9]{1,3})?$/),
  effectiveFrom: z.string().date(),
  effectiveUntil: z.string().date(),
  sourceUri: z.string().url(),
  legalReviewRequired: z.literal(true),
}).strict();

export const verifiedIncomeLineSchema = z.object({
  bookIndex: u32Schema,
  lineIndex: z.number().int().min(0).max(49),
  recipientReference: z.string().min(1).max(240),
  recipientAddress: starknetAddressSchema,
  workerType: workerTypeSchema,
  token: payrollTokenSchema,
  grossAtomic: atomicAmountSchema,
  deductionsAtomic: atomicAmountSchema,
  netAtomic: atomicAmountSchema,
  policy: verifiedIncomePolicyBindingSchema,
  integrityVerificationTransactionHash: starknetAddressSchema,
  settlementTransactionHash: starknetAddressSchema,
}).strict().superRefine((line, context) => {
  if (BigInt(line.grossAtomic) - BigInt(line.deductionsAtomic) !== BigInt(line.netAtomic)) {
    context.addIssue({ code: "custom", path: ["netAtomic"], message: "Verified income arithmetic does not balance." });
  }
});
export type VerifiedIncomeLine = z.infer<typeof verifiedIncomeLineSchema>;

const verifiedIncomeEvidenceCoreSchema = z.object({
  evidenceVersion: z.literal("payo-verified-income-evidence-v1"),
  sourceReportId: uuidV7Schema,
  organizationId: uuidV7Schema,
  sourceReportType: z.enum(["complete_payroll_book", "worker_income_statement"]),
  scope: z.enum(["employer", "tax_authority", "worker"]),
  taxYear: z.number().int().min(2020).max(2100),
  checkpoint: z.object({
    ownerAddress: starknetAddressSchema,
    periodStart: unixSecondsSchema,
    periodEnd: unixSecondsSchema,
    entryCount: u32Schema,
    accumulatorRoot: commitmentSchema,
  }).strict(),
  coverage: z.object({
    completeBookEntryCount: u32Schema,
    disclosedLineCount: u32Schema,
    mode: z.enum(["complete_book", "worker_lines_in_complete_book"]),
  }).strict(),
  lines: z.array(verifiedIncomeLineSchema).min(1),
  generatedAt: z.string().datetime(),
}).strict();

export const verifiedIncomeEvidenceSchema = verifiedIncomeEvidenceCoreSchema.extend({
  evidenceCommitment: commitmentSchema,
}).strict();
export type VerifiedIncomeEvidence = z.infer<typeof verifiedIncomeEvidenceSchema>;

export const familiarTaxDocumentSchema = z.object({
  documentVersion: z.literal("payo-familiar-tax-evidence-v1"),
  style: z.enum(["w2_style", "p60_style", "t4_style"]),
  title: z.string().min(1).max(160),
  recipientReference: z.string().min(1).max(240),
  recipientAddress: starknetAddressSchema,
  jurisdictionCode: z.string().regex(/^(US|GB|CA)(-[A-Z0-9]{1,3})?$/),
  taxYear: z.number().int().min(2020).max(2100),
  token: payrollTokenSchema,
  fields: z.array(z.object({
    code: z.string().min(1).max(40),
    label: z.string().min(1).max(160),
    amountAtomic: atomicAmountSchema,
  }).strict()).min(3),
  policyBindings: z.array(verifiedIncomePolicyBindingSchema).min(1),
  sourceLineCount: z.number().int().positive(),
  completeBookEntryCount: u32Schema,
  checkpointRoot: commitmentSchema,
  sourceEvidenceCommitment: commitmentSchema,
  disclaimer: z.literal("PAYO cryptographic evidence only — not an official tax form, filing, certification, or legal/tax advice."),
  documentCommitment: commitmentSchema,
}).strict();
export type FamiliarTaxDocument = z.infer<typeof familiarTaxDocumentSchema>;

function taxYearForPeriod(periodStart: string, periodEnd: string): number {
  const start = new Date(Number(BigInt(periodStart)) * 1_000);
  const year = start.getUTCFullYear();
  const expectedStart = BigInt(Math.floor(Date.UTC(year, 0, 1) / 1_000));
  const expectedEnd = BigInt(Math.floor(Date.UTC(year + 1, 0, 1) / 1_000));
  if (BigInt(periodStart) !== expectedStart || BigInt(periodEnd) !== expectedEnd) {
    throw new Error("Familiar tax evidence requires one complete calendar-year payroll book.");
  }
  return year;
}

function canonicalLine(input: {
  bookIndex: number;
  lineIndex: number;
  recipientReference: string;
  recipientAddress: string;
  workerType: VerifiedIncomeLine["workerType"];
  token: VerifiedIncomeLine["token"];
  earningsAtomic: readonly string[];
  deductionsAtomic: readonly string[];
  policy: PolicyPack;
  policyCatalogRoot: string;
  integrityVerificationTransactionHash: string;
  settlementTransactionHash: string;
}): VerifiedIncomeLine {
  const gross = input.earningsAtomic.reduce((sum, value) => sum + BigInt(value), 0n);
  const deductions = input.deductionsAtomic.reduce((sum, value) => sum + BigInt(value), 0n);
  if (deductions > gross) throw new Error("Verified income deductions exceed gross pay.");
  return verifiedIncomeLineSchema.parse({
    bookIndex: input.bookIndex,
    lineIndex: input.lineIndex,
    recipientReference: input.recipientReference,
    recipientAddress: input.recipientAddress,
    workerType: input.workerType,
    token: input.token,
    grossAtomic: gross.toString(),
    deductionsAtomic: deductions.toString(),
    netAtomic: (gross - deductions).toString(),
    policy: {
      policyId: input.policy.id,
      policyRevision: input.policy.revision,
      policyCommitment: policyPackCommitment(input.policy),
      policyCatalogRoot: input.policyCatalogRoot,
      jurisdictionCode: input.policy.jurisdictionCode,
      effectiveFrom: input.policy.effectiveFrom,
      effectiveUntil: input.policy.effectiveUntil,
      sourceUri: input.policy.sourceUri,
      legalReviewRequired: input.policy.legalReviewRequired,
    },
    integrityVerificationTransactionHash: input.integrityVerificationTransactionHash,
    settlementTransactionHash: input.settlementTransactionHash,
  });
}

/**
 * Re-verifies the report against an independently read book snapshot before
 * producing the one canonical income representation consumed by every style.
 */
export async function createVerifiedIncomeEvidence(input: {
  report: PayrollReportPayload;
  trustedSnapshot: TrustedPayrollBookSnapshot;
  generatedAt?: Date;
}): Promise<VerifiedIncomeEvidence> {
  const report = payrollReportPayloadSchema.parse(input.report);
  const trustedSnapshot = trustedPayrollBookSnapshotSchema.parse(input.trustedSnapshot);
  const lines: VerifiedIncomeLine[] = [];
  if (report.reportType === "complete_payroll_book") {
    await verifyCompletePayrollBookReport({ report, trustedSnapshot });
    for (const entry of report.entries) {
      for (const line of entry.lines) {
        lines.push(canonicalLine({
          bookIndex: entry.index,
          lineIndex: line.index,
          recipientReference: line.recipientReference,
          recipientAddress: line.source.recipientAddress,
          workerType: line.workerType,
          token: line.source.token,
          earningsAtomic: line.source.earningsAtomic,
          deductionsAtomic: line.source.deductionsAtomic,
          policy: line.policy,
          policyCatalogRoot: entry.policyCatalogRoot,
          integrityVerificationTransactionHash: entry.integrityVerificationTransactionHash,
          settlementTransactionHash: entry.settlementTransactionHash,
        }));
      }
    }
  } else {
    await verifyWorkerIncomeStatement({ statement: report, trustedSnapshot });
    for (const disclosed of report.lines) {
      const line = disclosed.line;
      lines.push(canonicalLine({
        bookIndex: disclosed.bookIndex,
        lineIndex: line.index,
        recipientReference: line.recipientReference,
        recipientAddress: line.source.recipientAddress,
        workerType: line.workerType,
        token: line.source.token,
        earningsAtomic: line.source.earningsAtomic,
        deductionsAtomic: line.source.deductionsAtomic,
        policy: line.policy,
        policyCatalogRoot: disclosed.policyCatalogRoot,
        integrityVerificationTransactionHash: disclosed.integrityVerificationTransactionHash,
        settlementTransactionHash: disclosed.settlementTransactionHash,
      }));
    }
  }
  if (lines.length === 0) throw new Error("Verified income evidence cannot omit every payroll line.");
  const generatedAt = input.generatedAt ?? new Date();
  const core = verifiedIncomeEvidenceCoreSchema.parse({
    evidenceVersion: "payo-verified-income-evidence-v1",
    sourceReportId: report.reportId,
    organizationId: report.organizationId,
    sourceReportType: report.reportType,
    scope: report.scope,
    taxYear: taxYearForPeriod(report.checkpoint.periodStart, report.checkpoint.periodEnd),
    checkpoint: {
      ownerAddress: report.checkpoint.ownerAddress,
      periodStart: report.checkpoint.periodStart,
      periodEnd: report.checkpoint.periodEnd,
      entryCount: report.checkpoint.entryCount,
      accumulatorRoot: report.checkpoint.accumulatorRoot,
    },
    coverage: {
      completeBookEntryCount: trustedSnapshot.entries.length,
      disclosedLineCount: lines.length,
      mode: report.reportType === "complete_payroll_book" ? "complete_book" : "worker_lines_in_complete_book",
    },
    lines,
    generatedAt: generatedAt.toISOString(),
  });
  return verifiedIncomeEvidenceSchema.parse({
    ...core,
    evidenceCommitment: hashCanonicalJson({ domain: "PAYO_VERIFIED_INCOME_EVIDENCE_V1", evidence: core }),
  });
}

function styleForJurisdiction(jurisdictionCode: string): FamiliarTaxDocument["style"] | null {
  const country = jurisdictionCode.split("-")[0];
  if (country === "US") return "w2_style";
  if (country === "GB") return "p60_style";
  if (country === "CA") return "t4_style";
  return null;
}

const labels = {
  w2_style: {
    title: "W-2-style PAYO wage evidence",
    gross: ["BOX_1", "Wages, tips, other compensation"],
    deductions: ["BOX_2", "Federal income tax withheld under bound policy"],
    net: ["PAYO_NET", "Private net pay"],
  },
  p60_style: {
    title: "P60-style PAYO pay evidence",
    gross: ["TOTAL_PAY", "Total pay in this employment"],
    deductions: ["BOUND_DEDUCTIONS", "Deductions under bound policy"],
    net: ["PAYO_NET", "Private net pay"],
  },
  t4_style: {
    title: "T4-style PAYO remuneration evidence",
    gross: ["BOX_14", "Employment income"],
    deductions: ["BOX_22", "Income tax deducted under bound policy"],
    net: ["PAYO_NET", "Private net pay"],
  },
} as const;

/** Builds familiar views only for verified employee lines; contractors stay out. */
export function renderFamiliarTaxDocuments(
  evidenceInput: VerifiedIncomeEvidence,
): FamiliarTaxDocument[] {
  const evidence = verifiedIncomeEvidenceSchema.parse(evidenceInput);
  const groups = new Map<string, VerifiedIncomeLine[]>();
  for (const line of evidence.lines) {
    if (line.workerType !== "employee" || !styleForJurisdiction(line.policy.jurisdictionCode)) continue;
    const key = [BigInt(line.recipientAddress).toString(), line.policy.jurisdictionCode, line.token].join(":");
    groups.set(key, [...(groups.get(key) ?? []), line]);
  }
  return [...groups.values()].map((lines) => {
    const first = lines[0];
    if (lines.some((line) => line.recipientReference !== first.recipientReference)) {
      throw new Error("One recipient address has conflicting reporting references.");
    }
    const style = styleForJurisdiction(first.policy.jurisdictionCode)!;
    const gross = lines.reduce((sum, line) => sum + BigInt(line.grossAtomic), 0n);
    const deductions = lines.reduce((sum, line) => sum + BigInt(line.deductionsAtomic), 0n);
    const policyBindings = [...new Map(lines.map((line) => [
      `${line.policy.policyId}:${line.policy.policyRevision}:${line.policy.policyCatalogRoot}`,
      line.policy,
    ])).values()];
    const definition = labels[style];
    const withoutCommitment = {
      documentVersion: "payo-familiar-tax-evidence-v1" as const,
      style,
      title: definition.title,
      recipientReference: first.recipientReference,
      recipientAddress: first.recipientAddress,
      jurisdictionCode: first.policy.jurisdictionCode,
      taxYear: evidence.taxYear,
      token: first.token,
      fields: [
        { code: definition.gross[0], label: definition.gross[1], amountAtomic: gross.toString() },
        { code: definition.deductions[0], label: definition.deductions[1], amountAtomic: deductions.toString() },
        { code: definition.net[0], label: definition.net[1], amountAtomic: (gross - deductions).toString() },
      ],
      policyBindings,
      sourceLineCount: lines.length,
      completeBookEntryCount: evidence.coverage.completeBookEntryCount,
      checkpointRoot: evidence.checkpoint.accumulatorRoot,
      sourceEvidenceCommitment: evidence.evidenceCommitment,
      disclaimer: "PAYO cryptographic evidence only — not an official tax form, filing, certification, or legal/tax advice." as const,
    };
    return familiarTaxDocumentSchema.parse({
      ...withoutCommitment,
      documentCommitment: hashCanonicalJson({ domain: "PAYO_FAMILIAR_TAX_EVIDENCE_V1", document: withoutCommitment }),
    });
  });
}

export function verifyVerifiedIncomeEvidence(
  evidenceInput: VerifiedIncomeEvidence,
): VerifiedIncomeEvidence {
  const evidence = verifiedIncomeEvidenceSchema.parse(evidenceInput);
  const { evidenceCommitment, ...core } = evidence;
  const expected = hashCanonicalJson({
    domain: "PAYO_VERIFIED_INCOME_EVIDENCE_V1",
    evidence: core,
  });
  if (expected !== evidenceCommitment) {
    throw new Error("The canonical verified-income evidence was mutated after verification.");
  }
  return evidence;
}

export function verifyFamiliarTaxDocument(input: {
  document: FamiliarTaxDocument;
  evidence: VerifiedIncomeEvidence;
}): FamiliarTaxDocument {
  const document = familiarTaxDocumentSchema.parse(input.document);
  const evidence = verifyVerifiedIncomeEvidence(input.evidence);
  const expected = renderFamiliarTaxDocuments(evidence).find((candidate) =>
    candidate.style === document.style
      && BigInt(candidate.recipientAddress) === BigInt(document.recipientAddress)
      && candidate.token === document.token
      && candidate.policyBindings[0]?.jurisdictionCode === document.policyBindings[0]?.jurisdictionCode);
  if (!expected || expected.documentCommitment !== document.documentCommitment
    || hashCanonicalJson(expected) !== hashCanonicalJson(document)) {
    throw new Error("The familiar tax document is omitted, mutated, or bound to different verified income evidence.");
  }
  return document;
}

export function familiarTaxEvidenceFilename(document: FamiliarTaxDocument): string {
  const kind = document.style.replace("_style", "").replace("w2", "w-2");
  const recipient = document.recipientReference.toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);
  return `payo-${kind}-style-${recipient || "worker"}-${document.taxYear}-${document.documentCommitment.slice(2, 10)}.json`;
}
