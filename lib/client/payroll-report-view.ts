import type {
  EncryptedPayrollReport,
  PayrollReportPayload,
} from "@/lib/disclosure/payroll-book-report";
import type {
  FamiliarTaxDocument,
  FamiliarTaxRenderIssue,
} from "@/lib/disclosure/tax-evidence";
import type { RecipientReferenceResolution } from "@/lib/domain/records";
import type { AuthorityReadinessEvidence } from "@/lib/disclosure/authority-readiness";
import type { PublicAccountabilitySummary } from "@/lib/disclosure/public-accountability";
import {
  formatTokenAmount,
  type PayrollTokenSymbol,
} from "@/lib/starknet/tokens";

export type ReportTotal = {
  token: PayrollTokenSymbol;
  gross?: string;
  deductions?: string;
  net: string;
};

export type PayrollReportView = {
  file: EncryptedPayrollReport;
  filename: string;
  recipientPrincipalId: string;
  organizationId: string;
  authorizedRecipientCount: number;
  title: string;
  workerName?: string;
  scope: "employer" | "tax_authority" | "worker";
  countLabel: string;
  totals: ReportTotal[];
  periodLabel: string;
  checkpointRoot: string;
  blockNumber: string;
  packageCommitment: string;
  transactionReferences: Array<{
    kind: "Integrity proof" | "Settlement";
    hash: string;
  }>;
  familiarTaxDocuments: FamiliarTaxDocument[];
  familiarTaxIssues: FamiliarTaxRenderIssue[];
  recipientReferenceResolutions: RecipientReferenceResolution[];
  authorityReadinessEvidence?: AuthorityReadinessEvidence;
  publicAccountabilitySummary?: PublicAccountabilitySummary;
};

export function createPayrollReportView(input: {
  file: EncryptedPayrollReport;
  filename: string;
  recipientPrincipalId: string;
  payload: PayrollReportPayload;
  verification: unknown;
  blockNumber: string;
  familiarTaxDocuments: FamiliarTaxDocument[];
  familiarTaxIssues: FamiliarTaxRenderIssue[];
  authorityReadinessEvidence?: AuthorityReadinessEvidence;
  publicAccountabilitySummary?: PublicAccountabilitySummary;
}): PayrollReportView {
  const start = new Date(Number(BigInt(input.payload.checkpoint.periodStart)) * 1_000);
  const end = new Date(Number(BigInt(input.payload.checkpoint.periodEnd)) * 1_000 - 1);
  const dateFormat = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "numeric",
    day: "numeric",
    timeZone: "UTC",
  });
  const periodLabel = `${start.getUTCFullYear()} · ${dateFormat.format(start)} – ${dateFormat.format(end)}`;
  const transactionReferences = Array.from(new Map(
    (input.payload.reportType === "complete_payroll_book"
      ? input.payload.entries
      : input.payload.lines
    ).flatMap((entry) => [
      { kind: "Integrity proof" as const, hash: entry.integrityVerificationTransactionHash },
      { kind: "Settlement" as const, hash: entry.settlementTransactionHash },
    ]).map((reference) => [`${reference.kind}:${reference.hash}`, reference]),
  ).values());

  if (input.payload.reportType === "complete_payroll_book") {
    const verified = input.verification as {
      entryCount: number;
      totals: Record<PayrollTokenSymbol, {
        grossAtomic: string;
        deductionsAtomic: string;
        netAtomic: string;
      }>;
    };
    const recipientReferenceResolutions = [...new Map(input.payload.entries.flatMap((entry) =>
      entry.lines.flatMap((line) => line.recipientReferenceResolution
        ? [[line.recipientReferenceResolution.resolutionId, line.recipientReferenceResolution] as const]
        : []))).values()];
    const totals = (["STRK", "USDC"] as const).flatMap((token) => {
      const value = verified.totals[token];
      return BigInt(value.grossAtomic) === 0n ? [] : [{
        token,
        gross: formatTokenAmount(BigInt(value.grossAtomic), token),
        deductions: formatTokenAmount(BigInt(value.deductionsAtomic), token),
        net: formatTokenAmount(BigInt(value.netAtomic), token),
      }];
    });
    return {
      file: input.file,
      filename: input.filename,
      recipientPrincipalId: input.recipientPrincipalId,
      organizationId: input.payload.organizationId,
      authorizedRecipientCount: input.payload.recipientIdentities?.length ?? 1,
      title: input.payload.scope === "tax_authority"
        ? "Payroll book for tax review"
        : "Complete employer payroll book",
      scope: input.payload.scope,
      countLabel: `${verified.entryCount} payroll ${verified.entryCount === 1 ? "entry" : "entries"} · complete book`,
      totals,
      periodLabel,
      checkpointRoot: input.payload.checkpoint.accumulatorRoot,
      blockNumber: input.blockNumber,
      packageCommitment: input.file.packageCommitment,
      transactionReferences,
      familiarTaxDocuments: input.familiarTaxDocuments,
      familiarTaxIssues: input.familiarTaxIssues,
      recipientReferenceResolutions,
      authorityReadinessEvidence: input.authorityReadinessEvidence,
      publicAccountabilitySummary: input.publicAccountabilitySummary,
    };
  }

  const workerPayload = input.payload;
  const verified = input.verification as {
    lineCount: number;
    netTotals: Record<PayrollTokenSymbol, string>;
  };
  const totals = (["STRK", "USDC"] as const).flatMap((token) => {
    const lines = workerPayload.lines.filter(({ line }) => line.source.token === token);
    const gross = lines.reduce((sum, { line }) =>
      sum + line.source.earningsAtomic.reduce((lineSum, amount) => lineSum + BigInt(amount), 0n), 0n);
    const deductions = lines.reduce((sum, { line }) =>
      sum + line.source.deductionsAtomic.reduce((lineSum, amount) => lineSum + BigInt(amount), 0n), 0n);
    const net = BigInt(verified.netTotals[token]);
    return gross === 0n && net === 0n ? [] : [{
      token,
      gross: formatTokenAmount(gross, token),
      deductions: formatTokenAmount(deductions, token),
      net: formatTokenAmount(net, token),
    }];
  });
  const recipientReferenceResolutions = [...new Map(workerPayload.lines.flatMap(({ line }) =>
    line.recipientReferenceResolution
      ? [[line.recipientReferenceResolution.resolutionId, line.recipientReferenceResolution] as const]
      : [])).values()];
  return {
    file: input.file,
    filename: input.filename,
    recipientPrincipalId: input.recipientPrincipalId,
    organizationId: input.payload.organizationId,
    authorizedRecipientCount: 1,
    title: "Your private income statement",
    workerName: input.payload.recipientReference,
    scope: "worker",
    countLabel: `${verified.lineCount} of your payroll ${verified.lineCount === 1 ? "line" : "lines"} verified`,
    totals,
    periodLabel,
    checkpointRoot: input.payload.checkpoint.accumulatorRoot,
    blockNumber: input.blockNumber,
    packageCommitment: input.file.packageCommitment,
    transactionReferences,
    familiarTaxDocuments: input.familiarTaxDocuments,
    familiarTaxIssues: input.familiarTaxIssues,
    recipientReferenceResolutions,
    authorityReadinessEvidence: input.authorityReadinessEvidence,
  };
}
