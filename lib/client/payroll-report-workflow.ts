import { z } from "zod";
import {
  decryptVaultRecord,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import {
  buildPayrollBookReportEntry,
  completePayrollBookReportSchema,
  createWorkerIncomeStatement,
  encryptPayrollReport,
  encryptedPayrollReportSchema,
  inspectEncryptedPayrollReport,
  openEncryptedPayrollReport,
  payrollBookReportSourceSchema,
  verifyCompletePayrollBookReport,
  verifyTrustedPayrollBookSnapshot,
  verifyWorkerIncomeStatement,
  type EncryptedPayrollReport,
  type PayrollReportPayload,
  type TrustedPayrollBookSnapshot,
} from "@/lib/disclosure/payroll-book-report";
import {
  createVerifiedIncomeEvidence,
  renderFamiliarTaxDocuments,
} from "@/lib/disclosure/tax-evidence";
import {
  createEncryptedWorkerStatementSource,
  encryptedWorkerStatementSourceSchema,
  generateWorkerIncomeStatementFromSource,
  openEncryptedWorkerStatementSource,
  type EncryptedWorkerStatementSource,
} from "@/lib/disclosure/worker-statement-source";
import type { PayoReportingIdentity } from "@/lib/crypto/reporting-identity";
import { generateUuidV7 } from "@/lib/domain/records";
import { buildPayrollIntegrityInputsFromSerialized } from "@/lib/proof/input-builder";
import type { PayoClient } from "./payo-client";
import type { PayAgreementDirectoryRecord } from "./agreement-directory";
import type { PayeeDirectoryRecord } from "./payee-directory";

const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const encryptedRunPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  agreementRoot: commitmentSchema,
  manifestRoot: commitmentSchema,
  policyRoot: commitmentSchema,
  fxRoot: commitmentSchema,
  runNullifier: commitmentSchema,
  claimProofSource: z.object({ buildInput: z.unknown() }).strict(),
}).passthrough();

type ReportClient = Pick<PayoClient, "getPayrollBookSnapshot" | "getPayrollBookSources">;

export type PayrollReportKind = "employer_book" | "tax_book" | "worker_statement";

function sameFelt(left: string, right: string): boolean {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

function safeFilenamePart(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
}

export function payrollReportFilename(report: EncryptedPayrollReport, input?: {
  recipientReference?: string;
  year?: number;
}): string {
  const scope = report.reportType === "worker_income_statement"
    ? `worker-income-statement${input?.recipientReference ? `-${safeFilenamePart(input.recipientReference)}` : ""}`
    : "complete-payroll-book";
  const year = input?.year ? `-${input.year}` : "";
  return `payo-${scope}${year}-${report.reportId.slice(0, 8)}.json`;
}

function metadataForPayroll(input: {
  payrollAgreementIds: readonly string[];
  agreements: readonly PayAgreementDirectoryRecord[];
  payees: readonly PayeeDirectoryRecord[];
}) {
  const agreements = new Map(input.agreements.map((record) => [record.agreement.id, record]));
  const payees = new Map(input.payees.map((record) => [record.id, record]));
  return Object.fromEntries(input.payrollAgreementIds.map((agreementId) => {
    const agreementRecord = agreements.get(agreementId);
    if (!agreementRecord) throw new Error(`Encrypted agreement ${agreementId} is unavailable for the complete book.`);
    const payee = payees.get(agreementRecord.payeeId);
    if (!payee) throw new Error(`Encrypted contributor ${agreementRecord.payeeId} is unavailable for the complete book.`);
    const workerType = agreementRecord.agreement.classification;
    if ((workerType === "agent_service") !== (payee.principalKind === "agent")) {
      throw new Error(`Contributor classification for agreement ${agreementId} is inconsistent.`);
    }
    return [agreementId, {
      recipientReference: payee.displayName,
      workerType,
    }];
  }));
}

async function createFamiliarTaxArtifacts(
  report: PayrollReportPayload,
  trustedSnapshot: TrustedPayrollBookSnapshot,
) {
  const verifiedIncomeEvidence = await createVerifiedIncomeEvidence({
    report,
    trustedSnapshot,
    generatedAt: new Date(report.generatedAt),
  });
  return {
    verifiedIncomeEvidence,
    familiarTaxDocuments: renderFamiliarTaxDocuments(verifiedIncomeEvidence),
  };
}

export async function createEncryptedPayrollReportFromBook(input: {
  client: ReportClient;
  organizationId: string;
  ownerAddress: string;
  periodStart: string;
  periodEnd: string;
  principal: VaultPrincipalKeyPair;
  recipient: VaultPrincipal;
  kind: PayrollReportKind;
  agreements: readonly PayAgreementDirectoryRecord[];
  payees: readonly PayeeDirectoryRecord[];
  workerPayeeId?: string;
  now?: Date;
}) {
  const [snapshotResponse, sourceResponse] = await Promise.all([
    input.client.getPayrollBookSnapshot({
      organizationId: input.organizationId,
      ownerAddress: input.ownerAddress,
      periodStart: input.periodStart,
      periodEnd: input.periodEnd,
    }),
    input.client.getPayrollBookSources({
      organizationId: input.organizationId,
      ownerAddress: input.ownerAddress,
      periodStart: input.periodStart,
      periodEnd: input.periodEnd,
    }),
  ]);
  const snapshot = verifyTrustedPayrollBookSnapshot(snapshotResponse.snapshot);
  if (snapshot.entries.length === 0) {
    throw new Error("This payer has no finalized PAYO payroll-book entries for the selected period.");
  }
  const sources = sourceResponse.sources.map((source) => payrollBookReportSourceSchema.parse(source));
  const sourceByCommitment = new Map<string, (typeof sources)[number]>();
  for (const source of sources) {
    const key = BigInt(source.bookEntryCommitment).toString();
    if (sourceByCommitment.has(key)) throw new Error("Duplicate encrypted evidence exists for one payroll-book entry.");
    sourceByCommitment.set(key, source);
  }

  const reportEntries = [];
  for (const trustedEntry of snapshot.entries) {
    const source = sourceByCommitment.get(BigInt(trustedEntry.entryCommitment).toString());
    if (!source) {
      throw new Error(
        `Complete-book export stopped: encrypted evidence for on-chain entry ${trustedEntry.index + 1} is unavailable to this organization.`,
      );
    }
    if (
      source.runEnvelope.aad.organizationId !== input.organizationId
      || source.runEnvelope.aad.recordType !== "payroll-run"
      || source.runEnvelope.aad.recordId !== source.runId
      || source.runEnvelope.aad.revision !== source.runRevision
    ) throw new Error(`Payroll-book source ${source.runId} has invalid encrypted-record identity.`);
    const payload = encryptedRunPayloadSchema.parse(decryptVaultRecord(source.runEnvelope, input.principal));
    const payroll = await buildPayrollIntegrityInputsFromSerialized(
      payload.claimProofSource.buildInput as Parameters<typeof buildPayrollIntegrityInputsFromSerialized>[0],
    );
    for (const [actual, expected, label] of [
      [payroll.agreementRoot, payload.agreementRoot, "agreement"],
      [payroll.manifestRoot, payload.manifestRoot, "manifest"],
      [payroll.policyRoot, payload.policyRoot, "policy"],
      [payroll.fxRoot, payload.fxRoot, "FX"],
      [payroll.runNullifier, payload.runNullifier, "run nullifier"],
    ] as const) {
      if (!sameFelt(actual, expected)) throw new Error(`Encrypted payroll ${source.runId} has a changed ${label} commitment.`);
    }
    const lineMetadata = metadataForPayroll({
      payrollAgreementIds: payroll.proofBindings.map(({ agreementId }) => agreementId),
      agreements: input.agreements,
      payees: input.payees,
    });
    reportEntries.push(await buildPayrollBookReportEntry({
      index: trustedEntry.index,
      entry: source.bookEntry,
      payroll,
      policies: (payload.claimProofSource.buildInput as Parameters<typeof buildPayrollIntegrityInputsFromSerialized>[0]).policies,
      lineMetadata,
      integrityVerificationTransactionHash: source.integrityVerificationTransactionHash,
      settlementTransactionHash: source.settlementTransactionHash,
    }));
  }
  if (reportEntries.length !== sourceByCommitment.size) {
    throw new Error("The organization supplied report evidence outside the selected on-chain payroll book.");
  }

  const now = input.now ?? new Date();
  const completeReport = completePayrollBookReportSchema.parse({
    reportVersion: "payo-private-payroll-report-v1",
    reportType: "complete_payroll_book",
    reportId: generateUuidV7(now.getTime()),
    organizationId: input.organizationId,
    scope: input.kind === "tax_book" ? "tax_authority" : "employer",
    checkpoint: snapshot.checkpoint,
    entries: reportEntries,
    generatedAt: now.toISOString(),
  });
  const completeVerification = await verifyCompletePayrollBookReport({
    report: completeReport,
    trustedSnapshot: snapshot,
  });

  if (input.kind !== "worker_statement") {
    const encryptedReport = encryptPayrollReport({ payload: completeReport, recipients: [input.recipient] });
    return {
      encryptedReport,
      payload: completeReport,
      verification: completeVerification,
      snapshot,
      ...await createFamiliarTaxArtifacts(completeReport, snapshot),
    };
  }
  const worker = input.payees.find(({ id }) => id === input.workerPayeeId);
  if (!worker) throw new Error("Choose the contributor whose income statement should be created.");
  const statement = await createWorkerIncomeStatement({
    reportId: generateUuidV7(now.getTime() + 1),
    completeReport,
    trustedSnapshot: snapshot,
    recipientAddress: worker.recipientAddress,
    recipientReference: worker.displayName,
    generatedAt: now,
  });
  const encryptedReport = encryptPayrollReport({ payload: statement, recipients: [input.recipient] });
  return {
    encryptedReport,
    payload: statement,
    verification: await verifyWorkerIncomeStatement({ statement, trustedSnapshot: snapshot }),
    snapshot,
    ...await createFamiliarTaxArtifacts(statement, snapshot),
  };
}

export async function inspectPayrollReportAgainstLiveBook(input: {
  client: Pick<PayoClient, "getPayrollBookSnapshot">;
  encryptedReport: EncryptedPayrollReport;
  recipient: VaultPrincipalKeyPair;
}) {
  const encryptedReport = encryptedPayrollReportSchema.parse(input.encryptedReport);
  const opened = openEncryptedPayrollReport({ encryptedReport, recipient: input.recipient });
  const checkpoint = opened.payload.checkpoint;
  const { snapshot } = await input.client.getPayrollBookSnapshot({
    organizationId: opened.payload.organizationId,
    ownerAddress: checkpoint.ownerAddress,
    periodStart: checkpoint.periodStart,
    periodEnd: checkpoint.periodEnd,
  });
  const inspection = await inspectEncryptedPayrollReport({
    encryptedReport,
    recipient: input.recipient,
    trustedSnapshot: snapshot,
  });
  return {
    ...inspection,
    snapshot,
    ...await createFamiliarTaxArtifacts(inspection.payload, snapshot),
  };
}

/**
 * Employer-side extraction stops at an encrypted recipient-only source. The
 * worker later generates the final statement with their own reporting key.
 */
export async function createWorkerStatementSourceFromBook(input: {
  client: ReportClient;
  organizationId: string;
  ownerAddress: string;
  periodStart: string;
  periodEnd: string;
  principal: VaultPrincipalKeyPair;
  recipientIdentity: PayoReportingIdentity;
  agreements: readonly PayAgreementDirectoryRecord[];
  payees: readonly PayeeDirectoryRecord[];
  workerPayeeId: string;
  now?: Date;
}) {
  const complete = await createEncryptedPayrollReportFromBook({
    client: input.client,
    organizationId: input.organizationId,
    ownerAddress: input.ownerAddress,
    periodStart: input.periodStart,
    periodEnd: input.periodEnd,
    principal: input.principal,
    recipient: input.principal,
    kind: "employer_book",
    agreements: input.agreements,
    payees: input.payees,
    now: input.now,
  });
  if (complete.payload.reportType !== "complete_payroll_book") {
    throw new Error("The complete payroll book could not be reconstructed for worker extraction.");
  }
  const worker = input.payees.find(({ id }) => id === input.workerPayeeId);
  if (!worker) throw new Error("Choose the contributor whose statement source should be created.");
  const encryptedSource = await createEncryptedWorkerStatementSource({
    completeReport: complete.payload,
    trustedSnapshot: complete.snapshot,
    recipientAddress: worker.recipientAddress,
    recipientReference: worker.displayName,
    recipientIdentity: input.recipientIdentity,
    now: input.now,
  });
  return {
    encryptedSource,
    worker,
    snapshot: complete.snapshot,
    completeBookVerification: complete.verification,
  };
}

/** Worker-side source opening, live chain read, final generation and self-encryption. */
export async function generateWorkerStatementAgainstLiveBook(input: {
  client: Pick<PayoClient, "getPayrollBookSnapshot">;
  encryptedSource: EncryptedWorkerStatementSource;
  recipient: VaultPrincipalKeyPair;
  now?: Date;
}) {
  const encryptedSource = encryptedWorkerStatementSourceSchema.parse(input.encryptedSource);
  const opened = openEncryptedWorkerStatementSource({ encryptedSource, recipient: input.recipient });
  const checkpoint = opened.record.source.statement.checkpoint;
  const { snapshot } = await input.client.getPayrollBookSnapshot({
    organizationId: encryptedSource.organizationId,
    ownerAddress: checkpoint.ownerAddress,
    periodStart: checkpoint.periodStart,
    periodEnd: checkpoint.periodEnd,
  });
  const generated = await generateWorkerIncomeStatementFromSource({
    encryptedSource,
    recipient: input.recipient,
    trustedSnapshot: snapshot,
    now: input.now,
  });
  const encryptedReport = encryptPayrollReport({
    payload: generated.statement,
    recipients: [input.recipient],
  });
  const trustedSnapshot = verifyTrustedPayrollBookSnapshot(snapshot);
  return {
    ...generated,
    encryptedReport,
    snapshot: trustedSnapshot,
    ...await createFamiliarTaxArtifacts(generated.statement, trustedSnapshot),
  };
}
