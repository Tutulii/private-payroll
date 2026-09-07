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
  renderFamiliarTaxDocumentsWithDiagnostics,
} from "@/lib/disclosure/tax-evidence";
import {
  createEncryptedWorkerStatementSource,
  encryptedWorkerStatementSourceSchema,
  generateWorkerIncomeStatementFromSource,
  openEncryptedWorkerStatementSource,
  type EncryptedWorkerStatementSource,
} from "@/lib/disclosure/worker-statement-source";
import type { PayoReportingIdentity } from "@/lib/crypto/reporting-identity";
import { createAuthorityReadinessEvidence } from "@/lib/disclosure/authority-readiness";
import { createPublicAccountabilitySummary } from "@/lib/disclosure/public-accountability";
import { generateUuidV7 } from "@/lib/domain/records";
import { buildPayrollIntegrityInputsFromSerialized } from "@/lib/proof/input-builder";
import type { PayoClient } from "./payo-client";
import type { PayAgreementDirectoryRecord } from "./agreement-directory";
import type { PayeeDirectoryRecord } from "./payee-directory";
import { parsePayoPublicIdentity, type PayoPublicIdentity } from "./proof-package-files";

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
      ...(payee.recipientReferenceResolution
        ? { recipientReferenceResolution: payee.recipientReferenceResolution }
        : {}),
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
  const rendered = renderFamiliarTaxDocumentsWithDiagnostics(verifiedIncomeEvidence);
  return {
    verifiedIncomeEvidence,
    familiarTaxDocuments: rendered.documents,
    familiarTaxIssues: rendered.issues,
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
  recipientIdentities?: readonly PayoPublicIdentity[];
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
  let encryptedRecipients: VaultPrincipal[] = [input.recipient];
  let recipientIdentities: Array<{ principalId: string; identityFingerprint: string }> | undefined;
  if (input.kind === "tax_book") {
    if (!input.recipientIdentities?.length) {
      throw new Error("An authorized-reviewer report requires at least one verified public identity.");
    }
    if (input.recipientIdentities.length > 8) {
      throw new Error("An authorized-reviewer report supports at most eight verified recipients.");
    }
    const identities = input.recipientIdentities.map((identity) => {
      const parsed = parsePayoPublicIdentity(identity);
      if (parsed.format !== "payo-public-identity-v2") {
        throw new Error("Authorized-reviewer reports require version 2 wallet-bound PAYO identities.");
      }
      return parsed;
    });
    if (new Set(identities.map(({ principalId }) => principalId)).size !== identities.length
      || new Set(identities.map(({ publicKey }) => publicKey)).size !== identities.length
      || new Set(identities.map(({ fingerprint }) => fingerprint.toLowerCase())).size !== identities.length) {
      throw new Error("Authorized-reviewer recipients must use unique principals, encryption keys and fingerprints.");
    }
    const primary = identities[0]!;
    if (primary.principalId !== input.recipient.principalId
      || primary.publicKey !== input.recipient.publicKey) {
      throw new Error("The primary reviewer identity does not match the encrypted report recipient.");
    }
    encryptedRecipients = identities.map(({ principalId, publicKey }) => ({ principalId, publicKey }));
    recipientIdentities = identities.map(({ principalId, fingerprint }) => ({
      principalId,
      identityFingerprint: fingerprint,
    }));
  } else if (input.recipientIdentities?.length) {
    throw new Error("Additional reviewer identities are valid only for an authorized-reviewer report.");
  }
  const completeReport = completePayrollBookReportSchema.parse({
    reportVersion: "payo-private-payroll-report-v1",
    reportType: "complete_payroll_book",
    reportId: generateUuidV7(now.getTime()),
    organizationId: input.organizationId,
    scope: input.kind === "tax_book" ? "tax_authority" : "employer",
    ...(recipientIdentities ? { recipientIdentities } : {}),
    checkpoint: snapshot.checkpoint,
    entries: reportEntries,
    generatedAt: now.toISOString(),
  });
  const completeVerification = await verifyCompletePayrollBookReport({
    report: completeReport,
    trustedSnapshot: snapshot,
  });

  if (input.kind !== "worker_statement") {
    const encryptedReport = encryptPayrollReport({ payload: completeReport, recipients: encryptedRecipients });
    const familiarArtifacts = await createFamiliarTaxArtifacts(completeReport, snapshot);
    const authorityReadinessEvidence = input.kind === "tax_book"
      && familiarArtifacts.familiarTaxIssues.length === 0
      ? await createAuthorityReadinessEvidence({
          report: completeReport,
          trustedSnapshot: snapshot,
          reportCommitment: encryptedReport.packageCommitment,
          recipients: recipientIdentities!,
          generatedAt: now,
        })
      : undefined;
    const publicAccountabilitySummary = await createPublicAccountabilitySummary({
      report: completeReport,
      trustedSnapshot: snapshot,
      reportCommitment: encryptedReport.packageCommitment,
      generatedAt: now,
    });
    return {
      encryptedReport,
      payload: completeReport,
      verification: completeVerification,
      snapshot,
      ...familiarArtifacts,
      authorityReadinessEvidence,
      publicAccountabilitySummary,
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
    publicAccountabilitySummary: undefined,
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
  const familiarArtifacts = await createFamiliarTaxArtifacts(inspection.payload, snapshot);
  const authorityReadinessEvidence = inspection.payload.reportType === "complete_payroll_book"
    && inspection.payload.scope === "tax_authority"
    && inspection.payload.recipientIdentities
    && familiarArtifacts.familiarTaxIssues.length === 0
    ? await createAuthorityReadinessEvidence({
        report: inspection.payload,
        trustedSnapshot: snapshot,
        reportCommitment: encryptedReport.packageCommitment,
        recipients: inspection.payload.recipientIdentities,
      })
    : undefined;
  const publicAccountabilitySummary = inspection.payload.reportType === "complete_payroll_book"
    ? await createPublicAccountabilitySummary({
        report: inspection.payload,
        trustedSnapshot: snapshot,
        reportCommitment: encryptedReport.packageCommitment,
      })
    : undefined;
  return {
    ...inspection,
    snapshot,
    ...familiarArtifacts,
    authorityReadinessEvidence,
    publicAccountabilitySummary,
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
