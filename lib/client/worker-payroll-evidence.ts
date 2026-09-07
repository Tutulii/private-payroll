import type { VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  encryptedPayrollReportSchema,
  type EncryptedPayrollReport,
} from "@/lib/disclosure/payroll-book-report";
import {
  encryptedWorkerStatementSourceSchema,
  type EncryptedWorkerStatementSource,
} from "@/lib/disclosure/worker-statement-source";
import type { PayoClient } from "./payo-client";
import {
  generateWorkerStatementAgainstLiveBook,
  inspectPayrollReportAgainstLiveBook,
  payrollReportFilename,
} from "./payroll-report-workflow";

export type WorkerEvidenceRecipient = {
  principal: VaultPrincipalKeyPair;
  identityFingerprint?: string;
};

type WrappedKey = { principalId: string };

function packageVersion(value: unknown): unknown {
  return value && typeof value === "object" && "packageVersion" in value
    ? value.packageVersion
    : undefined;
}

function selectRecipient(input: {
  recipients: readonly WorkerEvidenceRecipient[];
  wrappedKeys: readonly WrappedKey[];
  identityFingerprint?: string;
}): WorkerEvidenceRecipient {
  const wrappedPrincipalIds = new Set(input.wrappedKeys.map(({ principalId }) => principalId));
  const matches = input.recipients.filter(({ principal }) =>
    wrappedPrincipalIds.has(principal.principalId),
  );
  const fingerprintMatch = input.identityFingerprint
    ? matches.find(({ identityFingerprint }) =>
        identityFingerprint === input.identityFingerprint)
    : undefined;
  const recipient = fingerprintMatch ?? matches[0];
  if (!recipient) {
    throw new Error(
      "This encrypted worker file belongs to another PAYO identity. Open the matching Ready vault or derive the matching direct STRK20 reporting key.",
    );
  }
  return recipient;
}

function parseWorkerSource(value: unknown): EncryptedWorkerStatementSource {
  const parsed = encryptedWorkerStatementSourceSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error("This file is not a valid encrypted PAYO worker statement source.");
  }
  return parsed.data;
}

function parseWorkerReport(value: unknown): EncryptedPayrollReport {
  const parsed = encryptedPayrollReportSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error("Choose an encrypted PAYO worker statement source or worker income statement.");
  }
  if (parsed.data.reportType !== "worker_income_statement") {
    throw new Error(
      "My Pay opens worker evidence only. Employer and reviewer complete payroll books must be opened from Activity.",
    );
  }
  return parsed.data;
}

/**
 * Opens only worker-scoped evidence. Complete employer and reviewer books are
 * rejected from their public package type before any private content is shown.
 * All successful paths independently reread and verify the live payroll book.
 */
export async function openWorkerPayrollEvidenceAgainstLiveBook(input: {
  client: Pick<PayoClient, "getPayrollBookSnapshot">;
  value: unknown;
  sourceFilename: string;
  recipients: readonly WorkerEvidenceRecipient[];
  now?: Date;
}) {
  if (input.recipients.length === 0) {
    throw new Error("Unlock a matching PAYO vault before opening worker evidence.");
  }

  if (packageVersion(input.value) === "payo-encrypted-worker-statement-source-v1") {
    const encryptedSource = parseWorkerSource(input.value);
    const recipient = selectRecipient({
      recipients: input.recipients,
      wrappedKeys: encryptedSource.envelope.wrappedKeys,
      identityFingerprint: encryptedSource.recipientIdentityFingerprint,
    });
    const generated = await generateWorkerStatementAgainstLiveBook({
      client: input.client,
      encryptedSource,
      recipient: recipient.principal,
      now: input.now,
    });
    const reportFilename = payrollReportFilename(generated.encryptedReport, {
      recipientReference: generated.statement.recipientReference,
      year: new Date(
        Number(BigInt(generated.statement.checkpoint.periodStart)) * 1_000,
      ).getUTCFullYear(),
    });
    return {
      kind: "source" as const,
      encryptedSource,
      sourceFilename: input.sourceFilename,
      reportFilename,
      recipientPrincipalId: recipient.principal.principalId,
      statement: generated.statement,
      verification: generated.verification,
      snapshot: generated.snapshot,
      encryptedReport: generated.encryptedReport,
      familiarTaxDocuments: generated.familiarTaxDocuments,
      familiarTaxIssues: generated.familiarTaxIssues,
      recipientIdentity: generated.recipientIdentity,
      sourceCommitment: generated.sourceCommitment,
    };
  }

  const encryptedReport = parseWorkerReport(input.value);
  const recipient = selectRecipient({
    recipients: input.recipients,
    wrappedKeys: encryptedReport.envelope.wrappedKeys,
  });
  const opened = await inspectPayrollReportAgainstLiveBook({
    client: input.client,
    encryptedReport,
    recipient: recipient.principal,
  });
  if (opened.payload.reportType !== "worker_income_statement") {
    throw new Error("The decrypted report is not a worker income statement.");
  }
  return {
    kind: "report" as const,
    encryptedSource: null,
    sourceFilename: null,
    reportFilename: input.sourceFilename,
    recipientPrincipalId: recipient.principal.principalId,
    statement: opened.payload,
    verification: opened.verification,
    snapshot: opened.snapshot,
    encryptedReport,
    familiarTaxDocuments: opened.familiarTaxDocuments,
    familiarTaxIssues: opened.familiarTaxIssues,
    recipientIdentity: null,
    sourceCommitment: null,
  };
}

export type OpenWorkerPayrollEvidenceResult = Awaited<
  ReturnType<typeof openWorkerPayrollEvidenceAgainstLiveBook>
>;
