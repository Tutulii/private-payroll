"use client";

import { useState } from "react";
import {
  PayrollReportResultCard,
  type PayrollReportView,
} from "@/app/activity/report-results";
import type { EncryptedPayrollReport } from "@/lib/disclosure/payroll-book-report";
import type { RecipientReferenceResolution } from "@/lib/domain/records";

const recipientAddress = "0x789";
const historicalReferences = ["Simson", "Vesting canary"];

const initialView: PayrollReportView = {
  file: {} as EncryptedPayrollReport,
  filename: "payo-complete-payroll-book-2026-browser.json",
  recipientPrincipalId: "browser-tax-reviewer",
  organizationId: "018f1000-0000-7000-8000-000000000030",
  authorizedRecipientCount: 1,
  title: "Payroll book for tax review",
  scope: "tax_authority",
  countLabel: "1 payroll entry · complete book",
  totals: [{ token: "USDC", gross: "0.2", deductions: "0.044", net: "0.156" }],
  periodLabel: "2026 · 1/1/2026 – 12/31/2026",
  checkpointRoot: `0x${"1".repeat(64)}`,
  blockNumber: "1234567",
  packageCommitment: `0x${"2".repeat(64)}`,
  transactionReferences: [],
  familiarTaxDocuments: [],
  familiarTaxIssues: [{
    code: "conflicting_recipient_references",
    recipientAddress,
    jurisdictionCode: "US",
    token: "USDC",
    recipientReferences: historicalReferences,
  }],
  recipientReferenceResolutions: [],
};

export default function ReferenceReconciliationBrowserEvidencePage() {
  const [view, setView] = useState(initialView);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState("Awaiting reconciliation");

  const reconcile = (_issue: PayrollReportView["familiarTaxIssues"][number], canonicalReference: string) => {
    setBusy(true);
    window.setTimeout(() => {
      const resolution: RecipientReferenceResolution = {
        resolutionVersion: "payo-recipient-reference-resolution-v1",
        resolutionId: "01991f00-2000-7000-8000-000000000005",
        recipientAddress,
        canonicalReference,
        historicalReferences,
        resolvedAt: "2026-09-07T03:00:00.000Z",
      };
      setView((current) => ({
        ...current,
        familiarTaxIssues: [],
        recipientReferenceResolutions: [resolution],
      }));
      setResult(`Regenerated with ${canonicalReference}`);
      setBusy(false);
    }, 25);
  };

  return <main>
    <PayrollReportResultCard
      view={view}
      canReverify
      busy={busy}
      download={() => undefined}
      reverify={() => undefined}
      copy={() => undefined}
      reconcileReference={reconcile}
    />
    <output aria-live="polite">{result}</output>
  </main>;
}
