"use client";

import {
  ArrowRight, WalletCards, CheckCircle2, ChevronDown, Copy, Download, Eye,
  ReceiptText, FileText, LoaderCircle, LockKeyhole, ShieldAlert, ExternalLink,
  ShieldCheck, Users, type LucideIcon,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import type { EncryptedWorkerStatementSource } from "@/lib/disclosure/worker-statement-source";
import type { PayrollReportView } from "@/lib/client/payroll-report-view";
export type { PayrollReportView } from "@/lib/client/payroll-report-view";
import type { PayoReportingIdentity } from "@/lib/crypto/reporting-identity";
import {
  authorityReadinessFilename,
} from "@/lib/disclosure/authority-readiness";
import { PAYROLL_EVIDENCE_COPY } from "@/lib/disclosure/compliance-claims";
import { publicAccountabilityFilename } from "@/lib/disclosure/public-accountability";
import {
  familiarTaxEvidenceFilename,
  type FamiliarTaxDocument,
  type FamiliarTaxRenderIssue,
} from "@/lib/disclosure/tax-evidence";
import type { PayoProofPackageExport, ReadableProofPackageReport } from "@/lib/client/proof-package-files";
import type { LiveProofTransactionEvidence } from "@/lib/client/starknet-proof-evidence";
import { formatTokenAmount } from "@/lib/starknet/tokens";
import { STARKNET_MAINNET_EXPLORER } from "../starknet/starknet-wallet";
import styles from "./report-results.module.css";

export type ResultTone = "employer" | "tax" | "worker" | "claim";
export type ResultStatusTone = "success" | "pending" | "error" | "neutral";
export type WorkerSourceView = {
  file: EncryptedWorkerStatementSource;
  filename: string;
  workerName: string;
  recipientAddress: string;
  identityMode: PayoReportingIdentity["mode"];
  identityFingerprint: string;
  sourceCommitment: string;
};

export type OpenProofPackageResult = {
  report: ReadableProofPackageReport;
  liveEvidence: LiveProofTransactionEvidence;
  grantEvidence: "current" | "embedded";
  filename: string;
};

export type CreatedProofPackageResult = {
  file: PayoProofPackageExport;
  filename: string;
  workflowLabel: string;
};

type DownloadFile = (value: unknown, filename: string) => void;

export function ResultCard({
  audience, title, description, tone, status, statusTone = "success", icon: Icon,
  kind, children,
}: {
  audience: string;
  title: string;
  description: string;
  tone: ResultTone;
  status: string;
  statusTone?: ResultStatusTone;
  icon: LucideIcon;
  kind: string;
  children: ReactNode;
}) {
  const StatusIcon = statusTone === "success" ? CheckCircle2 : statusTone === "error" ? ShieldAlert : FileText;
  return <article className={styles.card} data-tone={tone} data-report-result={kind}>
    <header className={styles.header}>
      <div className={styles.identity}><span className={styles.emblem}><Icon size={22} /></span><span><small>PAYO · PRIVATE RECORD</small><strong>{audience}</strong></span></div>
      <span className={styles.status} data-status={statusTone} role="status"><StatusIcon size={15} />{status}</span>
    </header>
    <div className={styles.intro}><h4>{title}</h4><p>{description}</p></div>
    <div className={styles.body}>{children}</div>
  </article>;
}

export function ResultFacts({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return <dl className={styles.facts}>{items.map(({ label, value }) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>;
}

export function ResultNextStep({ children }: { children: ReactNode }) {
  return <div className={styles.nextStep}><ArrowRight size={18} /><div><strong>Next step</strong><p>{children}</p></div></div>;
}

export function ResultDetails({ children }: { children: ReactNode }) {
  return <details className={styles.details}><summary><span><ShieldCheck size={17} />Verification details</span><ChevronDown size={17} /></summary><div className={styles.detailsBody}>{children}</div></details>;
}

export function ResultActions({ children }: { children: ReactNode }) {
  return <div className={styles.actions}>{children}</div>;
}

export function ResultNote({ children, warning = false }: { children: ReactNode; warning?: boolean }) {
  return <p className={styles.note} data-warning={warning || undefined}>{warning ? <ShieldAlert size={16} /> : <LockKeyhole size={16} />}<span>{children}</span></p>;
}

function TaxEvidenceDocument({ document, download, expanded }: { document: FamiliarTaxDocument; download: DownloadFile; expanded: boolean }) {
  const styleLabel = { w2_style: "W-2-style", p60_style: "P60-style", t4_style: "T4-style" }[document.style];
  return <details className={styles.document} open={expanded || undefined}>
    <summary><FileText size={20} /><span><strong>{document.recipientReference}</strong><small>{styleLabel} evidence · {document.taxYear} · {document.jurisdictionCode} · {document.token}</small></span><ChevronDown size={18} /></summary>
    <div className={styles.documentBody}>
      <h5>{document.title}</h5>
      <dl className={styles.documentFields}>{document.fields.map((field) => <div key={field.code}><dt>{field.label}</dt><dd>{formatTokenAmount(BigInt(field.amountAtomic), document.token)} <small>{document.token}</small></dd></div>)}</dl>
      <p className={styles.caption}>Based on {document.sourceLineCount} verified payroll {document.sourceLineCount === 1 ? "line" : "lines"} for this worker.</p>
      <ResultActions><button type="button" onClick={() => download(document, familiarTaxEvidenceFilename(document))}><Download size={16} />Download readable evidence</button></ResultActions>
      <ResultDetails>
        <ResultFacts items={[
          { label: "Recipient address", value: document.recipientAddress },
          { label: "Policy", value: document.policyBindings.map(({ policyId, policyRevision }) => `${policyId} · revision ${policyRevision}`).join("; ") },
          { label: "On-chain root", value: document.checkpointRoot },
          { label: "Evidence commitment", value: document.documentCommitment },
        ]} />
      </ResultDetails>
    </div>
  </details>;
}

function ReferenceResolutionAction({ issue, busy, resolve }: {
  issue: FamiliarTaxRenderIssue;
  busy: boolean;
  resolve: (issue: FamiliarTaxRenderIssue, canonicalReference: string) => void;
}) {
  const [canonicalReference, setCanonicalReference] = useState(issue.recipientReferences[0] ?? "");
  return <div className={styles.referenceResolution}>
    <label><span>Canonical contributor name</span><select value={canonicalReference} onChange={(event) => setCanonicalReference(event.target.value)} disabled={busy}>
      {issue.recipientReferences.map((reference) => <option value={reference} key={reference}>{reference}</option>)}
    </select></label>
    <p>Confirm this only when every listed name belongs to the same person and wallet. PAYO keeps the old names in encrypted revision history and leaves every confirmed payroll entry unchanged.</p>
    <button type="button" onClick={() => resolve(issue, canonicalReference)} disabled={busy || !canonicalReference}>
      {busy ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />}
      {busy ? "Reconciling encrypted records…" : "Reconcile names & regenerate report"}
    </button>
  </div>;
}

export function PayrollReportResultCard({ view, canReverify, busy, download, reverify, copy, reconcileReference, workerHomeLabel = "Activity" }: {
  view: PayrollReportView;
  canReverify: boolean;
  busy: boolean;
  download: DownloadFile;
  reverify: () => void;
  copy: (commitment: string) => void;
  reconcileReference?: (issue: FamiliarTaxRenderIssue, canonicalReference: string) => void;
  workerHomeLabel?: string;
}) {
  const worker = view.scope === "worker";
  const tax = view.scope === "tax_authority";
  const audience = worker ? "Worker copy" : tax ? "Authorized reviewer copy" : "Employer copy";
  const readiness = view.authorityReadinessEvidence;
  const accountability = view.publicAccountabilitySummary;
  return <ResultCard kind={worker ? "worker-statement" : tax ? "tax-book" : "employer-book"} tone={worker ? "worker" : tax ? "tax" : "employer"}
    audience={audience} title={view.title} status="Verified against payroll book" icon={worker ? Users : tax ? FileText : WalletCards}
    description={worker ? "Your income statement is ready. Your payroll lines were checked against the complete on-chain book; other workers’ pay stays private." : "Every payroll entry for this period matches the on-chain payroll book. This encrypted report contains the complete records for your review."}>
    <ResultFacts items={[
      ...(view.workerName ? [{ label: "Prepared for", value: view.workerName }] : []),
      { label: "Reporting period", value: view.periodLabel },
      { label: "Records checked", value: view.countLabel },
      { label: "Access", value: worker ? "Your income only" : tax ? `Full selected book · ${view.authorizedRecipientCount} independently authorized ${view.authorizedRecipientCount === 1 ? "reviewer" : "reviewers"}` : "Full book · employer" },
    ]} />
    {view.totals.length > 0 && <section className={styles.totals} aria-label="Verified payroll totals">
      <h5>{worker ? "Your verified income" : "Payroll totals"}</h5>
      {view.totals.map((total) => <div className={styles.tokenTotal} key={total.token}>
        <span className={styles.token}>{total.token}</span>
        <dl className={styles.moneyGrid}>
          {total.gross !== undefined && <div><dt>Gross pay</dt><dd>{total.gross}</dd></div>}
          {total.deductions !== undefined && <div><dt>Deductions</dt><dd>{total.deductions}</dd></div>}
          <div className={styles.netTotal}><dt>{worker ? "Net income" : "Net pay"}</dt><dd>{total.net}</dd></div>
        </dl>
      </div>)}
    </section>}
    {tax && <section className={styles.assurance} aria-label="Evidence coverage and limits">
      <div className={styles.sectionHeading}><ShieldCheck size={19} /><div><h5>What this evidence establishes</h5><p>Exact coverage, with its real-world limits kept visible.</p></div></div>
      <div className={styles.assuranceGrid}>
        <div data-established><small>CRYPTOGRAPHICALLY ESTABLISHED</small>
          <p>{PAYROLL_EVIDENCE_COPY.confidentiality}</p>
          <p>{PAYROLL_EVIDENCE_COPY.completeness}</p>
          <p>{PAYROLL_EVIDENCE_COPY.integrity}</p>
        </div>
        <div data-limited><small>OUTSIDE THIS PROOF</small>
          <p>{PAYROLL_EVIDENCE_COPY.sourceTruthLimit}</p>
          <p>{PAYROLL_EVIDENCE_COPY.outsideBookLimit}</p>
          <p>{PAYROLL_EVIDENCE_COPY.reviewerLimit}</p>
        </div>
      </div>
      {readiness && <div className={styles.readiness}>
        <div><span><CheckCircle2 size={16} />Verified evidence</span><strong>Exported — not submitted</strong></div>
        <ResultFacts items={[
          { label: "Complete-book coverage", value: `${readiness.coverage.entryCount} ${readiness.coverage.entryCount === 1 ? "entry" : "entries"} · ${readiness.coverage.lineCount} payroll ${readiness.coverage.lineCount === 1 ? "line" : "lines"}` },
          { label: "Authorized recipients", value: readiness.source.recipients.length },
          { label: "Jurisdiction evidence", value: readiness.reporting.jurisdictionCodes.join(" · ") },
          { label: "Observed block", value: readiness.chainEvidence.blockNumber },
        ]} />
        {canReverify
          ? <ResultActions><button type="button" data-primary onClick={() => download(readiness, authorityReadinessFilename(readiness))}><Download size={17} />Download readiness evidence</button></ResultActions>
          : <ResultNote>The authorized recipient can generate the readable readiness evidence after opening this encrypted report and checking the live book.</ResultNote>}
        {view.authorizedRecipientCount > 1 && <ResultNote warning>{PAYROLL_EVIDENCE_COPY.committeeAccessLimit} {PAYROLL_EVIDENCE_COPY.downloadedAccessLimit}</ResultNote>}
        <ResultNote warning>{PAYROLL_EVIDENCE_COPY.filingLimit}</ResultNote>
      </div>}
      {!readiness && view.familiarTaxIssues.length > 0 && <div className={styles.readiness} data-blocked>
        <div><span><ShieldAlert size={16} />Reviewer book verified</span><strong>Readiness file withheld</strong></div>
        <ResultNote warning>The complete encrypted payroll book was created for the authorized reviewer. PAYO withheld only the authority-readiness evidence because one paid address has conflicting historical contributor references; it did not merge or guess an identity.</ResultNote>
        <ResultFacts items={[
          { label: "Conflicting contributor references", value: view.familiarTaxIssues.map(({ recipientReferences }) => recipientReferences.join(" / ")).join("; ") },
          { label: "Required resolution", value: "Reconcile the historical references before an official-readiness export." },
        ]} />
        {reconcileReference && view.familiarTaxIssues.map((issue) => <ReferenceResolutionAction
          key={`${issue.recipientAddress}:${issue.recipientReferences.join(":")}`}
          issue={issue}
          busy={busy}
          resolve={reconcileReference}
        />)}
      </div>}
      {view.recipientReferenceResolutions.length > 0 && <ResultNote>Historical contributor aliases were reconciled through encrypted, revisioned employer records. The readiness export includes {view.recipientReferenceResolutions.length} reference {view.recipientReferenceResolutions.length === 1 ? "resolution" : "resolutions"}; original payroll commitments remain unchanged.</ResultNote>}
    </section>}
    {!worker && accountability && <section className={styles.accountability} aria-label="DAO public accountability">
      <div className={styles.sectionHeading}><Users size={19} /><div><h5>DAO public accountability</h5><p>Publishable counts and aggregate token totals derived from the verified payroll book.</p></div></div>
      <ResultFacts items={[
        { label: "On-chain root", value: accountability.source.accumulatorRoot },
        { label: "Observed block", value: accountability.source.blockNumber },
        { label: "Privacy", value: "Recipient identities and per-recipient amounts omitted" },
        { label: "Fiat display", value: "Not shown without verified period FX" },
      ]} />
      <div className={styles.quarterGrid}>
        {accountability.quarters.map((quarter) => {
          const status = quarter.aggregateState === "complete_public"
            ? "Complete public aggregate"
            : quarter.aggregateState === "partial_public"
              ? "Public portion only"
              : "Aggregate totals kept private";
          const count = quarter.contributorPayments.coverage === "complete_public"
            ? `${quarter.contributorPayments.value} private contributor ${quarter.contributorPayments.value === 1 ? "payment" : "payments"}`
            : quarter.contributorPayments.coverage === "partial_public"
              ? `${quarter.contributorPayments.value} payment slots disclosed; legacy count unavailable`
              : "Contributor count unavailable for legacy entries";
          return <article className={styles.quarter} key={quarter.quarter}>
            <div className={styles.quarterTop}><div><small>PROOF-BOUND QUARTER</small><h6>{quarter.quarter}</h6></div><span className={styles.aggregateStatus} data-state={quarter.aggregateState}>{status}</span></div>
            <ResultFacts items={[
              { label: "Payroll-book entries", value: quarter.entryCount },
              { label: "Public count", value: count },
            ]} />
            {quarter.publicTotals && <div className={styles.publicMoney}>
              {(["STRK", "USDC"] as const).flatMap((token) => {
                const totals = quarter.publicTotals?.[token];
                if (!totals || BigInt(totals.grossAtomic) === 0n) return [];
                return <div key={token}><span>{token}</span><strong>{formatTokenAmount(BigInt(totals.netAtomic), token)}</strong><small>public net · {formatTokenAmount(BigInt(totals.grossAtomic), token)} gross</small></div>;
              })}
            </div>}
            {quarter.aggregateState === "partial_public" && <ResultNote warning>{quarter.publicEntryCount} public {quarter.publicEntryCount === 1 ? "entry is" : "entries are"} summed above. {quarter.hiddenEntryCount + quarter.legacyEntryCount} private or legacy {quarter.hiddenEntryCount + quarter.legacyEntryCount === 1 ? "entry is" : "entries are"} excluded and never estimated.</ResultNote>}
            {quarter.aggregateState === "hidden" && <div className={styles.hiddenAggregate}><LockKeyhole size={17} /><span><strong>Aggregate totals kept private</strong><small>No hidden amount was derived or guessed.</small></span></div>}
            {quarter.smallCohortWarning && <ResultNote warning>This quarter has fewer than five contributor payments. Publishing an aggregate may still make an individual amount easier to infer.</ResultNote>}
            <details className={styles.accountabilityTrace}><summary>Trace {quarter.entryCount} {quarter.entryCount === 1 ? "entry" : "entries"} on Starknet <ChevronDown size={16} /></summary><div>{quarter.entries.flatMap((entry) => [
              <a key={`proof:${entry.index}`} href={`${STARKNET_MAINNET_EXPLORER}/tx/${entry.integrityVerificationTransactionHash}`} target="_blank" rel="noreferrer">Entry {entry.index + 1} proof <ExternalLink size={13} /></a>,
              <a key={`settlement:${entry.index}`} href={`${STARKNET_MAINNET_EXPLORER}/tx/${entry.settlementTransactionHash}`} target="_blank" rel="noreferrer">Entry {entry.index + 1} settlement <ExternalLink size={13} /></a>,
            ])}</div></details>
          </article>;
        })}
      </div>
      <ResultNote>Counts mean payment slots across proved runs, not unique people. Quarter assignment comes from verified proof-bound due dates; recipient references and addresses are omitted.</ResultNote>
      <ResultActions>
        <button type="button" onClick={() => download(accountability, publicAccountabilityFilename(accountability))}><Download size={17} />Download public accountability evidence</button>
        <button type="button" onClick={() => copy(accountability.summaryCommitment)}><Copy size={15} />Copy summary commitment</button>
      </ResultActions>
    </section>}
    {view.transactionReferences.length > 0 && <section className={styles.transactions} aria-label="Mainnet transaction references">
      <h5>Mainnet references</h5>
      <div>{view.transactionReferences.map(({ kind, hash }, index) => <a key={`${kind}:${hash}`} href={`${STARKNET_MAINNET_EXPLORER}/tx/${hash}`} target="_blank" rel="noreferrer"><span><small>{kind}{view.transactionReferences.length > 2 ? ` ${index + 1}` : ""}</small><strong>{hash}</strong></span><ExternalLink size={15} /></a>)}</div>
    </section>}
    <ResultActions>
      <button type="button" data-primary onClick={() => download(view.file, view.filename)}><Download size={17} />Download encrypted report</button>
      {canReverify && <button type="button" onClick={reverify} disabled={busy}>{busy ? <LoaderCircle className="spin" size={17} /> : <ShieldCheck size={17} />}Check again</button>}
    </ResultActions>
    <ResultNextStep>{worker ? (view.familiarTaxDocuments.length ? "Keep this encrypted report for your records. Use the readable evidence below when you need to share your income with an authorized reviewer." : `Keep this encrypted report for your records. Reopen it in ${workerHomeLabel} whenever you need to check your income.`) : tax ? (canReverify ? "Review the payroll totals and worker evidence below. Save the encrypted report for future reference." : "Send the encrypted report to the named tax reviewer. They can open it from Activity using their own matching PAYO vault.") : "Save the encrypted book for your records. Expand a worker’s evidence below to review their income or download a readable copy."}</ResultNextStep>
    <section className={styles.documents} aria-label="Readable income evidence">
      <div className={styles.sectionHeading}><ReceiptText size={19} /><div><h5>Readable income evidence</h5><p>Individual worker summaries from this verified report.</p></div></div>
      {view.familiarTaxDocuments.length > 0 ? <>
        {view.familiarTaxDocuments.map((document, index) => <TaxEvidenceDocument key={document.documentCommitment} document={document} download={download} expanded={index === 0} />)}
        <ResultNote>Readable downloads contain private compensation data. Share only with the named worker or an authorized reviewer.</ResultNote>
      </> : view.familiarTaxIssues.length > 0
        ? <p className={styles.empty}>Readable tax-style summaries are withheld for an address that appears under multiple contributor references. The complete encrypted payroll book remains verified.</p>
        : <p className={styles.empty}>This report has no employee lines eligible for a W-2-, P60-, or T4-style summary. Your encrypted report is still verified.</p>}
      {view.familiarTaxIssues.length > 0 && <ResultNote warning>{view.familiarTaxIssues.length} recipient {view.familiarTaxIssues.length === 1 ? "address has" : "addresses have"} conflicting historical contributor references: {view.familiarTaxIssues.map(({ recipientReferences }) => recipientReferences.join(" / ")).join("; ")}. PAYO preserved every original line in the verified encrypted book and did not create an ambiguous readable tax summary.</ResultNote>}
      <p className={styles.caption}>{PAYROLL_EVIDENCE_COPY.familiarEvidence} for your records. {PAYROLL_EVIDENCE_COPY.filingLimit}</p>
    </section>
    <ResultDetails>
      <p className={styles.caption}>CHAIN-COMPLETE REPORT VERIFIED · Every disclosed line reconstructs its proved roots; every entry reconstructs the on-chain accumulator.</p>
      <ResultFacts items={[
        { label: "Scope", value: tax ? "authorized tax reviewer" : view.scope }, { label: "Verified at block", value: view.blockNumber },
        { label: "On-chain root", value: view.checkpointRoot }, { label: "Package commitment", value: view.packageCommitment },
        { label: "Encrypted for", value: view.authorizedRecipientCount > 1 ? `${view.authorizedRecipientCount} verified PAYO principals` : view.recipientPrincipalId }, { label: "File", value: view.filename },
      ]} />
      <ResultActions><button type="button" onClick={() => copy(view.packageCommitment)}><Copy size={15} />Copy commitment</button></ResultActions>
    </ResultDetails>
    {!canReverify && <ResultNote>Only the recipient’s matching reporting key can reopen this encrypted file.</ResultNote>}
  </ResultCard>;
}

export function WorkerSourceResultCard({ view, download, copy, openedByWorker = false }: {
  view: WorkerSourceView;
  download: DownloadFile;
  copy: (commitment: string) => void;
  openedByWorker?: boolean;
}) {
  return <ResultCard
    kind="worker-source"
    tone="worker"
    audience={openedByWorker ? "Your worker source" : "For the worker"}
    title={openedByWorker ? "Encrypted source accepted" : "Worker statement source"}
    status={openedByWorker ? "Identity and source verified" : "Encrypted source ready"}
    icon={Users}
    description={openedByWorker
      ? "Your matching identity opened this source locally. PAYO checked its complete-book evidence before creating your final statement."
      : "The complete payroll book has been checked. This file lets the worker create their own private income statement."}
  >
    <ResultFacts items={[
      { label: "Prepared for", value: view.workerName },
      { label: "Who can open it", value: "The worker’s matching PAYO identity" },
      { label: "File contains", value: "Encrypted statement source" },
      { label: "Final statement", value: openedByWorker ? "Generated and verified below" : "Created when the worker opens the file" },
    ]} />
    <ResultActions><button type="button" data-primary onClick={() => download(view.file, view.filename)}><Download size={17} />Download worker source</button></ResultActions>
    <ResultNextStep>{openedByWorker
      ? "Keep the encrypted source if you may need to generate the statement again. Your final encrypted statement is ready below."
      : <>Send this encrypted file to {view.workerName}. In their own vault, they open My Pay → “Open my encrypted statement” to generate their income statement.</>}
    </ResultNextStep>
    <ResultNote>Only the worker’s matching key can open this file. The worker controls creation of the final statement.</ResultNote>
    <ResultDetails><ResultFacts items={[
      { label: "Recipient address", value: view.recipientAddress },
      { label: "Identity method", value: view.identityMode === "direct_strk20_viewing_key" ? "Direct STRK20-derived reporting key" : "Ready PAYO X25519 fallback" },
      { label: "Identity fingerprint", value: view.identityFingerprint },
      { label: "Source commitment", value: view.sourceCommitment },
      { label: "File", value: view.filename },
    ]} /><ResultActions><button type="button" onClick={() => copy(view.sourceCommitment)}><Copy size={15} />Copy commitment</button></ResultActions></ResultDetails>
  </ResultCard>;
}

function audienceLabel(scope: string) {
  return ({ worker: "Worker", employer: "Employer", auditor: "Auditor", tax: "Authorized tax reviewer" } as Record<string, string>)[scope] ?? scope.replaceAll("_", " ");
}

function readableDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));
}

export function CreatedProofResultCard({ result, canOpen, busy, open, download, copy }: {
  result: CreatedProofPackageResult; canOpen: boolean; busy: boolean; open: () => void; download: DownloadFile; copy: (commitment: string) => void;
}) {
  return <ResultCard kind="created-proof" tone="claim" audience={`${audienceLabel(result.file.scope)} copy`} title={result.workflowLabel} status="Encrypted package ready" icon={ReceiptText}
    description="Your evidence package is ready. It is encrypted for the selected recipient and includes the disclosed proof records.">
    <ResultFacts items={[{ label: "Prepared for", value: audienceLabel(result.file.scope) }, { label: "Access expires", value: readableDate(result.file.grant.expiresAt) }]} />
    <ResultActions><button type="button" data-primary onClick={() => download(result.file, result.filename)}><Download size={17} />Download encrypted package</button>{canOpen && <button type="button" onClick={open} disabled={busy}><Eye size={17} />Open package</button>}</ResultActions>
    <ResultNextStep>{canOpen ? "Open this package to review the disclosed information and check its live proof status." : "Send the encrypted file to the selected recipient. They can use “Open proof package” in their own PAYO vault before access expires."}</ResultNextStep>
    <ResultDetails><ResultFacts items={[{ label: "Package commitment", value: result.file.encryptedPackage.packageCommitment }, { label: "File", value: result.filename }]} /><ResultActions><button type="button" onClick={() => copy(result.file.encryptedPackage.packageCommitment)}><Copy size={15} />Copy commitment</button></ResultActions></ResultDetails>
  </ResultCard>;
}

export function OpenProofResultCard({ result, copy }: { result: OpenProofPackageResult; copy: (commitment: string) => void }) {
  const { report, liveEvidence } = result;
  const proofVerified = liveEvidence.status === "confirmed" && liveEvidence.proofStateStatus === "verified";
  const status = proofVerified ? "On-chain proof verified" : liveEvidence.status === "confirmed" ? "Proof transaction confirmed" : liveEvidence.status === "failed" ? "Proof transaction failed" : liveEvidence.status === "pending" ? "Proof transaction pending" : "Live check unavailable";
  const claim = report.workflow !== "payroll";
  return <ResultCard kind="proof-package" tone={claim ? "claim" : "employer"} audience={`${audienceLabel(report.scope)} copy`} title={report.workflowLabel} status={status}
    statusTone={proofVerified ? "success" : liveEvidence.status === "failed" ? "error" : "pending"} icon={claim ? ShieldAlert : ReceiptText}
    description={claim ? "Review the wage issue, the disclosed amount, and the evidence attached to this claim. Proof verification and payment confirmation are tracked separately." : "Your package has been opened locally. Review the disclosed records and the latest available proof status below."}>
    <ResultFacts items={[
      ...(report.claim ? [{ label: "Wage issue", value: report.claim.typeLabel ?? "Private wage exception" }, ...(report.claim.amountLabel ? [{ label: report.workflow === "wage_claim" ? "Claim amount" : "Remediation amount", value: report.claim.amountLabel }] : [])] : []),
      { label: "Shared with", value: audienceLabel(report.scope) }, { label: "Access expires", value: readableDate(report.expiresAt) },
      { label: "Recorded settlement state", value: report.settlementState.replaceAll("_", " ") },
    ]} />
    {!proofVerified && <ResultNote warning>{liveEvidence.status === "confirmed" ? "The transaction is confirmed, but the bound on-chain proof has not been verified. Its verification status remains unconfirmed." : liveEvidence.status === "failed" ? "The proof transaction failed. Ask the issuer for updated evidence before relying on this package." : liveEvidence.status === "pending" ? "The proof transaction is still pending. Check it again after the network confirms it." : "The package opened locally, but the live on-chain check was unavailable. Its on-chain proof status remains unconfirmed."}</ResultNote>}
    <ResultActions><a data-primary href={`${STARKNET_MAINNET_EXPLORER}/tx/${report.verificationTransactionHash}`} target="_blank" rel="noreferrer"><ShieldCheck size={17} />View proof transaction</a></ResultActions>
    <ResultNextStep>{proofVerified ? claim ? "Keep this evidence with the wage claim. Check the claim’s payment status before treating the shortfall as paid." : "Keep this package for your records. Share its contents only within the recipient’s authorized access." : "Review the proof transaction or reopen the package later to repeat the live check."}</ResultNextStep>
    <ResultNote warning={result.grantEvidence !== "current"}>{result.grantEvidence === "current" ? "Access was checked against the issuer’s current grant record." : "This package came from another organization. Expiry and embedded access permission were checked; current revocation and issuer identity require a fresh authenticated record from the issuer."}</ResultNote>
    <ResultDetails>
      <p className={styles.caption}>{report.publicInputsBinding === "verified" ? "Archive integrity, manifest hashes, recipient key, grant window, balanced journal and proof public-input digest verified locally." : "Archive integrity, recipient authorization, grant window and balanced journal verified. This legacy package does not contain a reconstructable proof public-input digest."}</p>
      <ResultFacts items={[
        ...(report.claim ? [{ label: "Claim ID", value: report.claim.id }] : []),
        { label: "Disclosed fields", value: report.fieldScope.join(", ") }, { label: "Proof version", value: report.proofVersion },
        { label: "Verification transaction", value: report.verificationTransactionHash }, { label: "Grant ID", value: report.grantId },
        { label: "Package commitment", value: report.packageCommitment }, { label: "Opened file", value: result.filename },
      ]} />
      <ResultActions><button type="button" onClick={() => copy(report.packageCommitment)}><Copy size={15} />Copy commitment</button></ResultActions>
    </ResultDetails>
  </ResultCard>;
}
