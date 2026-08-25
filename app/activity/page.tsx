"use client";

import {
  Bot,
  Check,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileText,
  Filter,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  ReceiptText,
  Search,
  ShieldCheck,
  Sparkles,
  WalletCards,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useAppShell } from "../ui/app-shell";
import { usePayoVault } from "../vault/payo-vault";
import { STARKNET_MAINNET_EXPLORER } from "../starknet/starknet-wallet";
import { createEncryptedSettlementReceipt } from "@/lib/client/settlement-receipts";
import { createEncryptedDisclosureGrant } from "@/lib/client/disclosure-grants";
import {
  createEncryptedRemediationDraft,
  createEncryptedWageClaimDraft,
  loadEncryptedClaims,
  loadEncryptedRemediations,
  type RemediationRecord,
  type WageClaimRecord,
} from "@/lib/client/claim-workflows";
import {
  loadEncryptedPayAgreements,
  type PayAgreementDirectoryRecord,
} from "@/lib/client/agreement-directory";

type ActivityKind = "Payroll" | "Agent" | "Vault";

type SettlementSummary = {
  id: string;
  runId: string;
  state: string;
  tokenTotalsCommitment: string;
  transactionHash: string | null;
  submittedAt: string | null;
  confirmedAt: string | null;
  finalizedAt: string | null;
  confirmationDepth: number;
  lastErrorCode: string | null;
  createdAt: string;
  updatedAt: string;
};

type AuditSummary = {
  id: string;
  actorId: string;
  action: string;
  subjectId: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
};

type PayrollRunSummary = {
  id: string;
  cycleId: string;
  state: string;
  dueAt: string;
};

type ActivityEvent = {
  id: string;
  day: string;
  title: string;
  detail: string;
  time: string;
  amount: string;
  kind: ActivityKind;
  icon: LucideIcon;
  tone: string;
  hash?: string;
  timestamp: number;
};

const activityFilters = ["All", "Payroll", "Agent", "Vault"] as const;

function dateParts(value: string) {
  const date = new Date(value);
  const today = new Date();
  const isToday = date.toDateString() === today.toDateString();
  return {
    day: isToday ? "Today" : new Intl.DateTimeFormat(undefined, { month: "long", day: "numeric" }).format(date),
    time: new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(date),
    timestamp: date.getTime(),
  };
}

function shortId(value: string | null) {
  return value ? `${value.slice(0, 8)}…${value.slice(-5)}` : "—";
}

function settlementEvent(settlement: SettlementSummary): ActivityEvent {
  const date = dateParts(settlement.updatedAt);
  const confirmed = settlement.state === "confirmed" || settlement.state === "finalized" || settlement.state === "reconciled";
  const delayed = settlement.lastErrorCode === "CONFIRMATION_DELAYED";
  return {
    id: `settlement:${settlement.id}`,
    ...date,
    title: delayed ? "Settlement confirmation delayed" : `Private payroll ${settlement.state.replaceAll("_", " ")}`,
    detail: `Run ${shortId(settlement.runId)} · ${settlement.confirmationDepth} confirmation depth`,
    amount: "Totals encrypted",
    kind: "Payroll",
    icon: confirmed ? CheckCircle2 : LockKeyhole,
    tone: delayed ? "yellow" : confirmed ? "green" : settlement.state === "failed" || settlement.state === "reorged" ? "coral" : "blue",
    hash: settlement.transactionHash ?? undefined,
  };
}

function auditEvent(event: AuditSummary): ActivityEvent {
  const date = dateParts(event.createdAt);
  const agent = event.action.startsWith("capability.") || event.action.startsWith("agent.");
  const payroll = event.action.startsWith("payroll_") || event.action.startsWith("proof_");
  const kind: ActivityKind = agent ? "Agent" : payroll ? "Payroll" : "Vault";
  const actionLabel = event.action.replaceAll("_", " ").replaceAll(".", " · ");
  const transactionHash = typeof event.metadata.transactionHash === "string"
    ? event.metadata.transactionHash
    : undefined;
  return {
    id: `audit:${event.id}`,
    ...date,
    title: actionLabel.charAt(0).toUpperCase() + actionLabel.slice(1),
    detail: `${kind === "Vault" ? "Authorized vault event" : "Authorized operational event"} · ${shortId(event.subjectId)}`,
    amount: kind === "Agent" ? "Policy-scoped" : "Encrypted",
    kind,
    icon: kind === "Agent" ? Bot : kind === "Payroll" ? ShieldCheck : KeyRound,
    tone: kind === "Agent" ? "yellow" : kind === "Payroll" ? "blue" : "coral",
    hash: transactionHash,
  };
}

export default function ActivityPage() {
  const { notify } = useAppShell();
  const vault = usePayoVault();
  const [filter, setFilter] = useState<(typeof activityFilters)[number]>("All");
  const [query, setQuery] = useState("");
  const [copiedHash, setCopiedHash] = useState("");
  const [settlements, setSettlements] = useState<SettlementSummary[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditSummary[]>([]);
  const [receiptCount, setReceiptCount] = useState(0);
  const [agreements, setAgreements] = useState<PayAgreementDirectoryRecord[]>([]);
  const [runs, setRuns] = useState<PayrollRunSummary[]>([]);
  const [claims, setClaims] = useState<WageClaimRecord[]>([]);
  const [remediations, setRemediations] = useState<RemediationRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [creatingReceipt, setCreatingReceipt] = useState(false);
  const [showDisclosure, setShowDisclosure] = useState(false);
  const [disclosureScope, setDisclosureScope] = useState<"auditor" | "tax">("auditor");
  const [granteePrincipalId, setGranteePrincipalId] = useState("");
  const [granteePublicKey, setGranteePublicKey] = useState("");
  const [disclosureExpiry, setDisclosureExpiry] = useState("");
  const [activityError, setActivityError] = useState("");
  const [creatingException, setCreatingException] = useState(false);
  const [showClaimForm, setShowClaimForm] = useState(false);
  const [showRemediationForm, setShowRemediationForm] = useState(false);
  const [claimAgreementId, setClaimAgreementId] = useState("");
  const [claimRunId, setClaimRunId] = useState("");
  const [claimKind, setClaimKind] = useState<WageClaimRecord["claimKind"]>("missing_obligation");
  const [remediationClaimId, setRemediationClaimId] = useState("");

  const refreshActivity = useCallback(async () => {
    if (!vault.client || !vault.session) {
      setSettlements([]);
      setAuditEvents([]);
      setReceiptCount(0);
      setAgreements([]);
      setRuns([]);
      setClaims([]);
      setRemediations([]);
      return;
    }
    setLoading(true);
    setActivityError("");
    try {
      const [settlementResult, auditResult, receiptResult, agreementResult, runResult, claimResult, remediationResult] = await Promise.all([
        vault.client.listSettlements(vault.session.organizationId),
        vault.client.listAuditEvents(vault.session.organizationId),
        vault.client.listEncryptedRecords(vault.session.organizationId, "receipt"),
        loadEncryptedPayAgreements({
          client: vault.client,
          organizationId: vault.session.organizationId,
          principal: vault.session.principal,
        }),
        vault.client.listPayrollRuns(vault.session.organizationId),
        loadEncryptedClaims({
          client: vault.client,
          organizationId: vault.session.organizationId,
          principal: vault.session.principal,
        }),
        loadEncryptedRemediations({
          client: vault.client,
          organizationId: vault.session.organizationId,
          principal: vault.session.principal,
        }),
      ]);
      setSettlements(settlementResult.settlements);
      setAuditEvents(auditResult.events);
      setReceiptCount(receiptResult.records.length);
      setAgreements(agreementResult);
      setRuns(runResult.runs.flatMap((run) => {
        if (
          typeof run.id !== "string"
          || typeof run.cycleId !== "string"
          || typeof run.state !== "string"
          || !(typeof run.dueAt === "string" || run.dueAt instanceof Date)
        ) return [];
        return [{
          id: run.id,
          cycleId: run.cycleId,
          state: run.state,
          dueAt: run.dueAt instanceof Date ? run.dueAt.toISOString() : run.dueAt,
        }];
      }));
      setClaims(claimResult);
      setRemediations(remediationResult);
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : "PAYO activity could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [vault.client, vault.session]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshActivity(), 0);
    return () => window.clearTimeout(timer);
  }, [refreshActivity]);

  const events = useMemo(() => [
    ...settlements.map(settlementEvent),
    ...auditEvents.map(auditEvent),
  ].sort((left, right) => right.timestamp - left.timestamp), [auditEvents, settlements]);

  const visibleEvents = useMemo(() => events.filter((event) => {
    const matchesFilter = filter === "All" || event.kind === filter;
    const matchesQuery = `${event.title} ${event.detail} ${event.amount}`.toLowerCase().includes(query.toLowerCase());
    return matchesFilter && matchesQuery;
  }), [events, filter, query]);

  const groupedEvents = visibleEvents.reduce<Record<string, ActivityEvent[]>>((groups, event) => {
    (groups[event.day] ??= []).push(event);
    return groups;
  }, {});

  const copyHash = async (hash: string) => {
    await navigator.clipboard?.writeText(hash);
    setCopiedHash(hash);
    notify("Transaction hash copied");
    window.setTimeout(() => setCopiedHash(""), 1600);
  };

  const exportOperationalRecord = () => {
    if (!vault.session) return;
    const exportBody = {
      exportVersion: "payo-operational-audit-v1",
      organizationId: vault.session.organizationId,
      generatedAt: new Date().toISOString(),
      privacyNotice: "This export contains operational metadata, not decrypted salaries or recipients.",
      settlements,
      auditEvents,
    };
    const blob = new Blob([`${JSON.stringify(exportBody, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `payo-audit-${vault.session.organizationId}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    notify("Operational audit export downloaded");
  };

  const receiptableSettlement = settlements.find(({ state, transactionHash }) =>
    Boolean(transactionHash) && ["confirmed", "finalized", "reconciled"].includes(state));

  const createReceipt = async () => {
    if (!vault.client || !vault.session || !receiptableSettlement) return;
    setCreatingReceipt(true);
    setActivityError("");
    try {
      const receipt = await createEncryptedSettlementReceipt({
        client: vault.client,
        organizationId: vault.session.organizationId,
        settlementId: receiptableSettlement.id,
        issuerPrincipal: vault.session.principal,
      });
      const exportBody = {
        format: "payo-encrypted-receipt-v1",
        organizationId: vault.session.organizationId,
        receiptId: receipt.record.id,
        packageCommitment: receipt.record.packageCommitment,
        envelope: receipt.envelope,
      };
      const blob = new Blob([`${JSON.stringify(exportBody, null, 2)}\n`], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `payo-encrypted-receipt-${receipt.record.id}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      await refreshActivity();
      notify("Encrypted settlement receipt created");
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : "The encrypted receipt could not be created.");
    } finally {
      setCreatingReceipt(false);
    }
  };

  const createDisclosure = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!vault.client || !vault.session || !receiptableSettlement) return;
    setCreatingReceipt(true);
    setActivityError("");
    try {
      const grantee = { principalId: granteePrincipalId, publicKey: granteePublicKey };
      const receipt = await createEncryptedSettlementReceipt({
        client: vault.client,
        organizationId: vault.session.organizationId,
        settlementId: receiptableSettlement.id,
        issuerPrincipal: vault.session.principal,
        scope: disclosureScope,
        granteePrincipal: grantee,
        granteePrincipalId,
        expiresAt: new Date(disclosureExpiry).toISOString(),
      });
      const grant = await createEncryptedDisclosureGrant({
        client: vault.client,
        organizationId: vault.session.organizationId,
        runId: receiptableSettlement.runId,
        granteePrincipalId,
        granteePublicKey,
        issuerPrincipal: vault.session.principal,
        expiresAt: new Date(disclosureExpiry).toISOString(),
      });
      const exportBody = {
        format: "payo-encrypted-disclosure-v1",
        organizationId: vault.session.organizationId,
        runId: receiptableSettlement.runId,
        scope: disclosureScope,
        receipt: {
          id: receipt.record.id,
          packageCommitment: receipt.record.packageCommitment,
          envelope: receipt.envelope,
        },
        grant: {
          id: grant.record.id,
          expiresAt: grant.record.expiresAt,
          envelope: grant.envelope,
        },
      };
      const blob = new Blob([`${JSON.stringify(exportBody, null, 2)}\n`], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `payo-disclosure-${grant.record.id}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setShowDisclosure(false);
      setGranteePrincipalId("");
      setGranteePublicKey("");
      setDisclosureExpiry("");
      await refreshActivity();
      notify("Recipient-encrypted disclosure created");
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : "The recipient disclosure could not be created.");
    } finally {
      setCreatingReceipt(false);
    }
  };

  const createClaimDraft = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!vault.client || !vault.session) return;
    const agreement = agreements.find(({ agreement }) => agreement.id === claimAgreementId);
    const run = runs.find(({ id }) => id === claimRunId);
    if (!agreement || !run) {
      setActivityError("Choose an agreement and payroll run loaded from this encrypted workspace.");
      return;
    }
    setCreatingException(true);
    setActivityError("");
    try {
      await createEncryptedWageClaimDraft({
        client: vault.client,
        organizationId: vault.session.organizationId,
        agreementId: agreement.agreement.id,
        runId: run.id,
        claimKind,
        principal: vault.session.principal,
      });
      setShowClaimForm(false);
      setClaimAgreementId("");
      setClaimRunId("");
      await refreshActivity();
      notify("Encrypted claim draft stored");
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : "The encrypted claim draft could not be stored.");
    } finally {
      setCreatingException(false);
    }
  };

  const createRemediationDraft = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!vault.client || !vault.session) return;
    const claim = claims.find(({ id }) => id === remediationClaimId);
    if (!claim) {
      setActivityError("Choose a claim loaded from this encrypted workspace.");
      return;
    }
    setCreatingException(true);
    setActivityError("");
    try {
      await createEncryptedRemediationDraft({
        client: vault.client,
        organizationId: vault.session.organizationId,
        claimId: claim.id,
        principal: vault.session.principal,
      });
      setShowRemediationForm(false);
      setRemediationClaimId("");
      await refreshActivity();
      notify("Encrypted remediation draft stored");
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : "The encrypted remediation draft could not be stored.");
    } finally {
      setCreatingException(false);
    }
  };

  const confirmedCount = settlements.filter(({ state }) => ["confirmed", "finalized", "reconciled"].includes(state)).length;
  const agentRequestCount = auditEvents.filter(({ action }) => action.startsWith("capability.") || action.startsWith("agent.")).length;

  return (
    <div className="product-page activity-page-full">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--coral">PRIVATE RECORDS</span>
          <h2>Clear records.<br /><em>Quiet details.</em></h2>
          <p>Track operational evidence and settlement state without putting recipient identities or salaries into PAYO&apos;s server logs.</p>
        </div>
        <div className="page-heading__actions">
          <button type="button" className="button button--soft" onClick={exportOperationalRecord} disabled={!vault.session || loading}><Download size={17} /> Export audit</button>
          <button type="button" className="button button--ink" onClick={() => void refreshActivity()} disabled={!vault.session || loading}>{loading ? <LoaderCircle className="spin" size={17} /> : <ReceiptText size={17} />} Refresh records</button>
        </div>
      </section>

      <section className={`vault-gate reveal reveal--two ${vault.session ? "vault-gate--ready" : ""}`}>
        <span className="vault-gate__icon">{vault.session ? <ShieldCheck size={19} /> : <KeyRound size={19} />}</span>
        <div className="vault-gate__copy"><small>AUTHENTICATED ACTIVITY</small><strong>{vault.session ? `${events.length} durable operational records` : "Workspace locked"}</strong><p>{vault.session ? "Settlement state comes from PostgreSQL confirmation jobs; sensitive payroll payloads remain client-encrypted." : "Unlock the organization before loading its tenant-isolated audit trail."}</p></div>
        {!vault.session && <Link className="button button--ink" href="/payroll">Unlock workspace</Link>}
      </section>

      <section className="visibility-card reveal reveal--two">
        <div className="visibility-art" aria-hidden="true"><div className="visibility-folder"><span>PRIVATE</span><EyeOff size={26} /><i /><i /></div><span className="visibility-key">✦</span><div className="visibility-lock"><LockKeyhole size={22} /></div></div>
        <div className="visibility-copy"><span className="label">YOUR PRIVACY AT A GLANCE</span><h3>The record proves state—not everyone&apos;s salary.</h3><p>PAYO separates durable operational evidence from client-encrypted payroll details, so the activity API cannot render a public salary ledger.</p></div>
        <div className="visibility-legend"><div><span className="visibility-icon visibility-icon--hidden"><EyeOff size={16} /></span><span><small>Client encrypted</small><strong>Recipient · salary · agreement</strong></span></div><div><span className="visibility-icon visibility-icon--visible"><Eye size={16} /></span><span><small>Operational metadata</small><strong>Status · timing · transaction hash</strong></span></div></div>
      </section>

      <section className="activity-kpis reveal reveal--three">
        <article><span className="activity-kpi-icon activity-kpi-icon--green"><CheckCircle2 size={18} /></span><div><small>Confirmed settlements</small><strong>{confirmedCount}</strong><em>Durable confirmation state</em></div></article>
        <article><span className="activity-kpi-icon activity-kpi-icon--blue"><ShieldCheck size={18} /></span><div><small>Settlement records</small><strong>{settlements.length}</strong><em>STRK + native USDC</em></div></article>
        <article><span className="activity-kpi-icon activity-kpi-icon--yellow"><FileText size={18} /></span><div><small>Encrypted receipts</small><strong>{receiptCount}</strong><em>Explicit disclosure only</em></div></article>
        <article><span className="activity-kpi-icon activity-kpi-icon--coral"><Bot size={18} /></span><div><small>Agent policy events</small><strong>{agentRequestCount}</strong><em>Authenticated audit entries</em></div></article>
      </section>

      <div className="activity-layout reveal reveal--four">
        <section className="activity-feed-card">
          <div className="feed-header"><div><span className="label">AUDIT TRAIL</span><h3>Real activity</h3></div><label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search records" aria-label="Search activity" /></label></div>
          <div className="filter-tabs feed-tabs" role="tablist" aria-label="Filter activity">
            {activityFilters.map((item) => <button type="button" role="tab" aria-selected={filter === item} className={filter === item ? "filter-tab filter-tab--active" : "filter-tab"} key={item} onClick={() => setFilter(item)}>{item}</button>)}
            <button type="button" className="feed-filter-more" aria-label="Refresh activity" onClick={() => void refreshActivity()} disabled={!vault.session || loading}><Filter size={14} /> Refresh</button>
          </div>

          {activityError && <p className="team-directory-error"><KeyRound size={15} /> {activityError}</p>}
          <div className="timeline">
            {Object.entries(groupedEvents).map(([day, dayEvents]) => (
              <div className="timeline-day" key={day}>
                <div className="timeline-day__label"><span>{day}</span><i /></div>
                {dayEvents.map((event) => {
                  const Icon = event.icon;
                  return <article className="timeline-event" key={event.id}>
                    <span className={`timeline-icon timeline-icon--${event.tone}`}><Icon size={17} /></span>
                    <div className="timeline-event__main"><strong>{event.title}</strong><span>{event.detail}</span><small>{event.time}</small></div>
                    <div className="timeline-event__value"><strong>{event.amount}</strong><span className={`event-kind event-kind--${event.kind.toLowerCase()}`}>{event.kind}</span></div>
                    {event.hash ? <span className="timeline-hash-actions"><button type="button" className="hash-button" onClick={() => copyHash(event.hash!)}>{copiedHash === event.hash ? <Check size={13} /> : <Copy size={13} />} {shortId(event.hash)}</button><a className="hash-button" href={`${STARKNET_MAINNET_EXPLORER}/tx/${event.hash}`} target="_blank" rel="noreferrer">Explorer</a></span> : <span className="hash-button hash-button--muted"><LockKeyhole size={12} /> Offchain record</span>}
                  </article>;
                })}
              </div>
            ))}
            {loading && events.length === 0 && <div className="directory-empty"><LoaderCircle className="spin" size={24} /><strong>Loading durable records</strong><span>PAYO is reading tenant-scoped operational metadata.</span></div>}
            {!loading && vault.session && visibleEvents.length === 0 && <div className="directory-empty"><Search size={24} /><strong>No records found</strong><span>{events.length ? "Try a different search or filter." : "The first proof or settlement will appear here."}</span></div>}
          </div>
        </section>

        <aside className="activity-side">
          <section className="privacy-score-card">
            <div className="privacy-score-top"><span className="label">DURABILITY COVERAGE</span><Sparkles size={17} /></div>
            <div className="privacy-score-body"><div className="score-ring"><span><strong>{vault.recoveryReady ? "3" : "2"}</strong><small>/ 4</small></span></div><div><h3>{vault.recoveryReady ? "Recovery ready." : "Recovery needed."}</h3><p>Encrypted vault, confirmation jobs, chain indexing, and recovery are tracked separately.</p></div></div>
            <div className="score-checks"><span><Check size={13} /> Client-encrypted records</span><span><Check size={13} /> Durable confirmation jobs</span><span><Check size={13} /> Reorg-aware chain index</span></div>
            <Link className="button button--soft button--wide" href="/payroll"><ShieldCheck size={16} /> Review vault state</Link>
          </section>

          <section className="receipts-card">
            <div className="receipt-doodle" aria-hidden="true"><FileText size={28} /><span>✓</span></div><span className="label">ENCRYPTED RECEIPT</span><h3>Keep the evidence.<br />Hide the payroll.</h3><p>Creates a locally encrypted receipt binding the private token totals to the confirmed Starknet transaction and totals commitment. PAYO stores ciphertext only.</p><button type="button" className="button button--ink button--wide" onClick={() => void createReceipt()} disabled={!vault.session || !receiptableSettlement || creatingReceipt}>{creatingReceipt ? <LoaderCircle className="spin" size={16} /> : <ReceiptText size={16} />} {receiptableSettlement ? "Create encrypted receipt" : "Awaiting confirmed settlement"}</button>
            <button type="button" className="button button--soft button--wide" onClick={() => setShowDisclosure((current) => !current)} disabled={!vault.session || !receiptableSettlement || creatingReceipt}><KeyRound size={16} /> Share encrypted aggregate</button>
            {showDisclosure && <form className="receipt-disclosure-form" onSubmit={createDisclosure}>
              <label><span>Recipient scope</span><select value={disclosureScope} onChange={(event) => setDisclosureScope(event.target.value as typeof disclosureScope)}><option value="auditor">Auditor</option><option value="tax">Tax reviewer</option></select></label>
              <label><span>Recipient principal UUID</span><input value={granteePrincipalId} onChange={(event) => setGranteePrincipalId(event.target.value)} placeholder="UUIDv7" required pattern="[0-9a-fA-F-]{36}" /></label>
              <label><span>Recipient X25519 public key</span><input value={granteePublicKey} onChange={(event) => setGranteePublicKey(event.target.value)} placeholder="Recipient encryption key" required /></label>
              <label><span>Expires</span><input type="datetime-local" value={disclosureExpiry} onChange={(event) => setDisclosureExpiry(event.target.value)} required /></label>
              <p>Only aggregate totals, token selection, and settlement evidence are included. The recipient key never leaves the encrypted grant as plaintext.</p>
              <button type="submit" className="button button--ink button--wide" disabled={creatingReceipt}>{creatingReceipt ? <LoaderCircle className="spin" size={16} /> : <Download size={16} />} Encrypt and download</button>
            </form>}
          </section>

          <section className="receipts-card private-exceptions-card">
            <div className="receipt-doodle receipt-doodle--warning" aria-hidden="true"><FileText size={28} /><span>!</span></div>
            <span className="label">PRIVATE EXCEPTIONS</span>
            <h3>Raise the issue.<br />Keep terms encrypted.</h3>
            <p>Claim and remediation facts are encrypted in this browser. Phase 2 stores drafts only; proof and onchain CLAIM / REMEDIATE transitions remain Phase 3 work.</p>
            <div className="private-exception-counts">
              <span><strong>{claims.length}</strong> claim drafts</span>
              <span><strong>{remediations.length}</strong> remediation drafts</span>
            </div>
            <button type="button" className="button button--ink button--wide" onClick={() => setShowClaimForm((current) => !current)} disabled={!vault.session || creatingException || agreements.length === 0 || runs.length === 0}><FileText size={16} /> Draft private claim</button>
            {showClaimForm && <form className="receipt-disclosure-form" onSubmit={createClaimDraft}>
              <label><span>Committed agreement</span><select value={claimAgreementId} onChange={(event) => setClaimAgreementId(event.target.value)} required><option value="">Choose agreement</option>{agreements.map((agreement) => <option value={agreement.agreement.id} key={agreement.id}>{agreement.agreement.classification} · {shortId(agreement.agreement.id)}</option>)}</select></label>
              <label><span>Payroll run</span><select value={claimRunId} onChange={(event) => setClaimRunId(event.target.value)} required><option value="">Choose run</option>{runs.map((run) => <option value={run.id} key={run.id}>{run.cycleId} · {run.state}</option>)}</select></label>
              <label><span>Claim type</span><select value={claimKind} onChange={(event) => setClaimKind(event.target.value as WageClaimRecord["claimKind"])}><option value="missing_obligation">Missing obligation</option><option value="below_committed_floor">Below committed floor</option><option value="incomplete_final_pay">Incomplete final pay</option></select></label>
              <p>This creates a salted, encrypted draft. It does not assert that a ZK claim proof has been generated or verified.</p>
              <button type="submit" className="button button--ink button--wide" disabled={creatingException}>{creatingException ? <LoaderCircle className="spin" size={16} /> : <LockKeyhole size={16} />} Encrypt claim draft</button>
            </form>}
            <button type="button" className="button button--soft button--wide" onClick={() => setShowRemediationForm((current) => !current)} disabled={!vault.session || creatingException || claims.length === 0}><ShieldCheck size={16} /> Draft remediation</button>
            {showRemediationForm && <form className="receipt-disclosure-form" onSubmit={createRemediationDraft}>
              <label><span>Encrypted claim</span><select value={remediationClaimId} onChange={(event) => setRemediationClaimId(event.target.value)} required><option value="">Choose claim</option>{claims.map((claim) => <option value={claim.id} key={claim.id}>{claim.claimKind.replaceAll("_", " ")} · {shortId(claim.id)}</option>)}</select></label>
              <p>The remediation remains an unproved draft until a settlement and proof bundle are attached in the later proof workflow.</p>
              <button type="submit" className="button button--ink button--wide" disabled={creatingException}>{creatingException ? <LoaderCircle className="spin" size={16} /> : <LockKeyhole size={16} />} Encrypt remediation draft</button>
            </form>}
          </section>

          <section className="pool-status-card"><span className="pool-pulse"><i /></span><div><small>STRK20 pool</small><strong>Mainnet configured</strong></div><WalletCards size={18} /></section>
        </aside>
      </div>
    </div>
  );
}
