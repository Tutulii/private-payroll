"use client";

import {
  ArrowRight,
  Bot,
  CalendarDays,
  Check,
  Copy,
  LoaderCircle,
  LockKeyhole,
  MoreHorizontal,
  Plus,
  ShieldCheck,
  WalletCards,
  Zap,
} from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  loadEncryptedPayAgreements,
  type PayAgreementDirectoryRecord,
} from "@/lib/client/agreement-directory";
import {
  loadEncryptedPayees,
  type PayeeDirectoryRecord,
} from "@/lib/client/payee-directory";
import { formatTokenAmount, type PayrollTokenSymbol } from "@/lib/starknet/tokens";
import { useAppShell } from "./ui/app-shell";
import { usePayoVault } from "./vault/payo-vault";
import { useStarknetWallet } from "./starknet/starknet-wallet";

const memberTones = ["coral", "blue", "yellow", "green"] as const;

function PayrollIllustration() {
  return (
    <div className="payroll-art" aria-hidden="true">
      <span className="art-spark art-spark--one">✦</span><span className="art-spark art-spark--two">✦</span>
      <span className="art-coin art-coin--one">S</span><span className="art-coin art-coin--two">$</span>
      <div className="art-cloud art-cloud--one" /><div className="art-cloud art-cloud--two" />
      <div className="art-card art-card--back"><span className="art-card__line" /><span className="art-card__line art-card__line--short" /></div>
      <div className="art-card art-card--front"><div className="art-card__face"><span className="face-eye" /><span className="face-eye" /><span className="face-smile" /></div><div className="art-card__amount">PAY DAY!</div><div className="art-card__legs"><span /><span /></div></div>
      <div className="art-shield"><ShieldCheck size={30} strokeWidth={2.5} /></div><div className="art-ground" />
    </div>
  );
}

type OverviewActivity = {
  id: string;
  title: string;
  meta: string;
  amount: string;
  icon: typeof ShieldCheck;
  tone: string;
};

export default function OverviewPage() {
  const { openPayroll, notify } = useAppShell();
  const vault = usePayoVault();
  const starknet = useStarknetWallet();
  const [copied, setCopied] = useState(false);
  const [payees, setPayees] = useState<PayeeDirectoryRecord[]>([]);
  const [agreements, setAgreements] = useState<PayAgreementDirectoryRecord[]>([]);
  const [activity, setActivity] = useState<OverviewActivity[]>([]);
  const [loading, setLoading] = useState(false);
  const [overviewError, setOverviewError] = useState("");

  const refreshOverview = useCallback(async () => {
    if (!vault.client || !vault.session) {
      setPayees([]);
      setAgreements([]);
      setActivity([]);
      return;
    }
    setLoading(true);
    setOverviewError("");
    try {
      const [loadedPayees, loadedAgreements, settlementResult, auditResult] = await Promise.all([
        loadEncryptedPayees({ client: vault.client, organizationId: vault.session.organizationId, principal: vault.session.principal }),
        loadEncryptedPayAgreements({ client: vault.client, organizationId: vault.session.organizationId, principal: vault.session.principal }),
        vault.client.listSettlements(vault.session.organizationId, 4),
        vault.client.listAuditEvents(vault.session.organizationId, 8),
      ]);
      setPayees(loadedPayees);
      setAgreements(loadedAgreements);
      const settlementEvents: OverviewActivity[] = settlementResult.settlements.slice(0, 3).map((settlement) => ({
        id: `settlement:${settlement.id}`,
        title: `Private payroll ${settlement.state.replaceAll("_", " ")}`,
        meta: `${settlement.confirmationDepth} confirmation depth · ${new Date(settlement.updatedAt).toLocaleString()}`,
        amount: "Totals encrypted",
        icon: settlement.state === "confirmed" || settlement.state === "finalized" ? Check : LockKeyhole,
        tone: settlement.state === "failed" || settlement.state === "reorged" ? "coral" : "green",
      }));
      const auditEvents: OverviewActivity[] = auditResult.events.slice(0, Math.max(0, 3 - settlementEvents.length)).map((event) => ({
        id: `audit:${event.id}`,
        title: event.action.replaceAll("_", " ").replaceAll(".", " · "),
        meta: `Authorized event · ${new Date(event.createdAt).toLocaleString()}`,
        amount: "Encrypted",
        icon: event.action.startsWith("agent") || event.action.startsWith("capability") ? Bot : ShieldCheck,
        tone: "blue",
      }));
      setActivity([...settlementEvents, ...auditEvents]);
    } catch (error) {
      setOverviewError(error instanceof Error ? error.message : "The private overview could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [vault.client, vault.session]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshOverview(), 0);
    return () => window.clearTimeout(timer);
  }, [refreshOverview]);

  const activeAgreements = useMemo(() => agreements.filter(({ effectiveUntil }) => !effectiveUntil), [agreements]);
  const nextAgreement = useMemo(() => activeAgreements
    .filter(({ agreement }) => agreement.schedule.kind === "recurring")
    .sort((left, right) => {
      const leftDue = left.agreement.schedule.kind === "recurring" ? left.agreement.schedule.nextDueAt : "";
      const rightDue = right.agreement.schedule.kind === "recurring" ? right.agreement.schedule.nextDueAt : "";
      return leftDue.localeCompare(rightDue);
    })[0], [activeAgreements]);
  const dueAt = nextAgreement?.agreement.schedule.kind === "recurring"
    ? new Date(nextAgreement.agreement.schedule.nextDueAt)
    : null;
  const agreementTotals = activeAgreements.reduce<Record<PayrollTokenSymbol, bigint>>((totals, record) => {
    totals[record.agreement.settlementToken] += record.agreement.earningsAtomic
      .reduce((sum, amount) => sum + BigInt(amount), 0n);
    return totals;
  }, { STRK: 0n, USDC: 0n });

  const members = payees.slice(0, 4).map((payee, index) => {
    const agreement = activeAgreements.find(({ payeeId }) => payeeId === payee.id);
    const amount = agreement?.agreement.earningsAtomic.reduce((sum, value) => sum + BigInt(value), 0n);
    return {
      ...payee,
      tone: memberTones[index % memberTones.length],
      initials: payee.displayName.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase(),
      compensation: agreement && amount !== undefined
        ? `${formatTokenAmount(amount, agreement.agreement.settlementToken)} ${agreement.agreement.settlementToken}`
        : "Agreement needed",
    };
  });

  const copyMcp = async () => {
    if (!vault.session) return;
    const command = [
      "PAYO_API_URL=http://localhost:3000 \\",
      "PAYO_API_ACCESS_TOKEN='<short-lived-token>' \\",
      "PAYO_CAPABILITY_ID='<registered-capability-id>' \\",
      "PAYO_CAPABILITY_ISSUER_PUBLIC_KEY='<pinned-ed25519-key>' \\",
      "npm run mcp",
    ].join("\n");
    await navigator.clipboard?.writeText(command);
    setCopied(true);
    notify("Capability-gated MCP template copied");
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="content-grid">
      <section className="hero-card reveal reveal--one">
        <div className="hero-copy">
          <span className="sticker">NEXT PRIVATE OBLIGATION</span>
          <h2>{dueAt ? <>Payday is<br /><span>{dueAt.toLocaleDateString(undefined, { month: "short", day: "numeric" })}.</span></> : <>Your private payroll<br /><span>starts here.</span></>}</h2>
          <p>{activeAgreements.length ? `${activeAgreements.length} locally decrypted active ${activeAgreements.length === 1 ? "agreement" : "agreements"} for ${payees.length} private contributors.` : "Add encrypted contributors and authoritative agreements before preparing the first proof-bound run."}</p>
          <div className="hero-actions"><button type="button" className="button button--ink" onClick={openPayroll}>{activeAgreements.length ? "Prepare payroll" : "Open payroll desk"} <ArrowRight size={18} /></button>{dueAt && <span className="text-button">{dueAt.toLocaleDateString()} <CalendarDays size={16} /></span>}</div>
        </div>
        <PayrollIllustration />
      </section>

      <section className="balance-card reveal reveal--two">
        <div className="card-heading"><div><span className="label">PRIVATE TREASURY</span><h3>{formatTokenAmount(starknet.shieldedBalances.STRK, "STRK")}<span> STRK</span></h3></div><span className="shield-badge"><ShieldCheck size={17} /> {starknet.privacyCapability === "available" ? "Available" : runState(starknet.privacyCapability)}</span></div>
        <div className="balance-meter"><span /></div>
        <div className="balance-meta"><div><span>Native USDC</span><strong>{formatTokenAmount(starknet.shieldedBalances.USDC, "USDC")}</strong></div><div><span>Current agreements</span><strong>{formatTokenAmount(agreementTotals.STRK, "STRK")} STRK · {formatTokenAmount(agreementTotals.USDC, "USDC")} USDC</strong></div></div>
        <Link className="button button--cream button--wide" href="/payroll"><WalletCards size={18} /> Manage private funds</Link>
      </section>

      <section className="panel team-panel reveal reveal--three">
        <div className="panel-title"><div><span className="label">YOUR CREW</span><h3>People &amp; agents</h3></div><Link className="circle-add" aria-label="Add team member" href="/team"><Plus size={19} /></Link></div>
        <div className="team-list">
          {members.map((member) => <Link className="team-row" key={member.id} href="/team"><div className={`avatar avatar--${member.tone}`}>{member.principalKind === "agent" ? <Bot size={18} /> : member.initials}<span className="online-dot" /></div><div className="team-info"><strong>{member.displayName}</strong><span>{member.jurisdictionCode}</span></div><span className={`type-pill ${member.principalKind === "agent" ? "type-pill--agent" : ""}`}>{member.principalKind}</span><strong className="team-amount">{member.compensation}</strong></Link>)}
          {loading && <div className="team-row"><LoaderCircle className="spin" size={18} /><div className="team-info"><strong>Opening encrypted crew</strong><span>Client-side decryption</span></div></div>}
          {!loading && members.length === 0 && <div className="team-row"><LockKeyhole size={18} /><div className="team-info"><strong>No encrypted contributors</strong><span>Add the first person or agent</span></div></div>}
        </div>
        <Link className="panel-link" href="/team">See all {payees.length} teammates <ArrowRight size={16} /></Link>
      </section>

      <section className="panel activity-panel reveal reveal--four">
        <div className="panel-title"><div><span className="label">RECENTLY</span><h3>Private activity</h3></div><Link className="more-button" aria-label="More activity options" href="/activity"><MoreHorizontal size={20} /></Link></div>
        <div className="activity-list">{activity.map(({ id, title, meta, amount, icon: Icon, tone }) => <div className="activity-row" key={id}><div className={`activity-icon activity-icon--${tone}`}><Icon size={17} /></div><div><strong>{title}</strong><span>{meta}</span></div><b>{amount}</b></div>)}{!loading && activity.length === 0 && <div className="activity-row"><div className="activity-icon activity-icon--blue"><LockKeyhole size={17} /></div><div><strong>No durable activity yet</strong><span>Confirmed settlements and vault events appear here.</span></div><b>Encrypted</b></div>}</div>
        <Link className="panel-link" href="/activity">View all activity <ArrowRight size={16} /></Link>
      </section>

      <section className="mcp-card reveal reveal--five">
        <div className="mcp-copy"><div className="mcp-icon"><Bot size={24} /><Zap className="mcp-zap" size={12} /></div><div><span className="label">FOR YOUR AI TEAMMATES</span><h3>Payroll speaks MCP.</h3><p>The copied template requires a registered signed capability and short-lived access token. It grants no generic wallet or calldata access.</p></div></div>
        <div className="terminal-card"><div className="terminal-top"><span /><span /><span /><small>MCP capability template</small></div><code><i>$</i> PAYO_CAPABILITY_ID=...<br /><span>npm run mcp</span></code><button type="button" onClick={copyMcp} aria-label="Copy MCP configuration" disabled={!vault.session}>{copied ? <Check size={16} /> : <Copy size={16} />}</button></div>
      </section>
      {overviewError && <p className="runner-error"><LockKeyhole size={16} /> {overviewError}</p>}
    </div>
  );
}

function runState(value: string) {
  return value.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}
