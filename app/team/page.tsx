"use client";

import {
  Bot,
  Check,
  Copy,
  KeyRound,
  LoaderCircle,
  MoreHorizontal,
  Plus,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  UserPlus,
  WalletCards,
  Zap,
} from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useAppShell } from "../ui/app-shell";
import { usePayoVault } from "../vault/payo-vault";
import {
  loadEncryptedPayees,
  storeEncryptedPayee,
  type PayeeDirectoryRecord,
} from "@/lib/client/payee-directory";
import {
  loadEncryptedPayAgreements,
  storeEncryptedRecurringAgreement,
  type PayAgreementDirectoryRecord,
} from "@/lib/client/agreement-directory";
import { formatTokenAmount, type PayrollTokenSymbol } from "@/lib/starknet/tokens";
import {
  completeEncryptedPrincipalDirectory,
  loadEncryptedPrincipals,
  type PrincipalDirectoryRecord,
} from "@/lib/client/principal-directory";
import {
  issueEncryptedAgentCapability,
  loadEncryptedAgentCapabilities,
  revokeEncryptedAgentCapability,
  type AgentCapabilityDirectoryRecord,
} from "@/lib/client/agent-capabilities";

const teamFilters = ["Everyone", "Humans", "Agents"] as const;
const memberTones = ["coral", "blue", "green", "yellow"] as const;

function localDateTimeInputValue(value: Date): string {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16);
}

export default function TeamPage() {
  const { notify } = useAppShell();
  const vault = usePayoVault();
  const [filter, setFilter] = useState<(typeof teamFilters)[number]>("Everyone");
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const [payees, setPayees] = useState<PayeeDirectoryRecord[]>([]);
  const [agreements, setAgreements] = useState<PayAgreementDirectoryRecord[]>([]);
  const [principals, setPrincipals] = useState<PrincipalDirectoryRecord[]>([]);
  const [capabilities, setCapabilities] = useState<AgentCapabilityDirectoryRecord[]>([]);
  const [directoryLoading, setDirectoryLoading] = useState(false);
  const [directoryError, setDirectoryError] = useState("");
  const [showAddPayee, setShowAddPayee] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [recipientAddress, setRecipientAddress] = useState("");
  const [principalKind, setPrincipalKind] = useState<"human" | "agent">("human");
  const [tokenPreference, setTokenPreference] = useState<PayrollTokenSymbol>("STRK");
  const [jurisdictionCode, setJurisdictionCode] = useState("US");
  const [showAddAgreement, setShowAddAgreement] = useState(false);
  const [agreementPayeeId, setAgreementPayeeId] = useState("");
  const [agreementAmount, setAgreementAmount] = useState("");
  const [agreementClassification, setAgreementClassification] = useState<"employee" | "contractor" | "agent_service">("contractor");
  const [agreementCadence, setAgreementCadence] = useState<"weekly" | "biweekly" | "monthly">("monthly");
  const [agreementNextDueAt, setAgreementNextDueAt] = useState("");
  const [policyId, setPolicyId] = useState("payo-net-invoice-no-withholding-v1");
  const [directoryLoadedAt] = useState(() => Date.now());

  const refreshPayees = useCallback(async () => {
    if (!vault.client || !vault.session) {
      setPayees([]);
      setPrincipals([]);
      setCapabilities([]);
      return;
    }
    setDirectoryLoading(true);
    setDirectoryError("");
    try {
      const [loadedPayees, loadedAgreements, loadedPrincipals, loadedCapabilities] = await Promise.all([
        loadEncryptedPayees({
          client: vault.client,
          organizationId: vault.session.organizationId,
          principal: vault.session.principal,
        }),
        loadEncryptedPayAgreements({
          client: vault.client,
          organizationId: vault.session.organizationId,
          principal: vault.session.principal,
        }),
        loadEncryptedPrincipals({
          client: vault.client,
          organizationId: vault.session.organizationId,
          principal: vault.session.principal,
        }),
        loadEncryptedAgentCapabilities({
          client: vault.client,
          organizationId: vault.session.organizationId,
          principal: vault.session.principal,
        }),
      ]);
      setPayees(loadedPayees);
      setAgreements(loadedAgreements);
      setPrincipals(loadedPrincipals);
      setCapabilities(loadedCapabilities);
    } catch (error) {
      setDirectoryError(error instanceof Error ? error.message : "The encrypted directory could not be opened.");
    } finally {
      setDirectoryLoading(false);
    }
  }, [vault.client, vault.session]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshPayees(), 0);
    return () => window.clearTimeout(timer);
  }, [refreshPayees]);

  const members = useMemo(() => payees.map((payee, index) => {
    const agreement = agreements
      .filter((candidate) => candidate.payeeId === payee.id && !candidate.effectiveUntil)
      .sort((left, right) => right.revision - left.revision)[0];
    const earnings = agreement?.agreement.earningsAtomic.reduce((total, amount) => total + BigInt(amount), 0n);
    const cadence = agreement?.agreement.schedule.kind === "recurring"
      ? agreement.agreement.schedule.cadence
      : agreement?.agreement.schedule.kind ?? "No agreement";
    return {
      id: payee.id,
      payee,
      name: payee.displayName,
      role: payee.principalKind === "agent" ? "AI agent" : "Human contributor",
      kind: payee.principalKind === "agent" ? "Agent" as const : "Human" as const,
      amount: earnings === undefined
        ? `Not configured · ${payee.tokenPreference}`
        : `${formatTokenAmount(earnings, agreement.agreement.settlementToken)} ${agreement.agreement.settlementToken}`,
      cadence,
      initials: payee.displayName.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase(),
      tone: memberTones[index % memberTones.length],
      ready: payee.status === "active" && Boolean(agreement),
      agreement,
      activeCapability: capabilities.find((capability) =>
        capability.principalId === payee.principalId && !capability.revokedAt),
    };
  }), [agreements, capabilities, payees]);

  const visibleMembers = useMemo(() => {
    return members.filter((member) => {
      const matchesKind = filter === "Everyone" || (filter === "Humans" && member.kind === "Human") || (filter === "Agents" && member.kind === "Agent");
      const matchesQuery = `${member.name} ${member.role}`.toLowerCase().includes(query.toLowerCase());
      return matchesKind && matchesQuery;
    });
  }, [filter, members, query]);

  const humanCount = members.filter(({ kind }) => kind === "Human").length;
  const agentCount = members.length - humanCount;
  const missingPrincipalCount = (vault.session && !principals.some(({ vaultPrincipalId }) =>
    vaultPrincipalId === vault.session!.principal.principalId) ? 1 : 0)
    + payees.filter((payee) => !principals.some(({ id }) => id === payee.principalId)).length;

  const addPayee = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!vault.client || !vault.session) {
      setDirectoryError("Unlock the encrypted workspace before adding a contributor.");
      return;
    }
    setDirectoryLoading(true);
    setDirectoryError("");
    try {
      await storeEncryptedPayee({
        client: vault.client,
        organizationId: vault.session.organizationId,
        displayName,
        principalKind,
        recipientAddress,
        tokenPreference,
        jurisdictionCode,
        principal: vault.session.principal,
      });
      setDisplayName("");
      setRecipientAddress("");
      setShowAddPayee(false);
      await refreshPayees();
      notify("Encrypted contributor added");
    } catch (error) {
      setDirectoryError(error instanceof Error ? error.message : "The contributor could not be encrypted.");
    } finally {
      setDirectoryLoading(false);
    }
  };

  const openAgreementForm = (payee: PayeeDirectoryRecord) => {
    setAgreementPayeeId(payee.id);
    setAgreementClassification(payee.principalKind === "agent" ? "agent_service" : "contractor");
    setAgreementAmount("");
    setAgreementNextDueAt(localDateTimeInputValue(new Date(directoryLoadedAt - 60_000)));
    setShowAddAgreement(true);
  };

  const addAgreement = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!vault.client || !vault.session) {
      setDirectoryError("Unlock the encrypted workspace before adding an agreement.");
      return;
    }
    const payee = payees.find(({ id }) => id === agreementPayeeId);
    if (!payee) {
      setDirectoryError("Select an existing encrypted contributor.");
      return;
    }
    setDirectoryLoading(true);
    setDirectoryError("");
    try {
      await storeEncryptedRecurringAgreement({
        client: vault.client,
        organizationId: vault.session.organizationId,
        payee,
        amount: agreementAmount,
        token: payee.tokenPreference,
        classification: agreementClassification,
        cadence: agreementCadence,
        nextDueAt: new Date(agreementNextDueAt).toISOString(),
        policyId,
        policyVersion: 1,
        principal: vault.session.principal,
      });
      setShowAddAgreement(false);
      setAgreementNextDueAt("");
      await refreshPayees();
      notify("Encrypted pay agreement added · return to Payroll to authorize and send");
    } catch (error) {
      setDirectoryError(error instanceof Error ? error.message : "The agreement could not be encrypted.");
    } finally {
      setDirectoryLoading(false);
    }
  };

  const copyToken = async () => {
    if (!vault.session) {
      setDirectoryError("Unlock the workspace before creating an organization-scoped MCP connection.");
      return;
    }
    await navigator.clipboard?.writeText(`payo://mcp/${vault.session.organizationId}/connect`);
    setCopied(true);
    notify("Agent connection copied");
    window.setTimeout(() => setCopied(false), 1800);
  };

  const completePrincipalDirectory = async () => {
    if (!vault.client || !vault.session) return;
    setDirectoryLoading(true);
    setDirectoryError("");
    try {
      const created = await completeEncryptedPrincipalDirectory({
        client: vault.client,
        organizationId: vault.session.organizationId,
        vaultPrincipal: vault.session.principal,
        existingPrincipals: principals,
        payees,
      });
      await refreshPayees();
      notify(`${created.length} encrypted ${created.length === 1 ? "identity" : "identities"} completed`);
    } catch (error) {
      setDirectoryError(error instanceof Error ? error.message : "The encrypted principal directory could not be completed.");
    } finally {
      setDirectoryLoading(false);
    }
  };

  const issueAgentCapability = async (payee: PayeeDirectoryRecord) => {
    if (!vault.client || !vault.session) return;
    const agreement = agreements
      .filter((candidate) => candidate.payeeId === payee.id && !candidate.effectiveUntil)
      .sort((left, right) => right.revision - left.revision)[0];
    if (!agreement) {
      setDirectoryError("Add an active encrypted agreement before issuing an agent capability.");
      return;
    }
    if (capabilities.some((capability) => capability.principalId === payee.principalId && !capability.revokedAt)) {
      setDirectoryError("Revoke the current capability before issuing a replacement.");
      return;
    }
    setDirectoryLoading(true);
    setDirectoryError("");
    try {
      const maxPerPayment = agreement.agreement.earningsAtomic.reduce((total, value) => total + BigInt(value), 0n);
      const periodMultiplier = agreement.agreement.schedule.kind === "recurring"
        ? agreement.agreement.schedule.cadence === "weekly" ? 5n : agreement.agreement.schedule.cadence === "biweekly" ? 3n : 1n
        : 1n;
      const expiresAt = new Date(Date.now() + 31 * 24 * 60 * 60 * 1_000);
      await issueEncryptedAgentCapability({
        client: vault.client,
        organizationId: vault.session.organizationId,
        organizationSecret: vault.session.organizationSecret,
        principalId: payee.principalId,
        recipientAddresses: [payee.recipientAddress],
        limits: [{
          token: agreement.agreement.settlementToken,
          maxPerPaymentAtomic: maxPerPayment.toString(),
          maxPerPeriodAtomic: (maxPerPayment * periodMultiplier).toString(),
          approvalThresholdAtomic: maxPerPayment.toString(),
        }],
        vaultPrincipal: vault.session.principal,
        expiresAt,
      });
      await refreshPayees();
      notify("Encrypted approval capability issued");
    } catch (error) {
      setDirectoryError(error instanceof Error ? error.message : "The agent capability could not be issued.");
    } finally {
      setDirectoryLoading(false);
    }
  };

  const revokeAgentCapability = async (record: AgentCapabilityDirectoryRecord) => {
    if (!vault.client || !vault.session) return;
    setDirectoryLoading(true);
    setDirectoryError("");
    try {
      await revokeEncryptedAgentCapability({
        client: vault.client,
        record,
        principal: vault.session.principal,
      });
      await refreshPayees();
      notify("Agent capability revoked");
    } catch (error) {
      setDirectoryError(error instanceof Error ? error.message : "The agent capability could not be revoked.");
    } finally {
      setDirectoryLoading(false);
    }
  };

  return (
    <div className="product-page team-page">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--green">ONE TEAM</span>
          <h2>People and agents,<br /><em>paid together.</em></h2>
          <p>Set compensation, private payout identities, and clear permissions for every kind of contributor.</p>
        </div>
        <div className="page-heading__actions">
          {members.some(({ ready }) => ready) && <Link className="button button--soft" href="/payroll#private-payroll">Review payroll <span aria-hidden="true">→</span></Link>}
          {missingPrincipalCount > 0 && <button type="button" className="button button--soft" onClick={() => void completePrincipalDirectory()} disabled={!vault.session || directoryLoading}><KeyRound size={17} /> Complete {missingPrincipalCount} {missingPrincipalCount === 1 ? "identity" : "identities"}</button>}
          <button type="button" className="button button--soft" onClick={() => void refreshPayees()} disabled={!vault.session || directoryLoading}>{directoryLoading ? <LoaderCircle className="spin" size={17} /> : <Sparkles size={17} />} Refresh vault</button>
          <button type="button" className="button button--ink" onClick={() => setShowAddPayee(true)} disabled={!vault.session}><UserPlus size={17} /> Add contributor</button>
        </div>
      </section>

      <section className={`vault-gate reveal reveal--two ${vault.session ? "vault-gate--ready" : ""}`}>
        <span className="vault-gate__icon">{vault.session ? <ShieldCheck size={19} /> : <KeyRound size={19} />}</span>
        <div className="vault-gate__copy">
          <small>ENCRYPTED DIRECTORY</small>
          <strong>{vault.session ? `${principals.length} principal records · ${members.length} payout profiles` : "Workspace locked"}</strong>
          <p>{vault.session ? "Principal access state, names, payout addresses, token preferences, and jurisdictions are decrypted only in this browser." : "Unlock the organization vault before PAYO can read or add private contributors."}</p>
        </div>
        {!vault.session && <Link className="button button--ink" href="/payroll">Unlock workspace</Link>}
      </section>

      <section className="team-story-card reveal reveal--two">
        <div className="team-story__copy">
          <span className="label">TEAM SNAPSHOT</span>
          <h3>{members.length} {members.length === 1 ? "contributor" : "contributors"}.<br />One private payday.</h3>
          <p>People receive salaries. Agents receive operating budgets. Payo gives both a private balance without exposing their activity to the rest of the team.</p>
          <div className="team-story__legend"><span><i className="legend-human" />{humanCount} humans</span><span><i className="legend-agent" />{agentCount} agents</span></div>
        </div>

        <div className="crew-art" aria-hidden="true">
          <span className="crew-spark crew-spark--one">✦</span><span className="crew-spark crew-spark--two">✦</span>
          <div className="crew-person">
            <div className="crew-head"><i /><i /><b /></div>
            <div className="crew-body">HUMAN</div>
            <span className="crew-arm crew-arm--right" />
            <span className="crew-leg crew-leg--one" /><span className="crew-leg crew-leg--two" />
          </div>
          <div className="crew-link"><span>+ PAY</span></div>
          <div className="crew-bot">
            <span className="crew-antenna" />
            <div className="crew-bot__screen"><i /><i /><b /></div>
            <strong>AGENT</strong>
            <span className="crew-arm crew-arm--left" />
            <span className="crew-leg crew-leg--one" /><span className="crew-leg crew-leg--two" />
          </div>
        </div>

        <div className="team-story__stats">
          <div><span>Private identities</span><strong>{members.length}</strong></div>
          <div><span>Privacy-ready</span><strong>{members.filter(({ ready }) => ready).length} <small>/ {members.length}</small></strong></div>
          <div><span>AI agents</span><strong>{agentCount}</strong></div>
        </div>
      </section>

      <section className="directory-section reveal reveal--three" id="team-directory">
        <div className="directory-top">
          <div><span className="label">DIRECTORY</span><h3>Meet the crew</h3></div>
          <div className="directory-tools">
            <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search the crew" aria-label="Search team" /></label>
            <button type="button" className="square-tool" aria-label="Directory filters" onClick={() => notify("More filters coming soon")}><SlidersHorizontal size={17} /></button>
          </div>
        </div>
        <div className="filter-tabs team-tabs" role="tablist" aria-label="Filter team">
          {teamFilters.map((item) => (
            <button type="button" role="tab" aria-selected={filter === item} className={filter === item ? "filter-tab filter-tab--active" : "filter-tab"} key={item} onClick={() => setFilter(item)}>
              {item} <span>{item === "Everyone" ? members.length : item === "Humans" ? humanCount : agentCount}</span>
            </button>
          ))}
        </div>

        {showAddPayee && (
          <form className="team-add-form" onSubmit={addPayee}>
            <div className="team-add-form__heading"><span><small>CLIENT-ENCRYPTED RECORD</small><strong>Add a private contributor</strong></span><button type="button" onClick={() => setShowAddPayee(false)} aria-label="Close contributor form">×</button></div>
            <label><span>Display name</span><input value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="Maya or Scout" required maxLength={160} /></label>
            <label><span>Kind</span><select value={principalKind} onChange={(event) => setPrincipalKind(event.target.value as "human" | "agent")}><option value="human">Human</option><option value="agent">AI agent</option></select></label>
            <label className="team-add-form__address"><span>Registered Starknet address</span><input value={recipientAddress} onChange={(event) => setRecipientAddress(event.target.value)} placeholder="0x…" required /></label>
            <label><span>Private token</span><select value={tokenPreference} onChange={(event) => setTokenPreference(event.target.value as PayrollTokenSymbol)}><option value="STRK">STRK</option><option value="USDC">USDC</option></select></label>
            <label><span>Jurisdiction</span><input value={jurisdictionCode} onChange={(event) => setJurisdictionCode(event.target.value)} placeholder="US-CA or GB" required maxLength={6} /></label>
            <button className="button button--ink" type="submit" disabled={directoryLoading}>{directoryLoading ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />} Encrypt contributor</button>
          </form>
        )}
        {showAddAgreement && (
          <form className="team-add-form" onSubmit={addAgreement}>
            <div className="team-add-form__heading"><span><small>AUTHORITATIVE ENCRYPTED TERMS</small><strong>Add recurring pay agreement</strong></span><button type="button" onClick={() => setShowAddAgreement(false)} aria-label="Close agreement form">×</button></div>
            <label><span>Contributor</span><select value={agreementPayeeId} onChange={(event) => {
              const payee = payees.find(({ id }) => id === event.target.value);
              setAgreementPayeeId(event.target.value);
              if (payee) setAgreementClassification(payee.principalKind === "agent" ? "agent_service" : "contractor");
            }}>{payees.map((payee) => <option value={payee.id} key={payee.id}>{payee.displayName}</option>)}</select></label>
            <label><span>Private amount</span><input value={agreementAmount} onChange={(event) => setAgreementAmount(event.target.value)} inputMode="decimal" placeholder="1250.00" required /></label>
            <label><span>Classification</span><select value={agreementClassification} onChange={(event) => setAgreementClassification(event.target.value as typeof agreementClassification)}><option value="contractor">Contractor</option><option value="agent_service">Agent service</option></select></label>
            <label><span>Cadence</span><select value={agreementCadence} onChange={(event) => setAgreementCadence(event.target.value as typeof agreementCadence)}><option value="weekly">Weekly</option><option value="biweekly">Biweekly</option><option value="monthly">Monthly</option></select></label>
            <label><span>First payment due</span><input type="datetime-local" value={agreementNextDueAt} onChange={(event) => setAgreementNextDueAt(event.target.value)} required /><small>Defaults to now so the first payroll can be sent immediately.</small></label>
            <label className="team-add-form__address"><span>Policy profile</span><input value={policyId} onChange={(event) => setPolicyId(event.target.value)} required maxLength={160} readOnly /><small>The proof catalog root is derived locally from this version-pinned policy, never pasted into the agreement.</small></label>
            <button className="button button--ink" type="submit" disabled={directoryLoading}>{directoryLoading ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />} Encrypt agreement</button>
          </form>
        )}
        {directoryError && <p className="team-directory-error"><KeyRound size={15} /> {directoryError}</p>}

        <div className="member-grid">
          {visibleMembers.map((member) => (
            <article className="member-card" key={member.id}>
              <button type="button" className="member-more" aria-label={`Encrypted record for ${member.name}`} title="Encrypted vault record"><MoreHorizontal size={18} /></button>
              <div className={`member-avatar avatar--${member.tone}`}>
                {member.kind === "Agent" ? <Bot size={24} /> : member.initials}
                <span className={member.ready ? "member-status" : "member-status member-status--pending"} />
              </div>
              <div className="member-name"><h4>{member.name}</h4><span className={member.kind === "Agent" ? "kind-tag kind-tag--agent" : "kind-tag"}>{member.kind}</span></div>
              <p>{member.role}</p>
              <div className="member-pay"><span><small>Compensation</small><strong>{member.amount}</strong></span><em>{member.cadence}</em></div>
              <button type="button" className="member-open" onClick={() => openAgreementForm(member.payee)}>{member.ready ? "Update encrypted agreement" : "Add encrypted agreement"} <span>→</span></button>
              {member.kind === "Agent" && member.ready && (
                member.activeCapability
                  ? <button type="button" className="member-open member-open--capability" onClick={() => void revokeAgentCapability(member.activeCapability!)} disabled={directoryLoading}>Revoke approval capability <span>×</span></button>
                  : <button type="button" className="member-open member-open--capability" onClick={() => void issueAgentCapability(member.payee)} disabled={directoryLoading}>Issue approval capability <span>+</span></button>
              )}
            </article>
          ))}
          <button type="button" className="member-card member-card--add" onClick={() => setShowAddPayee(true)} disabled={!vault.session}>
            <span><Plus size={22} /></span><strong>Add someone new</strong><small>Human or AI agent</small>
          </button>
        </div>
        {directoryLoading && members.length === 0 && <div className="directory-empty"><LoaderCircle className="spin" size={24} /><strong>Opening encrypted directory</strong><span>Only ciphertext is being loaded from PAYO.</span></div>}
        {!directoryLoading && vault.session && visibleMembers.length === 0 && <div className="directory-empty"><Search size={24} /><strong>No contributors found</strong><span>{members.length ? "Try another name or filter." : "Add the first encrypted human or AI-agent payout identity."}</span></div>}
      </section>

      <section className="agent-access-card reveal reveal--four">
        <div className="agent-access__intro">
          <div className="agent-access__icon"><Bot size={25} /><Zap size={12} /></div>
          <div><span className="label">MCP ACCESS</span><h3>Give agents a key—not the keys.</h3><p>Agents can prepare work within precise limits. Human approval still controls every private payroll execution.</p></div>
        </div>
        <div className="scope-list">
          <span><Check size={13} /> Read treasury balance</span>
          <span><Check size={13} /> Prepare payroll draft</span>
          <span><Check size={13} /> Request payment</span>
          <span className="scope-off"><KeyRound size={13} /> Execute payment</span>
        </div>
        <div className="agent-connect">
          <div><WalletCards size={16} /><span><small>Organization-scoped connection</small><strong>{vault.session ? `payo://mcp/${vault.session.organizationId.slice(0, 8)}…` : "Unlock to create"}</strong></span></div>
          <button type="button" onClick={copyToken} aria-label="Copy agent connection" disabled={!vault.session}>{copied ? <Check size={16} /> : <Copy size={16} />}</button>
        </div>
        <div className="access-footnote"><ShieldCheck size={16} /> {capabilities.filter(({ revokedAt }) => !revokedAt).length} active encrypted {capabilities.filter(({ revokedAt }) => !revokedAt).length === 1 ? "capability" : "capabilities"} · human approval remains mandatory <Sparkles size={14} /></div>
        {capabilities.length > 0 && (
          <div className="agent-capability-list">
            {capabilities.map((record) => {
              const payee = payees.find(({ principalId }) => principalId === record.principalId);
              const policy = record.signedCapability.capability;
              return (
                <div className="agent-capability-row" key={record.id}>
                  <span><small>{record.revokedAt ? "REVOKED" : "APPROVAL REQUIRED"}</small><strong>{payee?.displayName ?? "Encrypted agent"}</strong></span>
                  <span><small>LIMITS</small><strong>{policy.limits.map((limit) => `${formatTokenAmount(BigInt(limit.maxPerPeriodAtomic), limit.token)} ${limit.token}`).join(" · ")}</strong></span>
                  <span><small>EXPIRES</small><strong>{new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" }).format(new Date(policy.expiresAt))}</strong></span>
                  {!record.revokedAt && <button type="button" onClick={() => void revokeAgentCapability(record)} disabled={directoryLoading}>Revoke</button>}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
