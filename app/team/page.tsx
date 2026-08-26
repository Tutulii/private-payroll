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
  obligationScheduleForRecord,
  loadEncryptedPayAgreements,
  type PayAgreementDirectoryRecord,
} from "@/lib/client/agreement-directory";
import {
  storeEncryptedAgreementFromForm,
  type AgreementPlanKind,
} from "@/lib/client/agreement-form-workflow";
import { PAYO_EMPLOYEE_POLICY_OPTIONS } from "@/lib/policy/execution-catalog";
import {
  CLASSIFICATION_EMPLOYEE_THRESHOLD,
  CLASSIFICATION_FACTS,
  scoreClassificationFacts,
  type ClassificationFactsAnswers,
} from "@/lib/domain/classification";
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
type ClassificationFactKey = (typeof CLASSIFICATION_FACTS)[number]["key"];
type ClassificationAnswerDraft = Record<ClassificationFactKey, "" | "yes" | "no">;
const NET_INVOICE_POLICY_ID = "payo-net-invoice-no-withholding-v1";

function classificationAnswerDraft(principalKind: "human" | "agent"): ClassificationAnswerDraft {
  return Object.fromEntries(CLASSIFICATION_FACTS.map(({ key }) => [key, principalKind === "agent" ? "no" : ""])) as ClassificationAnswerDraft;
}

function policyForClassification(
  payee: PayeeDirectoryRecord,
  classification: "employee" | "contractor" | "agent_service",
): string {
  if (classification !== "employee") return NET_INVOICE_POLICY_ID;
  return payee.tokenPreference === "USDC" && payee.jurisdictionCode.split("-")[0] === "US"
    ? PAYO_EMPLOYEE_POLICY_OPTIONS.US.id
    : "";
}

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
  const [classificationAnswerDrafts, setClassificationAnswerDrafts] = useState<ClassificationAnswerDraft>(() => classificationAnswerDraft("human"));
  const [agreementCadence, setAgreementCadence] = useState<"weekly" | "biweekly" | "monthly">("monthly");
  const [agreementNextDueAt, setAgreementNextDueAt] = useState("");
  const [agreementPlanKind, setAgreementPlanKind] = useState<AgreementPlanKind>("recurring");
  const [planStartsAt, setPlanStartsAt] = useState("");
  const [planEndsAt, setPlanEndsAt] = useState("");
  const [planCheckpointAt, setPlanCheckpointAt] = useState("");
  const [planCliffAt, setPlanCliffAt] = useState("");
  const [planTotalAmount, setPlanTotalAmount] = useState("");
  const [milestoneCommitment, setMilestoneCommitment] = useState("");
  const [approverCommitment, setApproverCommitment] = useState("");
  const [attestationCommitment, setAttestationCommitment] = useState("");
  const [adjustmentReasonCommitment, setAdjustmentReasonCommitment] = useState("");
  const [terminationReasonCommitment, setTerminationReasonCommitment] = useState("");
  const [finalOrdinaryAmount, setFinalOrdinaryAmount] = useState("");
  const [finalLeaveAmount, setFinalLeaveAmount] = useState("0");
  const [finalNoticeAmount, setFinalNoticeAmount] = useState("0");
  const [finalSeveranceAmount, setFinalSeveranceAmount] = useState("0");
  const [finalAdjustmentAmount, setFinalAdjustmentAmount] = useState("0");
  const [finalDeductionsAmount, setFinalDeductionsAmount] = useState("0");
  const [requireLeave, setRequireLeave] = useState(true);
  const [requireNotice, setRequireNotice] = useState(false);
  const [requireSeverance, setRequireSeverance] = useState(false);
  const [policyId, setPolicyId] = useState(NET_INVOICE_POLICY_ID);
  const [fxFloorAmount, setFxFloorAmount] = useState("");
  const [directoryLoadedAt] = useState(() => Date.now());

  const classificationAnswers = useMemo<ClassificationFactsAnswers | null>(() => {
    if (Object.values(classificationAnswerDrafts).some((answer) => answer === "")) return null;
    return Object.fromEntries(
      CLASSIFICATION_FACTS.map(({ key }) => [key, classificationAnswerDrafts[key] === "yes"]),
    ) as ClassificationFactsAnswers;
  }, [classificationAnswerDrafts]);
  const classificationScore = classificationAnswers ? scoreClassificationFacts(classificationAnswers) : null;
  const classificationMatches = classificationScore !== null && (
    agreementClassification === "employee"
      ? classificationScore >= CLASSIFICATION_EMPLOYEE_THRESHOLD
      : classificationScore < CLASSIFICATION_EMPLOYEE_THRESHOLD
  );

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
  const agreementFormPayee = payees.find(({ id }) => id === agreementPayeeId);
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
    const now = new Date(directoryLoadedAt - 60_000);
    setAgreementPayeeId(payee.id);
    const classification = payee.principalKind === "agent" ? "agent_service" : "contractor";
    setAgreementClassification(classification);
    setClassificationAnswerDrafts(classificationAnswerDraft(payee.principalKind));
    setPolicyId(policyForClassification(payee, classification));
    setAgreementPlanKind("recurring");
    setAgreementAmount("");
    setAgreementNextDueAt(localDateTimeInputValue(now));
    setPlanStartsAt(localDateTimeInputValue(new Date(now.getTime() - 4 * 60 * 60 * 1_000)));
    setPlanCheckpointAt(localDateTimeInputValue(now));
    setPlanCliffAt(localDateTimeInputValue(new Date(now.getTime() - 2 * 60 * 60 * 1_000)));
    setPlanEndsAt(localDateTimeInputValue(new Date(now.getTime() + 4 * 60 * 60 * 1_000)));
    setPlanTotalAmount("");
    setMilestoneCommitment("");
    setApproverCommitment("");
    setAttestationCommitment("");
    setAdjustmentReasonCommitment("");
    setTerminationReasonCommitment("");
    setFinalOrdinaryAmount("");
    setFinalLeaveAmount("0");
    setFinalNoticeAmount("0");
    setFinalSeveranceAmount("0");
    setFinalAdjustmentAmount("0");
    setFinalDeductionsAmount("0");
    setFxFloorAmount("");
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
      if (!classificationAnswers) {
        throw new Error("Answer every classification fact before encrypting the agreement.");
      }
      if (!classificationMatches) {
        throw new Error("The selected treatment does not match the versioned classification fact rubric.");
      }
      const storedAgreement = await storeEncryptedAgreementFromForm({
        client: vault.client,
        organizationId: vault.session.organizationId,
        payee,
        principal: vault.session.principal,
        draft: {
          planKind: agreementPlanKind,
          amount: agreementAmount,
          classification: agreementClassification,
          classificationAnswers,
          cadence: agreementCadence,
          nextDueAt: agreementNextDueAt,
          planStartsAt,
          planEndsAt,
          planCheckpointAt,
          planCliffAt,
          planTotalAmount,
          milestoneCommitment,
          approverCommitment,
          attestationCommitment,
          adjustmentReasonCommitment,
          terminationReasonCommitment,
          finalOrdinaryAmount,
          finalLeaveAmount,
          finalNoticeAmount,
          finalSeveranceAmount,
          finalAdjustmentAmount,
          finalDeductionsAmount,
          requireLeave,
          requireNotice,
          requireSeverance,
          policyId,
          policyVersion: 1,
          fxFloorAmount,
          fxMaximumAgeSeconds: 900,
        },
      });
      let scheduleRegistered = true;
      try {
        await vault.client.registerObligationSchedules({
          organizationId: vault.session.organizationId,
          schedules: [obligationScheduleForRecord(storedAgreement)],
        });
      } catch {
        // The encrypted agreement is already durable. Payroll performs the
        // same idempotent registration on load, so a transient scheduler/API
        // failure must not encourage the user to create a duplicate agreement.
        scheduleRegistered = false;
      }
      setShowAddAgreement(false);
      setAgreementNextDueAt("");
      await refreshPayees();
      notify(scheduleRegistered
        ? `${agreementPlanKind === "recurring" ? "Recurring" : "Advanced proof-bound"} agreement encrypted · return to Payroll to authorize and send`
        : "Agreement encrypted · Payroll will retry its private due-schedule registration");
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
          <form className={`team-add-form ${agreementPlanKind !== "recurring" ? "team-add-form--advanced" : ""}`} onSubmit={addAgreement}>
            <div className="team-add-form__heading"><span><small>AUTHORITATIVE ENCRYPTED TERMS</small><strong>Add a proof-bound pay agreement</strong></span><button type="button" onClick={() => setShowAddAgreement(false)} aria-label="Close agreement form">×</button></div>
            <label><span>Contributor</span><select value={agreementPayeeId} onChange={(event) => {
              const payee = payees.find(({ id }) => id === event.target.value);
              setAgreementPayeeId(event.target.value);
              if (payee) {
                const classification = payee.principalKind === "agent" ? "agent_service" : "contractor";
                setAgreementClassification(classification);
                setClassificationAnswerDrafts(classificationAnswerDraft(payee.principalKind));
                setPolicyId(policyForClassification(payee, classification));
              }
            }}>{payees.map((payee) => <option value={payee.id} key={payee.id}>{payee.displayName}</option>)}</select></label>
            <label><span>Payment plan</span><select value={agreementPlanKind} onChange={(event) => {
              const plan = event.target.value as AgreementPlanKind;
              setAgreementPlanKind(plan);
            }}>
              <option value="recurring">Recurring payroll</option>
              <option value="checkpoint_stream">Checkpoint stream</option>
              <option value="milestone">Approved milestone</option>
              <option value="private_vesting">Private vesting release</option>
              <option value="approved_adjustment">Approved pay adjustment</option>
              <option value="final_pay">Final pay / offboarding</option>
            </select></label>
            <label><span>Classification</span><select value={agreementClassification} onChange={(event) => {
              const classification = event.target.value as typeof agreementClassification;
              setAgreementClassification(classification);
              const payee = payees.find(({ id }) => id === agreementPayeeId);
              if (payee) setPolicyId(policyForClassification(payee, classification));
            }}>
              {agreementFormPayee?.principalKind === "human" ? <>
                <option value="employee">Employee · narrow reference policy</option>
                <option value="contractor">Contractor</option>
              </> : <option value="agent_service">Agent service</option>}
            </select></label>
            {agreementFormPayee?.principalKind === "human" && (
              <fieldset className="team-add-form__classification">
                <legend>Private classification facts · rubric v1</legend>
                <p>Answer factual working-condition questions. PAYO proves internal treatment consistency; it does not decide legal status.</p>
                {CLASSIFICATION_FACTS.map(({ key, label }) => (
                  <label key={key}>
                    <span>{label}</span>
                    <select
                      value={classificationAnswerDrafts[key]}
                      onChange={(event) => setClassificationAnswerDrafts((current) => ({
                        ...current,
                        [key]: event.target.value as ClassificationAnswerDraft[ClassificationFactKey],
                      }))}
                      required
                    >
                      <option value="">Choose</option>
                      <option value="yes">Yes</option>
                      <option value="no">No</option>
                    </select>
                  </label>
                ))}
                <small className={classificationAnswers && !classificationMatches ? "classification-score classification-score--mismatch" : "classification-score"}>
                  {classificationScore === null
                    ? "Complete all six facts to derive the private consistency score."
                    : `Reference score ${classificationScore}/6 · employee threshold ${CLASSIFICATION_EMPLOYEE_THRESHOLD}/6${classificationMatches ? " · treatment consistent" : " · change the facts or selected treatment"}`}
                </small>
              </fieldset>
            )}
            {(agreementPlanKind === "recurring" || agreementPlanKind === "milestone" || agreementPlanKind === "approved_adjustment") && <label><span>{agreementPlanKind === "approved_adjustment" ? "Private adjustment amount" : "Private amount"}</span><input value={agreementAmount} onChange={(event) => setAgreementAmount(event.target.value)} inputMode="decimal" placeholder="1250.00" required /></label>}
            {agreementPlanKind === "recurring" && <label><span>Cadence</span><select value={agreementCadence} onChange={(event) => setAgreementCadence(event.target.value as typeof agreementCadence)}><option value="weekly">Weekly</option><option value="biweekly">Biweekly</option><option value="monthly">Monthly</option></select></label>}
            {(agreementPlanKind === "recurring" || agreementPlanKind === "milestone" || agreementPlanKind === "approved_adjustment" || agreementPlanKind === "final_pay") && <label><span>{agreementPlanKind === "recurring" ? "First payment due" : agreementPlanKind === "milestone" ? "Milestone due" : agreementPlanKind === "approved_adjustment" ? "Adjustment effective" : "Termination effective"}</span><input type="datetime-local" value={agreementNextDueAt} onChange={(event) => setAgreementNextDueAt(event.target.value)} required /><small>Set this to now or earlier when the obligation is ready for the next payroll.</small></label>}
            {(agreementPlanKind === "checkpoint_stream" || agreementPlanKind === "private_vesting") && <>
              <label><span>Total committed value</span><input value={planTotalAmount} onChange={(event) => setPlanTotalAmount(event.target.value)} inputMode="decimal" placeholder="5000.00" required /></label>
              <label><span>Plan starts</span><input type="datetime-local" value={planStartsAt} onChange={(event) => setPlanStartsAt(event.target.value)} required /></label>
              <label><span>{agreementPlanKind === "checkpoint_stream" ? "Settlement checkpoint" : "Release checkpoint"}</span><input type="datetime-local" value={planCheckpointAt} onChange={(event) => setPlanCheckpointAt(event.target.value)} required /><small>PAYO derives the exact accrued amount; the browser cannot choose it.</small></label>
              {agreementPlanKind === "private_vesting" && <label><span>Vesting cliff</span><input type="datetime-local" value={planCliffAt} onChange={(event) => setPlanCliffAt(event.target.value)} required /></label>}
              <label><span>Plan ends</span><input type="datetime-local" value={planEndsAt} onChange={(event) => setPlanEndsAt(event.target.value)} required /></label>
            </>}
            {(agreementPlanKind === "milestone" || agreementPlanKind === "approved_adjustment" || agreementPlanKind === "final_pay") && <>
              <label className="team-add-form__address"><span>{agreementPlanKind === "final_pay" ? "Offboarding obligation commitment" : agreementPlanKind === "approved_adjustment" ? "Adjustment obligation commitment" : "Milestone commitment"}</span><input value={milestoneCommitment} onChange={(event) => setMilestoneCommitment(event.target.value)} placeholder="0x + 64 hex characters" pattern="^0x[0-9a-fA-F]{64}$" required /></label>
              <label className="team-add-form__address"><span>Approver commitment</span><input value={approverCommitment} onChange={(event) => setApproverCommitment(event.target.value)} placeholder="0x + 64 hex characters" pattern="^0x[0-9a-fA-F]{64}$" required /></label>
              <label className="team-add-form__address"><span>Approval evidence commitment</span><input value={attestationCommitment} onChange={(event) => setAttestationCommitment(event.target.value)} placeholder="0x + 64 hex characters" pattern="^0x[0-9a-fA-F]{64}$" required /><small>Only the 32-byte commitment is encrypted into the agreement; the evidence itself stays with its issuer.</small></label>
            </>}
            {agreementPlanKind === "approved_adjustment" && <label className="team-add-form__address"><span>Adjustment reason commitment</span><input value={adjustmentReasonCommitment} onChange={(event) => setAdjustmentReasonCommitment(event.target.value)} placeholder="0x + 64 hex characters" pattern="^0x[0-9a-fA-F]{64}$" required /><small>The proof binds the approved delta to this private reason without revealing the reason itself.</small></label>}
            {agreementPlanKind === "checkpoint_stream" && <label className="team-add-form__address"><span>Checkpoint attestation commitment</span><input value={attestationCommitment} onChange={(event) => setAttestationCommitment(event.target.value)} placeholder="0x + 64 hex characters" pattern="^0x[0-9a-fA-F]{64}$" required /></label>}
            {agreementPlanKind === "final_pay" && <>
              <label className="team-add-form__address"><span>Termination reason commitment</span><input value={terminationReasonCommitment} onChange={(event) => setTerminationReasonCommitment(event.target.value)} placeholder="0x + 64 hex characters" pattern="^0x[0-9a-fA-F]{64}$" required /></label>
              <div className="team-add-form__subhead"><small>PRIVATE FINAL-PAY COMPONENTS</small><strong>Every required component is committed separately.</strong></div>
              <label><span>Ordinary pay</span><input value={finalOrdinaryAmount} onChange={(event) => setFinalOrdinaryAmount(event.target.value)} inputMode="decimal" placeholder="1000.00" required /></label>
              <label><span>Accrued leave</span><input value={finalLeaveAmount} onChange={(event) => setFinalLeaveAmount(event.target.value)} inputMode="decimal" required /></label>
              <label><span>Notice pay</span><input value={finalNoticeAmount} onChange={(event) => setFinalNoticeAmount(event.target.value)} inputMode="decimal" required /></label>
              <label><span>Severance</span><input value={finalSeveranceAmount} onChange={(event) => setFinalSeveranceAmount(event.target.value)} inputMode="decimal" required /></label>
              <label><span>Adjustments</span><input value={finalAdjustmentAmount} onChange={(event) => setFinalAdjustmentAmount(event.target.value)} inputMode="decimal" required /></label>
              <fieldset className="team-add-form__requirements"><legend>Required by committed terms</legend><label><input type="checkbox" checked={requireLeave} onChange={(event) => setRequireLeave(event.target.checked)} /> Accrued leave</label><label><input type="checkbox" checked={requireNotice} onChange={(event) => setRequireNotice(event.target.checked)} /> Notice</label><label><input type="checkbox" checked={requireSeverance} onChange={(event) => setRequireSeverance(event.target.checked)} /> Severance</label></fieldset>
            </>}
            <label className="team-add-form__address"><span>Policy profile</span><select value={policyId} onChange={(event) => setPolicyId(event.target.value)} required>
              {agreementClassification === "employee"
                ? <option value={agreementFormPayee ? policyForClassification(agreementFormPayee, "employee") : ""}>{policyId ? "US 2026 supplemental wages · 22% withholding" : "No executable employee policy for this jurisdiction/token"}</option>
                : <option value={NET_INVOICE_POLICY_ID}>Net invoice · no withholding</option>}
            </select><small>{agreementClassification === "employee" ? "Narrow example only: US employee, separately identified supplemental wages, and USDC settlement. It is not a general payroll-tax engine or legal advice." : "The proof catalog root is derived locally from this version-pinned policy, never pasted into the agreement."}</small></label>
            {agreementPlanKind === "recurring" && agreementFormPayee?.tokenPreference === "STRK" && <label><span>Optional USD value floor</span><input value={fxFloorAmount} onChange={(event) => setFxFloorAmount(event.target.value)} inputMode="decimal" placeholder="1250.00" /><small>Six-decimal USD floor chosen by the worker. Payroll binds it to Pragma&apos;s fresh STRK median and conservative 24-hour TWAP (maximum median age: 15 minutes).</small></label>}
            {agreementPlanKind === "recurring" && agreementFormPayee?.tokenPreference === "USDC" && <p className="team-form-note">USDC payroll remains available, but USDC/USD FXFloor is disabled because Pragma Mainnet currently has no usable TWAP checkpoint history for that pair.</p>}
            <button className="button button--ink" type="submit" disabled={directoryLoading || !classificationAnswers || !classificationMatches || !policyId}>{directoryLoading ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />} Encrypt proof-bound agreement</button>
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
