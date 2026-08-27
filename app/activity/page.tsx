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
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useAppShell } from "../ui/app-shell";
import { usePayoVault } from "../vault/payo-vault";
import { STARKNET_MAINNET_EXPLORER, useStarknetWallet } from "../starknet/starknet-wallet";
import { decryptVaultRecord } from "@/lib/crypto/vault";
import { createEncryptedSettlementReceipt } from "@/lib/client/settlement-receipts";
import { createProofPackageForSettlement } from "@/lib/client/proof-package-workflow";
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
import {
  loadEncryptedPayees,
  type PayeeDirectoryRecord,
} from "@/lib/client/payee-directory";
import {
  activityAgreementOptionLabel,
  activityRunOptionLabel,
} from "@/lib/client/activity-option-labels";
import { reportActivityOperationFailure } from "@/lib/client/activity-operation-feedback";
import {
  executeProofBoundWageClaim,
  executeProofBoundWageRemediation,
  parsePendingExceptionSubmission,
  resumeProofBoundWageClaim,
  type PendingExceptionSubmission,
} from "@/lib/client/exception-execution";
import type { PayrollExecutionStage } from "@/lib/client/payroll-execution";
import type { SerializedPayrollIntegrityBuildRequest } from "@/lib/proof/input-builder";
import { runProgressiveTasks, type ProgressiveTask } from "@/lib/client/progressive-tasks";

type ActivityKind = "Payroll" | "Agent" | "Vault";

type SettlementSummary = {
  id: string;
  runId: string;
  workflowType: "payroll" | "wage_claim" | "wage_remediation";
  subjectRecordId: string;
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
  updatedAt: string;
};

type DisclosureGrantSummary = {
  id: string;
  runId: string;
  granteePrincipalId: string;
  fieldScope: string[];
  validAfter: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
};

type ExceptionFeedback = {
  tone: "error" | "success";
  message: string;
};

const exceptionStageLabel: Record<PayrollExecutionStage, string> = {
  fx: "Reading live FX",
  authorizing: "Authorizing fresh FX",
  loading: "Loading the encrypted payday",
  executing: "Building the private claim",
  proving: "Generating the ZK claim proof",
  verifying: "Verifying the claim locally",
  encoding: "Encoding the Starknet proof",
  preflight: "Checking the on-chain verifier",
  persisting: "Encrypting the proof records",
  wallet: "Approve the claim in Ready",
  recording: "Recording the submission",
  queued: "On-chain verification queued",
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
  const pathname = usePathname();
  const { notify } = useAppShell();
  const vault = usePayoVault();
  const starknet = useStarknetWallet();
  const [filter, setFilter] = useState<(typeof activityFilters)[number]>("All");
  const [query, setQuery] = useState("");
  const [copiedHash, setCopiedHash] = useState("");
  const [settlements, setSettlements] = useState<SettlementSummary[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditSummary[]>([]);
  const [receiptCount, setReceiptCount] = useState(0);
  const [agreements, setAgreements] = useState<PayAgreementDirectoryRecord[]>([]);
  const [payees, setPayees] = useState<PayeeDirectoryRecord[]>([]);
  const [runs, setRuns] = useState<PayrollRunSummary[]>([]);
  const [claims, setClaims] = useState<WageClaimRecord[]>([]);
  const [remediations, setRemediations] = useState<RemediationRecord[]>([]);
  const [disclosureGrants, setDisclosureGrants] = useState<DisclosureGrantSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [creatingReceipt, setCreatingReceipt] = useState(false);
  const [showDisclosure, setShowDisclosure] = useState(false);
  const [disclosureSettlementId, setDisclosureSettlementId] = useState("");
  const [disclosureScope, setDisclosureScope] = useState<"worker" | "employer" | "auditor" | "tax">("auditor");
  const [disclosureAgreementId, setDisclosureAgreementId] = useState("");
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
  const [claimReferenceValue, setClaimReferenceValue] = useState("");
  const [claimFinalMask, setClaimFinalMask] = useState("0");
  const [claimRunAgreementIds, setClaimRunAgreementIds] = useState<string[] | null>(null);
  const [claimSourceLoading, setClaimSourceLoading] = useState(false);
  const [claimSourceError, setClaimSourceError] = useState("");
  const [remediationClaimId, setRemediationClaimId] = useState("");
  const [remediationAmount, setRemediationAmount] = useState("");
  const [provingClaimId, setProvingClaimId] = useState("");
  const [exceptionStage, setExceptionStage] = useState<PayrollExecutionStage | null>(null);
  const [exceptionFeedback, setExceptionFeedback] = useState<ExceptionFeedback | null>(null);
  const [pendingException, setPendingException] = useState<PendingExceptionSubmission | null>(null);
  const activityRefreshGeneration = useRef(0);

  const persistPendingException = useCallback((submission: PendingExceptionSubmission | null) => {
    const organizationId = vault.session?.organizationId;
    if (!organizationId) return;
    const key = `payo:pending-exception:${organizationId}`;
    if (submission) window.localStorage.setItem(key, JSON.stringify(submission));
    else window.localStorage.removeItem(key);
    setPendingException(submission);
  }, [vault.session?.organizationId]);

  const refreshActivity = useCallback(async () => {
    const generation = activityRefreshGeneration.current + 1;
    activityRefreshGeneration.current = generation;
    if (!vault.client || !vault.session) {
      setLoading(false);
      setSettlements([]);
      setAuditEvents([]);
      setReceiptCount(0);
      setAgreements([]);
      setPayees([]);
      setRuns([]);
      setClaims([]);
      setRemediations([]);
      setDisclosureGrants([]);
      setActivityError("");
      return;
    }
    setLoading(true);
    setActivityError("");
    try {
      const current = () => activityRefreshGeneration.current === generation;
      const organizationId = vault.session.organizationId;
      const principal = vault.session.principal;
      const client = vault.client;
      const tasks: ProgressiveTask[] = [
        { label: "Settlements", run: async () => {
          const result = await client.listSettlements(organizationId);
          if (current()) setSettlements(result.settlements);
        } },
        { label: "Audit events", run: async () => {
          const result = await client.listAuditEvents(organizationId);
          if (current()) setAuditEvents(result.events);
        } },
        { label: "Receipts", run: async () => {
          const result = await client.listEncryptedRecords(organizationId, "receipt");
          if (current()) setReceiptCount(result.records.length);
        } },
        { label: "Agreements", run: async () => {
          const result = await loadEncryptedPayAgreements({ client, organizationId, principal });
          if (current()) setAgreements(result);
        } },
        { label: "Contributors", run: async () => {
          const result = await loadEncryptedPayees({ client, organizationId, principal });
          if (current()) setPayees(result);
        } },
        { label: "Paydays", run: async () => {
          const result = await client.listPayrollRuns(organizationId);
          const normalized = result.runs.flatMap((run) => {
            if (
              typeof run.id !== "string"
              || typeof run.cycleId !== "string"
              || typeof run.state !== "string"
              || !(typeof run.dueAt === "string" || run.dueAt instanceof Date)
              || !(typeof run.updatedAt === "string" || run.updatedAt instanceof Date)
            ) return [];
            return [{
              id: run.id,
              cycleId: run.cycleId,
              state: run.state,
              dueAt: run.dueAt instanceof Date ? run.dueAt.toISOString() : run.dueAt,
              updatedAt: run.updatedAt instanceof Date ? run.updatedAt.toISOString() : run.updatedAt,
            }];
          });
          if (current()) setRuns(normalized);
        } },
        { label: "Claims", run: async () => {
          const result = await loadEncryptedClaims({ client, organizationId, principal });
          if (current()) setClaims(result);
        } },
        { label: "Remediations", run: async () => {
          const result = await loadEncryptedRemediations({ client, organizationId, principal });
          if (current()) setRemediations(result);
        } },
        { label: "Disclosure grants", run: async () => {
          const result = await client.listDisclosureGrants(organizationId);
          if (current()) setDisclosureGrants(result.grants);
        } },
      ];
      const results = await runProgressiveTasks(tasks, { concurrency: 3, timeoutMs: 12_000 });
      if (current()) {
        const failed = results.filter(({ status }) => status === "rejected");
        setActivityError(failed.length
          ? `${failed.map(({ label }) => label).join(", ")} could not refresh. Available records are still shown.`
          : "");
      }
    } finally {
      if (activityRefreshGeneration.current === generation) setLoading(false);
    }
  }, [vault.client, vault.session]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshActivity(), 0);
    return () => window.clearTimeout(timer);
  }, [refreshActivity]);

  useEffect(() => {
    const organizationId = vault.session?.organizationId;
    const timer = window.setTimeout(() => {
      if (!organizationId) {
        setPendingException(null);
        return;
      }
      const serialized = window.localStorage.getItem(`payo:pending-exception:${organizationId}`);
      if (!serialized) {
        setPendingException(null);
        return;
      }
      try {
        const pending = parsePendingExceptionSubmission(JSON.parse(serialized));
        setPendingException(pending.organizationId === organizationId ? pending : null);
      } catch {
        setPendingException(null);
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [vault.session?.organizationId]);

  useEffect(() => {
    let active = true;
    const client = vault.client;
    const session = vault.session;
    if (!claimRunId || !client || !session) {
      return () => { active = false; };
    }
    void (async () => {
      try {
        const { run } = await client.getPayrollRun(claimRunId);
        if (run.organizationId !== session.organizationId || run.state !== "confirmed") {
          throw new Error("Private claims require a confirmed payday from this workspace.");
        }
        if (!run.agreementRoot || !run.policyRoot || !run.fxRoot) {
          throw new Error("This payday is missing its public proof-root bindings.");
        }
        const browserEvidenceMode = pathname.startsWith("/payo-browser-evidence");
        const sealAddress = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS
          ?? (browserEvidenceMode ? "0x1" : undefined);
        if (!sealAddress) throw new Error("The proof-bound PAYO seal is not configured.");
        const { readiness } = await client.checkDeploymentReadiness({
          chainId: starknet.chainId || (browserEvidenceMode ? "0x534e5f4d41494e" : ""),
          sealAddress,
          mode: 2,
          proofVersion: 3,
          agreementRoot: run.agreementRoot,
          policyRoot: run.policyRoot,
          fxRoot: run.fxRoot,
        });
        const expiredFx = readiness.checks.find(({ code, ready }) => code === "fx_root" && !ready);
        if (expiredFx) {
          throw new Error("This payday's FX authorization has expired. Choose the newest payday; PAYO blocked proof generation before it could waste prover time.");
        }
        if (!readiness.ready) {
          throw new Error(`This payday is not claim-ready: ${readiness.checks.filter(({ ready }) => !ready).map(({ message }) => message).join(" ")}`);
        }
        const payload = decryptVaultRecord<{
          claimProofSource?: { buildInput?: SerializedPayrollIntegrityBuildRequest };
        }>(run.envelope, session.principal);
        const agreementIds = payload.claimProofSource?.buildInput?.lines
          .map(({ agreementId }) => agreementId)
          .filter((agreementId, index, values) => values.indexOf(agreementId) === index) ?? [];
        if (agreementIds.length === 0) {
          throw new Error("This payday has no encrypted claim-proof agreements.");
        }
        if (active) setClaimRunAgreementIds(agreementIds);
      } catch (error) {
        if (active) {
          setClaimSourceError(error instanceof Error
            ? error.message
            : "The matching agreements could not be loaded from this payday.");
        }
      } finally {
        if (active) setClaimSourceLoading(false);
      }
    })();
    return () => { active = false; };
  }, [claimRunId, pathname, starknet.chainId, vault.client, vault.session]);

  const events = useMemo(() => [
    ...settlements.map(settlementEvent),
    ...auditEvents.map(auditEvent),
  ].sort((left, right) => right.timestamp - left.timestamp), [auditEvents, settlements]);

  const agreementOptions = useMemo(() => {
    const payeeNames = new Map(payees.map(({ id, displayName }) => [id, displayName]));
    return agreements.map((agreement, index) => ({
      agreement,
      label: activityAgreementOptionLabel({
        classification: agreement.agreement.classification,
        payeeName: payeeNames.get(agreement.payeeId),
      }, index),
    }));
  }, [agreements, payees]);

  const runOptions = useMemo(() => runs
    .filter(({ state }) => state === "confirmed")
    .sort((left, right) => new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime())
    .map((run, index) => ({
      run,
      label: activityRunOptionLabel(run, index),
    })), [runs]);

  const claimAgreementOptions = useMemo(() => claimRunAgreementIds
    ? agreementOptions.filter(({ agreement }) => claimRunAgreementIds.includes(agreement.agreement.id))
    : [], [agreementOptions, claimRunAgreementIds]);

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

  const receiptableSettlement = settlements.find(({ state, transactionHash, workflowType }) =>
    workflowType === "payroll"
    && Boolean(transactionHash)
    && ["confirmed", "finalized", "reconciled"].includes(state));
  const disclosureSettlements = settlements.filter(({ state, transactionHash }) =>
    Boolean(transactionHash) && ["confirmed", "finalized", "reconciled"].includes(state));
  const disclosureSettlement = disclosureSettlements.find(({ id }) => id === disclosureSettlementId)
    ?? disclosureSettlements[0];

  const createReceipt = async () => {
    if (!vault.client || !vault.session || !disclosureSettlement) return;
    setCreatingReceipt(true);
    setActivityError("");
    try {
      const receipt = await createEncryptedSettlementReceipt({
        client: vault.client,
        organizationId: vault.session.organizationId,
        settlementId: disclosureSettlement.id,
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
      const proofPackage = await createProofPackageForSettlement({
        client: vault.client,
        organizationId: vault.session.organizationId,
        settlementId: receiptableSettlement.id,
        issuerPrincipal: vault.session.principal,
        grantee,
        scope: disclosureScope,
        ...(disclosureScope === "worker" && disclosureSettlement.workflowType === "payroll"
          ? { workerAgreementId: disclosureAgreementId }
          : {}),
        expiresAt: new Date(disclosureExpiry).toISOString(),
      });
      const exportBody = {
        format: "payo-encrypted-proof-package-v1",
        organizationId: vault.session.organizationId,
        runId: disclosureSettlement.runId,
        scope: disclosureScope,
        grant: proofPackage.grant,
        encryptedPackage: proofPackage.encryptedPackage,
      };
      const blob = new Blob([`${JSON.stringify(exportBody, null, 2)}\n`], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `payo-proof-package-${proofPackage.grant.id}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setShowDisclosure(false);
      setDisclosureSettlementId("");
      setDisclosureAgreementId("");
      setGranteePrincipalId("");
      setGranteePublicKey("");
      setDisclosureExpiry("");
      await refreshActivity();
      notify("Recipient-encrypted proof package created and verified");
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : "The recipient disclosure could not be created.");
    } finally {
      setCreatingReceipt(false);
    }
  };

  const revokeDisclosure = async (grantId: string) => {
    if (!vault.client || !vault.session) return;
    setCreatingReceipt(true);
    setActivityError("");
    try {
      await vault.client.revokeDisclosureGrant(vault.session.organizationId, grantId);
      await refreshActivity();
      notify("Disclosure grant revoked · offline verification now fails closed with the current grant state");
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : "The disclosure grant could not be revoked.");
    } finally {
      setCreatingReceipt(false);
    }
  };

  const createClaimDraft = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!vault.client || !vault.session) return;
    const agreement = agreements.find(({ agreement }) => agreement.id === claimAgreementId);
    const run = runs.find(({ id }) => id === claimRunId);
    if (!agreement || !run || run.state !== "confirmed" || !claimRunAgreementIds?.includes(agreement.agreement.id)) {
      const message = "Choose a confirmed payday and one of its matching agreements.";
      setActivityError(message);
      setExceptionFeedback({ tone: "error", message });
      return;
    }
    setCreatingException(true);
    setActivityError("");
    setExceptionFeedback(null);
    try {
      await createEncryptedWageClaimDraft({
        client: vault.client,
        organizationId: vault.session.organizationId,
        agreementId: agreement.agreement.id,
        runId: run.id,
        claimKind,
        disputedReferenceValueAtomic: claimKind === "below_committed_floor" ? claimReferenceValue : undefined,
        disputedFinalIncludedMask: claimKind === "incomplete_final_pay" ? Number(claimFinalMask) : undefined,
        principal: vault.session.principal,
      });
      setShowClaimForm(false);
      setClaimAgreementId("");
      setClaimRunId("");
      setClaimReferenceValue("");
      setClaimFinalMask("0");
      await refreshActivity();
      notify("Encrypted claim draft stored");
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : "The encrypted claim draft could not be stored.");
    } finally {
      setCreatingException(false);
    }
  };

  const proveClaim = async (claim: WageClaimRecord) => {
    if (!vault.client || !vault.session) return;
    setCreatingException(true);
    setProvingClaimId(claim.id);
    setExceptionStage(null);
    setActivityError("");
    setExceptionFeedback(null);
    try {
      if (!starknet.isConnected || !starknet.isMainnet) {
        throw new Error("Connect Ready on Starknet Mainnet before proving a private claim.");
      }
      starknet.assertPrivateActionAvailable();
      const sealAddress = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS;
      if (!sealAddress) throw new Error("The proof-bound PAYO seal is not configured.");
      const proverBaseUrl = process.env.NEXT_PUBLIC_PAYO_PROVER_URL?.trim();
      const result = await executeProofBoundWageClaim({
        client: vault.client,
        organizationId: vault.session.organizationId,
        principal: vault.session.principal,
        chainId: starknet.chainId,
        sealAddress,
        claim,
        submitException: starknet.runProofBoundException,
        onStage: setExceptionStage,
        persistPendingSubmission: persistPendingException,
        prove: proverBaseUrl
          ? async ({ encryptedWitness, principal, onProgress }) => {
              onProgress?.("loading");
              onProgress?.("proving");
              return vault.client!.provePayrollIntegrityRemotely({
                proverBaseUrl,
                encryptedWitness,
                principal,
              });
            }
          : undefined,
      });
      await refreshActivity();
      const message = `Private wage claim submitted · ${result.transactionHash.slice(0, 10)}…`;
      setExceptionFeedback({ tone: "success", message });
      notify(message);
    } catch (error) {
      await reportActivityOperationFailure({
        error,
        fallback: "The private wage claim could not be submitted.",
        refresh: refreshActivity,
        report: (message) => {
          setActivityError(message);
          setExceptionFeedback({ tone: "error", message });
        },
      });
    } finally {
      setCreatingException(false);
      setProvingClaimId("");
      setExceptionStage(null);
    }
  };

  const resumeClaimApproval = async (claim: WageClaimRecord) => {
    if (!vault.client || !vault.session || !pendingException) return;
    setCreatingException(true);
    setProvingClaimId(claim.id);
    setExceptionStage(null);
    setActivityError("");
    setExceptionFeedback(null);
    try {
      if (!starknet.isConnected || !starknet.isMainnet) {
        throw new Error("Connect Ready on Starknet Mainnet before resuming the private claim.");
      }
      starknet.assertPrivateActionAvailable();
      const sealAddress = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS;
      if (!sealAddress) throw new Error("The proof-bound PAYO seal is not configured.");
      const result = await resumeProofBoundWageClaim({
        client: vault.client,
        organizationId: vault.session.organizationId,
        principal: vault.session.principal,
        chainId: starknet.chainId,
        sealAddress,
        claim,
        pendingSubmission: pendingException,
        submitException: starknet.runProofBoundException,
        onStage: setExceptionStage,
        persistPendingSubmission: persistPendingException,
      });
      await refreshActivity();
      const message = `Private wage claim submitted · ${result.transactionHash.slice(0, 10)}…`;
      setExceptionFeedback({ tone: "success", message });
      notify(message);
    } catch (error) {
      await reportActivityOperationFailure({
        error,
        fallback: "The saved wage-claim approval could not be resumed.",
        refresh: refreshActivity,
        report: (message) => {
          setActivityError(message);
          setExceptionFeedback({ tone: "error", message });
        },
      });
    } finally {
      setCreatingException(false);
      setProvingClaimId("");
      setExceptionStage(null);
    }
  };

  const settleRemediation = async (remediation: RemediationRecord) => {
    if (!vault.client || !vault.session) return;
    const claim = claims.find(({ id }) => id === remediation.claimId);
    if (!claim) {
      const message = "The encrypted wage claim for this remediation is unavailable.";
      setActivityError(message);
      setExceptionFeedback({ tone: "error", message });
      return;
    }
    setCreatingException(true);
    setProvingClaimId(remediation.id);
    setExceptionStage(null);
    setActivityError("");
    setExceptionFeedback(null);
    try {
      if (!starknet.isConnected || !starknet.isMainnet) {
        throw new Error("Connect Ready on Starknet Mainnet before settling private remediation.");
      }
      starknet.assertPrivateActionAvailable();
      const sealAddress = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS;
      if (!sealAddress) throw new Error("The proof-bound PAYO seal is not configured.");
      const proverBaseUrl = process.env.NEXT_PUBLIC_PAYO_PROVER_URL?.trim();
      const result = await executeProofBoundWageRemediation({
        client: vault.client,
        organizationId: vault.session.organizationId,
        principal: vault.session.principal,
        chainId: starknet.chainId,
        sealAddress,
        claim,
        remediation,
        submitException: starknet.runProofBoundException,
        onStage: setExceptionStage,
        persistPendingSubmission: persistPendingException,
        prove: proverBaseUrl
          ? async ({ encryptedWitness, principal, onProgress }) => {
              onProgress?.("loading");
              onProgress?.("proving");
              return vault.client!.provePayrollIntegrityRemotely({ proverBaseUrl, encryptedWitness, principal });
            }
          : undefined,
      });
      await refreshActivity();
      const message = `Private remediation submitted · ${result.transactionHash.slice(0, 10)}…`;
      setExceptionFeedback({ tone: "success", message });
      notify(message);
    } catch (error) {
      await reportActivityOperationFailure({
        error,
        fallback: "The private remediation could not be submitted.",
        refresh: refreshActivity,
        report: (message) => {
          setActivityError(message);
          setExceptionFeedback({ tone: "error", message });
        },
      });
    } finally {
      setCreatingException(false);
      setProvingClaimId("");
      setExceptionStage(null);
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
        claim,
        amountAtomic: remediationAmount || undefined,
        principal: vault.session.principal,
      });
      setShowRemediationForm(false);
      setRemediationClaimId("");
      setRemediationAmount("");
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
            <button type="button" className="button button--soft button--wide" onClick={() => setShowDisclosure((current) => !current)} disabled={!vault.session || !disclosureSettlement || creatingReceipt}><KeyRound size={16} /> Create scoped proof package</button>
            {showDisclosure && <form className="receipt-disclosure-form" onSubmit={createDisclosure}>
              <label><span>Verified workflow</span><select value={disclosureSettlement?.id ?? ""} onChange={(event) => { setDisclosureSettlementId(event.target.value); setDisclosureAgreementId(""); }} required>{disclosureSettlements.map((settlement) => <option value={settlement.id} key={settlement.id}>{settlement.workflowType.replaceAll("_", " ")} · {shortId(settlement.transactionHash)}</option>)}</select></label>
              <label><span>Recipient scope</span><select value={disclosureScope} onChange={(event) => setDisclosureScope(event.target.value as typeof disclosureScope)}><option value="worker">Worker · own line only</option><option value="employer">Employer · full books</option><option value="auditor">Auditor · no identities</option><option value="tax">Tax reviewer · no classification</option></select></label>
              {disclosureScope === "worker" && disclosureSettlement?.workflowType === "payroll" && <label><span>Worker payroll line</span><select value={disclosureAgreementId} onChange={(event) => setDisclosureAgreementId(event.target.value)} required><option value="">Choose a proved agreement</option>{agreementOptions.map(({ agreement, label }) => <option key={agreement.id} value={agreement.agreement.id}>{label} · {agreement.agreement.settlementToken}</option>)}</select></label>}
              {disclosureScope === "worker" && disclosureSettlement?.workflowType !== "payroll" && <p>PAYO derives the claimant or remediation recipient from the encrypted, proof-bound exception record; no other payroll line can be selected.</p>}
              <label><span>Recipient principal UUID</span><input value={granteePrincipalId} onChange={(event) => setGranteePrincipalId(event.target.value)} placeholder="UUIDv7" required pattern="[0-9a-fA-F-]{36}" /></label>
              <label><span>Recipient X25519 public key</span><input value={granteePublicKey} onChange={(event) => setGranteePublicKey(event.target.value)} placeholder="Recipient encryption key" required /></label>
              <label><span>Expires</span><input type="datetime-local" value={disclosureExpiry} onChange={(event) => setDisclosureExpiry(event.target.value)} required /></label>
              <p>PAYO rebuilds the exact payroll, claim, or remediation manifest locally, requires both on-chain verifier shards, creates a balanced journal, and encrypts the package only to this recipient. Worker packages contain one workflow-specific Merkle opening; auditor and tax scopes omit restricted fields.</p>
              <button type="submit" className="button button--ink button--wide" disabled={creatingReceipt || !disclosureSettlement || (disclosureScope === "worker" && disclosureSettlement.workflowType === "payroll" && !disclosureAgreementId)}>{creatingReceipt ? <LoaderCircle className="spin" size={16} /> : <Download size={16} />} Verify, encrypt and download</button>
            </form>}
            {disclosureGrants.length > 0 && <div className="disclosure-grant-list">
              <small>SCOPED GRANTS</small>
              {disclosureGrants.slice(0, 4).map((grant) => {
                const expired = new Date(grant.expiresAt) <= new Date();
                return <div className="disclosure-grant-row" key={grant.id}>
                  <span><strong>{grant.fieldScope.join(" · ")}</strong><small>{grant.revokedAt ? "Revoked" : expired ? "Expired" : `Expires ${new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date(grant.expiresAt))}`} · {grant.granteePrincipalId.slice(0, 8)}…</small></span>
                  {!grant.revokedAt && !expired && <button type="button" onClick={() => void revokeDisclosure(grant.id)} disabled={creatingReceipt}>Revoke</button>}
                </div>;
              })}
            </div>}
          </section>

          <section className="receipts-card private-exceptions-card">
            <div className="receipt-doodle receipt-doodle--warning" aria-hidden="true"><FileText size={28} /><span>!</span></div>
            <span className="label">PRIVATE EXCEPTIONS</span>
            <h3>Raise the issue.<br />Keep terms encrypted.</h3>
            <p>Claim and remediation facts remain encrypted. Draft claims can now generate the pinned wage-claim proof, seal CLAIM through Ready, and enter durable verification.</p>
            <div className="private-exception-counts">
              <span><strong>{claims.length}</strong> claim drafts</span>
              <span><strong>{remediations.length}</strong> remediation drafts</span>
            </div>
            <button type="button" className="button button--ink button--wide" onClick={() => setShowClaimForm((current) => !current)} disabled={!vault.session || creatingException || agreements.length === 0 || runOptions.length === 0}><FileText size={16} /> Draft private claim</button>
            {showClaimForm && <form className="receipt-disclosure-form" onSubmit={createClaimDraft}>
              <label><span>Payroll run</span><select value={claimRunId} onChange={(event) => {
                const runId = event.target.value;
                setClaimRunId(runId);
                setClaimAgreementId("");
                setClaimRunAgreementIds(null);
                setClaimSourceError("");
                setClaimSourceLoading(Boolean(runId));
              }} required><option value="">Choose run</option>{runOptions.map(({ run, label }) => <option value={run.id} key={run.id}>{label}</option>)}</select></label>
              <label><span>Committed agreement</span><select value={claimAgreementId} onChange={(event) => setClaimAgreementId(event.target.value)} disabled={!claimRunId || claimSourceLoading || Boolean(claimSourceError)} required><option value="">{claimSourceLoading ? "Loading matching agreements…" : claimRunId ? "Choose matching agreement" : "Choose payday first"}</option>{claimAgreementOptions.map(({ agreement, label }) => <option value={agreement.agreement.id} key={agreement.id}>{label}</option>)}</select></label>
              {claimSourceError && <p className="private-exception-source-error" role="alert">{claimSourceError}</p>}
              <label><span>Claim type</span><select value={claimKind} onChange={(event) => setClaimKind(event.target.value as WageClaimRecord["claimKind"])}><option value="missing_obligation">Missing obligation</option><option value="below_committed_floor">Below committed floor</option><option value="incomplete_final_pay">Incomplete final pay</option></select></label>
              {claimKind === "below_committed_floor" && <label><span>Disputed reference value (6-decimal atomic)</span><input inputMode="numeric" pattern="[0-9]+" value={claimReferenceValue} onChange={(event) => setClaimReferenceValue(event.target.value)} placeholder="900000" required /></label>}
              {claimKind === "incomplete_final_pay" && <label><span>Included final-pay mask (0–31)</span><input type="number" min="0" max="31" step="1" value={claimFinalMask} onChange={(event) => setClaimFinalMask(event.target.value)} required /></label>}
              <p>This creates a salted, encrypted draft. It does not assert that a ZK claim proof has been generated or verified.</p>
              <button type="submit" className="button button--ink button--wide" disabled={creatingException}>{creatingException ? <LoaderCircle className="spin" size={16} /> : <LockKeyhole size={16} />} Encrypt claim draft</button>
            </form>}
            {claims.length > 0 && <div className="private-exception-list">
              {claims.map((claim) => <div key={claim.id} className="private-exception-row">
                <span><small>{claim.claimKind.replaceAll("_", " ")}</small><strong>{shortId(claim.id)} · {claim.state}</strong></span>
                {claim.state === "draft" && <button type="button" className="button button--soft" onClick={() => void proveClaim(claim)} disabled={creatingException || !starknet.isConnected}>{provingClaimId === claim.id ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />} Prove &amp; submit</button>}
                {claim.state === "proven" && pendingException?.workflowType === "wage_claim" && pendingException.subjectRecordId === claim.id && <button type="button" className="button button--soft" onClick={() => void resumeClaimApproval(claim)} disabled={creatingException || !starknet.isConnected}>{provingClaimId === claim.id ? <LoaderCircle className="spin" size={15} /> : <WalletCards size={15} />} Resume Ready approval</button>}
              </div>)}
              {exceptionStage && <p className="private-exception-feedback private-exception-feedback--progress" role="status" aria-live="polite"><LoaderCircle className="spin" size={14} /> {exceptionStageLabel[exceptionStage]}</p>}
            </div>}
            {exceptionFeedback && <p className={`private-exception-feedback private-exception-feedback--${exceptionFeedback.tone}`} role={exceptionFeedback.tone === "error" ? "alert" : "status"}><span aria-hidden="true">{exceptionFeedback.tone === "error" ? "!" : "✓"}</span> {exceptionFeedback.message}</p>}
            <button type="button" className="button button--soft button--wide" onClick={() => setShowRemediationForm((current) => !current)} disabled={!vault.session || creatingException || claims.length === 0}><ShieldCheck size={16} /> Draft remediation</button>
            {showRemediationForm && <form className="receipt-disclosure-form" onSubmit={createRemediationDraft}>
              <label><span>Encrypted claim</span><select value={remediationClaimId} onChange={(event) => setRemediationClaimId(event.target.value)} required><option value="">Choose claim</option>{claims.filter((claim) => ["submitted", "accepted"].includes(claim.state)).map((claim) => <option value={claim.id} key={claim.id}>{claim.claimKind.replaceAll("_", " ")} · {shortId(claim.id)}</option>)}</select></label>
              <label><span>Remediation amount (token atomic units)</span><input inputMode="numeric" pattern="[0-9]+" value={remediationAmount} onChange={(event) => setRemediationAmount(event.target.value)} placeholder="Leave empty for exact proved shortfall" /></label>
              <p>The amount cannot be below the private proved shortfall. PAYO binds its token, amount, recipient, and claim nullifier in the remediation proof.</p>
              <button type="submit" className="button button--ink button--wide" disabled={creatingException}>{creatingException ? <LoaderCircle className="spin" size={16} /> : <LockKeyhole size={16} />} Encrypt remediation draft</button>
            </form>}
            {remediations.length > 0 && <div className="private-exception-list">
              {remediations.map((remediation) => {
                const runDisputed = runs.some(({ id, state }) => id === remediation.runId && state === "disputed");
                return <div key={remediation.id} className="private-exception-row">
                  <span><small>remediation</small><strong>{shortId(remediation.id)} · {remediation.state}</strong></span>
                  {remediation.state === "draft" && <button type="button" className="button button--soft" onClick={() => void settleRemediation(remediation)} disabled={creatingException || !starknet.isConnected || !runDisputed}>{provingClaimId === remediation.id ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />} Prove &amp; settle</button>}
                </div>;
              })}
            </div>}
          </section>

          <section className="pool-status-card"><span className="pool-pulse"><i /></span><div><small>STRK20 pool</small><strong>Mainnet configured</strong></div><WalletCards size={18} /></section>
        </aside>
      </div>
    </div>
  );
}
