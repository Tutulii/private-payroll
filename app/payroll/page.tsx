"use client";

import {
  ArrowRight,
  CalendarDays,
  CheckCircle2,
  CircleDollarSign,
  Clock3,
  Download,
  ExternalLink,
  LoaderCircle,
  LockKeyhole,
  MoreHorizontal,
  PencilLine,
  Play,
  ShieldCheck,
  Sparkles,
  Users,
  WalletCards,
  KeyRound,
  X,
} from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  formatTokenAmount,
  parseTokenAmount,
  PAYROLL_TOKENS,
  shortStarknetAddress,
  STARKNET_MAINNET_EXPLORER,
  STRK20_SETUP_URL,
  type ShieldFeeQuote,
  type PayrollTokenSymbol,
  useStarknetWallet,
} from "../starknet/starknet-wallet";
import { useAppShell } from "../ui/app-shell";
import { usePayoVault } from "../vault/payo-vault";
import {
  executeProofBoundPayroll,
  derivePayrollCycleId,
  parsePendingPayrollSubmission,
  preparePayrollObligationRoot,
  recoverSealedProvenPayroll,
  resumePendingPayrollSubmission,
  type PayrollExecutionStage,
  type PayrollExecutionResult,
  type PendingPayrollSubmission,
} from "@/lib/client/payroll-execution";
import {
  payrollRecoveryMode,
  payrollSubmissionRecoveryHash,
} from "@/lib/client/payroll-recovery-state";
import {
  obligationAuthorizationSelectionKey,
  payeesMissingActiveAgreements,
  reconcileProofProfileSelection,
  toggleProofProfileSelection,
} from "@/lib/client/payroll-selection";
import { decryptVaultRecord, type EncryptedVaultRecord } from "@/lib/crypto/vault";
import {
  obligationScheduleForRecord,
  recordProofScheduleCommitment,
  loadEncryptedPayAgreements,
  lockedPayrollScheduleCommitments,
  synchronizeConfirmedRecurringAgreements,
  type PayAgreementDirectoryRecord,
} from "@/lib/client/agreement-directory";
import {
  loadEncryptedPayees,
  type PayeeDirectoryRecord,
} from "@/lib/client/payee-directory";
import { isAgreementDue } from "@/lib/domain/obligations";

type PayrollRunSummary = {
  id: string;
  cycleId: string;
  state: string;
  dueAt: string;
  updatedAt: string;
  transactionHash: string | null;
  revision: number;
  recipientCount: number;
  totals: Record<PayrollTokenSymbol, bigint>;
  lines: Array<{ agreementId: string; scheduleCommitment: string; paidAtomic: string }>;
};

const filters = ["All", "Pending", "Confirmed", "Attention"] as const;
const MIN_RECOVERY_PASSWORD_LENGTH = 12;

function runStateLabel(state: string) {
  return state.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

function runDate(value: string, options?: Intl.DateTimeFormatOptions) {
  return new Intl.DateTimeFormat(undefined, options ?? { month: "short", day: "numeric", year: "numeric" })
    .format(new Date(value));
}

export default function PayrollPage() {
  const { openPayroll, notify } = useAppShell();
  const starknet = useStarknetWallet();
  const { reconcilePayrollTransaction } = starknet;
  const {
    isConnected: shieldWalletConnected,
    isMainnet: shieldWalletMainnet,
    publicBalances: shieldPublicBalances,
    quoteShieldToken: requestShieldQuote,
    isObligationRootActive: readObligationRootActive,
  } = starknet;
  const vault = usePayoVault();
  const [filter, setFilter] = useState<(typeof filters)[number]>("All");
  const [shieldToken, setShieldToken] = useState<PayrollTokenSymbol>("STRK");
  const [shieldAmount, setShieldAmount] = useState("");
  const [shieldFeeQuote, setShieldFeeQuote] = useState<ShieldFeeQuote | null>(null);
  const [shieldQuoteError, setShieldQuoteError] = useState("");
  const [isQuotingShield, setIsQuotingShield] = useState(false);
  const [payees, setPayees] = useState<PayeeDirectoryRecord[]>([]);
  const [agreements, setAgreements] = useState<PayAgreementDirectoryRecord[]>([]);
  const [selectedAgreementIds, setSelectedAgreementIds] = useState<string[]>([]);
  const [formError, setFormError] = useState("");
  const [workspaceName, setWorkspaceName] = useState("");
  const [recoveryPassword, setRecoveryPassword] = useState("");
  const [workspaceError, setWorkspaceError] = useState("");
  const [secondAdminOrganizationId, setSecondAdminOrganizationId] = useState("");
  const [secondAdminPassword, setSecondAdminPassword] = useState("");
  const [showVaultSecurity, setShowVaultSecurity] = useState(false);
  const [rotationPassword, setRotationPassword] = useState("");
  const [revokePrincipalId, setRevokePrincipalId] = useState("");
  const [payrollStage, setPayrollStage] = useState<PayrollExecutionStage | null>(null);
  const [payrollReceipt, setPayrollReceipt] = useState<PayrollExecutionResult | null>(null);
  const [proofDeliveryNotice, setProofDeliveryNotice] = useState("");
  const [recoverableSubmission, setRecoverableSubmission] = useState<PendingPayrollSubmission | null>(null);
  const [recoveryTransactionHash, setRecoveryTransactionHash] = useState("");
  const [showManualHashRecovery, setShowManualHashRecovery] = useState(false);
  const automaticRecoveryRef = useRef<string | null>(null);
  const [releasingRunId, setReleasingRunId] = useState<string | null>(null);
  const [recoveringRunId, setRecoveringRunId] = useState<string | null>(null);
  const [payrollRuns, setPayrollRuns] = useState<PayrollRunSummary[]>([]);
  const [obligationSchedule, setObligationSchedule] = useState<{
    root: string;
    transactionHash: string | null;
    validAfter: number | null;
    state: "active" | "scheduled";
  } | null>(null);
  const [obligationAuthorizationActionPending, setObligationAuthorizationActionPending] = useState(false);
  const [runsLoading, setRunsLoading] = useState(false);
  const [dueScheduleKeys, setDueScheduleKeys] = useState<Set<string>>(() => new Set());
  const [scheduleSyncError, setScheduleSyncError] = useState("");
  const [dashboardNow, setDashboardNow] = useState(() => Date.now());
  const refreshInFlight = useRef(false);

  const runCategory = (state: string) => ["confirmed", "reconciled"].includes(state)
    ? "Confirmed"
    : ["failed", "cancelled", "disputed"].includes(state)
      ? "Attention"
      : "Pending";
  const visibleRuns = filter === "All"
    ? payrollRuns
    : payrollRuns.filter((run) => runCategory(run.state) === filter);
  const selectedOrganization = vault.organizations.find(({ id }) => id === vault.selectedOrganizationId);
  const hasActivePayee = payees.some(({ status }) => status === "active");
  const hasActiveAgreement = agreements.some((agreement) =>
    !agreement.effectiveUntil
    && payees.some(({ id, status }) => id === agreement.payeeId && status === "active"));
  const payeesMissingAgreements = useMemo(
    () => payeesMissingActiveAgreements(payees, agreements),
    [agreements, payees],
  );
  const payrollBusy = payrollStage !== null && payrollStage !== "queued";
  const walletTransactionBusy = starknet.transaction?.stage === "wallet" || starknet.transaction?.stage === "confirming";
  const registryTransactionBusy = starknet.transaction?.kind === "registry" && walletTransactionBusy;
  const busy = payrollBusy || obligationAuthorizationActionPending || walletTransactionBusy;
  const privacyChecking = starknet.privacyCapability === "checking";
  const privacyUnsupported = starknet.privacyCapability === "unsupported";
  const registrationRequired = starknet.privacyCapability === "uninitialized";
  const balanceUnavailable = starknet.privacyCapability === "error";
  const canRunPayroll = starknet.privacyCapability === "available";
  const selfHostedProverUrl = process.env.NEXT_PUBLIC_PAYO_PROVER_URL;
  const treasuryLabel = starknet.privacyCapability === "uninitialized"
    ? "Not initialized"
    : privacyUnsupported
      ? "API unsupported"
      : privacyChecking
        ? "Checking…"
        : starknet.privacyCapability === "error"
          ? "Balance unavailable"
          : `${formatTokenAmount(starknet.shieldedBalances.STRK, "STRK")} STRK · ${formatTokenAmount(starknet.shieldedBalances.USDC, "USDC")} USDC`;
  const treasuryHelp = starknet.privacyCapability === "uninitialized"
    ? "Complete the one-time STRK20 registration first. Wallet API 0.10.3 cannot register an account from this dapp."
    : privacyUnsupported
      ? "Update Ready to a STRK20-compatible Wallet API, then reconnect."
      : starknet.privacyCapability === "zero"
        ? "The private account is ready. Shield public STRK to fund it."
        : starknet.privacyCapability === "error"
          ? "Ready could not read this balance. Retry the balance check before shielding."
          : "Shield public STRK before it can be sent privately.";
  const lockedScheduleKeys = useMemo(
    () => lockedPayrollScheduleCommitments(payrollRuns),
    [payrollRuns],
  );
  const locallyDueObligations = useMemo(() => agreements.flatMap((agreement) => {
    const payee = payees.find(({ id }) => id === agreement.payeeId);
    const scheduleKey = `${agreement.agreement.id}:${recordProofScheduleCommitment(agreement).toLowerCase()}`;
    if (
      !payee
      || payee.status !== "active"
      || agreement.effectiveUntil
      || lockedScheduleKeys.has(scheduleKey)
      || !isAgreementDue(agreement.agreement, new Date(dashboardNow))
    ) return [];
    return [{ agreement, payee }];
  }).slice(0, 50), [agreements, dashboardNow, lockedScheduleKeys, payees]);
  const dueObligations = useMemo(() => locallyDueObligations.filter(({ agreement }) =>
    dueScheduleKeys.has(`${agreement.agreement.id}:${recordProofScheduleCommitment(agreement).toLowerCase()}`)),
  [dueScheduleKeys, locallyDueObligations]);
  const selectedObligations = useMemo(() => dueObligations.filter(({ agreement }) =>
    selectedAgreementIds.includes(agreement.id)), [dueObligations, selectedAgreementIds]);
  const selectedObligationAuthorizationKey = useMemo(
    () => obligationAuthorizationSelectionKey(
      vault.session?.organizationId,
      selectedObligations,
    ),
    [selectedObligations, vault.session?.organizationId],
  );
  const selectedObligationsRef = useRef(selectedObligations);
  useEffect(() => {
    selectedObligationsRef.current = selectedObligations;
  }, [selectedObligations]);
  const selectedProofProfile = selectedObligations[0]?.agreement.agreement.agreementVersion === "payo-agreement-v2"
    ? "Advanced obligations · proof v2"
    : "Recurring payroll · proof v1";
  const payrollTotals = useMemo(() => selectedObligations.reduce<Record<PayrollTokenSymbol, bigint>>(
    (totals, { agreement }) => {
      totals[agreement.agreement.settlementToken] += agreement.agreement.earningsAtomic
        .reduce((sum, amount) => sum + BigInt(amount), 0n);
      return totals;
    },
    { STRK: 0n, USDC: 0n },
  ), [selectedObligations]);

  const refreshPayrollRuns = useCallback(async () => {
    if (!vault.client || !vault.session) {
      setPayrollRuns([]);
      setPayees([]);
      setAgreements([]);
      setSelectedAgreementIds([]);
      setDueScheduleKeys(new Set());
      setScheduleSyncError("");
      return;
    }
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRunsLoading(true);
    try {
      const [listing, loadedPayees, loadedAgreements] = await Promise.all([
        vault.client.listPayrollRuns(vault.session.organizationId),
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
      ]);
      const decrypted = await Promise.all(listing.runs.map(async (candidate) => {
        const run = candidate as {
          id?: unknown;
          cycleId?: unknown;
          state?: unknown;
          dueAt?: unknown;
          updatedAt?: unknown;
          transactionHash?: unknown;
          revision?: unknown;
        };
        if (
          typeof run.id !== "string"
          || typeof run.cycleId !== "string"
          || typeof run.state !== "string"
          || typeof run.dueAt !== "string"
          || typeof run.updatedAt !== "string"
          || typeof run.revision !== "number"
        ) throw new Error("PAYO returned incomplete payroll-run metadata.");
        const response = await vault.client!.getEncryptedRecord({
          organizationId: vault.session!.organizationId,
          recordId: run.id,
        }) as { record: { envelope?: EncryptedVaultRecord } };
        if (!response.record.envelope) throw new Error("An encrypted payroll manifest is missing.");
        const privateRun = decryptVaultRecord<{
          manifest?: {
            lines?: Array<{
              agreementId?: unknown;
              scheduleCommitment?: unknown;
              earningsAtomic?: unknown;
              deductionsAtomic?: unknown;
            }>;
            totals?: { STRK?: unknown; USDC?: unknown };
          };
        }>(response.record.envelope, vault.session!.principal);
        const strk = privateRun.manifest?.totals?.STRK;
        const usdc = privateRun.manifest?.totals?.USDC;
        if (
          typeof strk !== "string"
          || typeof usdc !== "string"
          || !Array.isArray(privateRun.manifest?.lines)
        ) throw new Error("An encrypted payroll manifest has an invalid shape.");
        const lines = privateRun.manifest.lines.map((line) => {
          if (
            !line
            || typeof line.agreementId !== "string"
            || typeof line.scheduleCommitment !== "string"
            || !/^0x[0-9a-fA-F]{64}$/.test(line.scheduleCommitment)
            || !Array.isArray(line.earningsAtomic)
            || !Array.isArray(line.deductionsAtomic)
            || line.earningsAtomic.some((amount) => typeof amount !== "string" || !/^\d+$/.test(amount))
            || line.deductionsAtomic.some((amount) => typeof amount !== "string" || !/^\d+$/.test(amount))
          ) throw new Error("An encrypted payroll line is missing its schedule binding.");
          const paidAtomic = line.earningsAtomic.reduce((total, amount) => total + BigInt(amount as string), 0n)
            - line.deductionsAtomic.reduce((total, amount) => total + BigInt(amount as string), 0n);
          if (paidAtomic <= 0n) throw new Error("An encrypted payroll line has no positive settlement value.");
          return { agreementId: line.agreementId, scheduleCommitment: line.scheduleCommitment, paidAtomic: paidAtomic.toString() };
        });
        return {
          id: run.id,
          cycleId: run.cycleId,
          state: run.state,
          dueAt: run.dueAt,
          updatedAt: run.updatedAt,
          transactionHash: typeof run.transactionHash === "string" ? run.transactionHash : null,
          revision: run.revision,
          recipientCount: lines.length,
          totals: { STRK: BigInt(strk), USDC: BigInt(usdc) },
          lines,
        } satisfies PayrollRunSummary;
      }));
      const synchronizedAgreements = await synchronizeConfirmedRecurringAgreements({
        client: vault.client,
        agreements: loadedAgreements,
        runs: decrypted,
        principal: vault.session.principal,
      });
      // Directory data remains usable even if the operational scheduler is
      // temporarily unavailable. Never misreport existing encrypted records
      // as missing merely because schedule synchronization failed.
      setPayrollRuns(decrypted);
      setPayees(loadedPayees);
      setAgreements(synchronizedAgreements);
      setDashboardNow(Date.now());
      const activeSchedules = synchronizedAgreements
        .filter(({ effectiveUntil }) => !effectiveUntil)
        .map(obligationScheduleForRecord);
      try {
        if (activeSchedules.length > 0) {
          await vault.client.registerObligationSchedules({
            organizationId: vault.session.organizationId,
            schedules: activeSchedules,
          });
        }
        const dueScheduleListing = await vault.client.listDueObligationSchedules(
          vault.session.organizationId,
          100,
        );
        const schedulerKeys = new Set(dueScheduleListing.schedules.map(({ agreementId, scheduleCommitment }) =>
          `${agreementId}:${scheduleCommitment.toLowerCase()}`));
        setDueScheduleKeys(schedulerKeys);
        setScheduleSyncError("");
        const locked = lockedPayrollScheduleCommitments(decrypted);
        const dueIds = synchronizedAgreements.flatMap((agreement) => {
          const payee = loadedPayees.find(({ id }) => id === agreement.payeeId);
          return payee?.status === "active"
            && !agreement.effectiveUntil
            && !locked.has(`${agreement.agreement.id}:${recordProofScheduleCommitment(agreement)}`)
            && schedulerKeys.has(`${agreement.agreement.id}:${recordProofScheduleCommitment(agreement).toLowerCase()}`)
            && isAgreementDue(agreement.agreement, new Date())
            ? [agreement.id]
            : [];
        }).slice(0, 50);
        setSelectedAgreementIds((current) => reconcileProofProfileSelection({
          current,
          dueIds,
          agreements: synchronizedAgreements,
        }));
      } catch (scheduleError) {
        setDueScheduleKeys(new Set());
        setSelectedAgreementIds([]);
        setScheduleSyncError(scheduleError instanceof Error
          ? scheduleError.message
          : "The durable payroll schedule could not be synchronized.");
      }
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Encrypted payroll history could not be loaded.");
    } finally {
      refreshInFlight.current = false;
      setRunsLoading(false);
    }
  }, [vault.client, vault.session]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshPayrollRuns(), 0);
    return () => window.clearTimeout(timer);
  }, [refreshPayrollRuns]);

  const hasUnsettledRun = payrollRuns.some(({ state }) =>
    ["approval_pending", "submitted", "confirmed"].includes(state));
  useEffect(() => {
    if (!vault.session) return;
    const timer = window.setInterval(
      () => void refreshPayrollRuns(),
      hasUnsettledRun ? 5_000 : 30_000,
    );
    return () => window.clearInterval(timer);
  }, [hasUnsettledRun, refreshPayrollRuns, vault.session]);

  useEffect(() => {
    let stale = false;
    const timer = window.setTimeout(() => {
      const organizationId = vault.session?.organizationId;
      if (
        !organizationId
        || !shieldWalletConnected
        || !shieldWalletMainnet
        || !selectedObligationAuthorizationKey
      ) {
        setObligationSchedule(null);
        return;
      }
      void preparePayrollObligationRoot({
        organizationId,
        obligations: selectedObligationsRef.current,
      })
        .then(async (planned) => ({
          planned,
          active: await readObligationRootActive(planned.root),
        }))
        .then(({ planned, active }) => {
          if (stale) return;
          setObligationSchedule(active
            ? {
                root: planned.root,
                transactionHash: null,
                validAfter: null,
                state: "active",
              }
            : null);
        })
        .catch(() => {
          if (!stale) setObligationSchedule(null);
        });
    }, 0);

    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [readObligationRootActive, selectedObligationAuthorizationKey, shieldWalletConnected, shieldWalletMainnet, vault.session?.organizationId]);

  useEffect(() => {
    let stale = false;
    const timeout = window.setTimeout(() => {
      if (stale) return;
      setShieldFeeQuote(null);
      setShieldQuoteError("");
      setIsQuotingShield(false);
      if (
        !shieldWalletConnected
        || !shieldWalletMainnet
        || privacyChecking
        || privacyUnsupported
        || registrationRequired
      ) return;

      let grossAmount: bigint;
      try {
        grossAmount = parseTokenAmount(shieldAmount, shieldToken);
      } catch {
        return;
      }
      const publicBalance = shieldPublicBalances[shieldToken];
      if (publicBalance === null || grossAmount > publicBalance) return;

      setIsQuotingShield(true);
      void requestShieldQuote(shieldToken, shieldAmount)
        .then((quote) => {
          if (!stale) setShieldFeeQuote(quote);
        })
        .catch((quoteError) => {
          if (!stale) {
            setShieldQuoteError(
              quoteError instanceof Error ? quoteError.message : "The live private-fee quote is unavailable.",
            );
          }
        })
        .finally(() => {
          if (!stale) setIsQuotingShield(false);
        });
    }, 650);
    return () => {
      stale = true;
      window.clearTimeout(timeout);
    };
  }, [
    privacyChecking,
    privacyUnsupported,
    registrationRequired,
    requestShieldQuote,
    shieldAmount,
    shieldPublicBalances,
    shieldToken,
    shieldWalletConnected,
    shieldWalletMainnet,
  ]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!vault.session) {
        setRecoverableSubmission(null);
        return;
      }
      const storageKey = `payo:pending-settlement:v1:${vault.session.organizationId}`;
      const serialized = localStorage.getItem(storageKey);
      if (!serialized) {
        setRecoverableSubmission(null);
        return;
      }
      try {
        setRecoverableSubmission(parsePendingPayrollSubmission(JSON.parse(serialized)));
      } catch {
        setRecoverableSubmission(null);
        setFormError("A local payroll recovery record is corrupt. Keep it for support; do not submit this payroll again.");
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [vault.session]);

  useEffect(() => {
    const recovered = (event: Event) => {
      const detail = (event as CustomEvent<{
        runId?: string;
        verificationQueued?: boolean;
        proofDeliveryWarning?: string;
      }>).detail;
      if (!detail?.runId || recoverableSubmission?.runId !== detail.runId) return;
      setRecoverableSubmission(null);
      setPayrollStage(detail.verificationQueued === false ? "recorded" : "queued");
      setProofDeliveryNotice(detail.proofDeliveryWarning ?? "");
      setFormError("");
      setShowManualHashRecovery(false);
      void refreshPayrollRuns();
    };
    window.addEventListener("payo:payroll-proof-recovered", recovered);
    return () => window.removeEventListener("payo:payroll-proof-recovered", recovered);
  }, [recoverableSubmission?.runId, refreshPayrollRuns]);

  const persistPendingSubmission = useCallback((submission: PendingPayrollSubmission | null) => {
    if (!vault.session) throw new Error("The PAYO workspace locked during settlement recording.");
    const storageKey = `payo:pending-settlement:v1:${vault.session.organizationId}`;
    if (submission) localStorage.setItem(storageKey, JSON.stringify(submission));
    else localStorage.removeItem(storageKey);
    setRecoverableSubmission(submission);
    setShowManualHashRecovery(false);
    if (submission) void refreshPayrollRuns();
  }, [refreshPayrollRuns, vault.session]);
  const recoveryMode = payrollRecoveryMode({
    hasPendingSubmission: recoverableSubmission !== null,
    hasTransactionHash: Boolean(recoverableSubmission?.transactionHash),
    executionStage: payrollStage,
    walletStage: starknet.transaction?.kind === "payroll" ? starknet.transaction.stage : null,
  });
  const shieldQuote = useMemo(() => {
    try {
      const token = PAYROLL_TOKENS[shieldToken];
      const grossAmount = parseTokenAmount(shieldAmount, token);
      const publicTokenBalance = starknet.publicBalances[shieldToken];
      const matchingQuote = shieldFeeQuote?.token === shieldToken
        && shieldFeeQuote.grossAmount === grossAmount
        ? shieldFeeQuote
        : null;
      const netAmount = matchingQuote?.netAmount ?? null;
      const shortfall = publicTokenBalance !== null && grossAmount > publicTokenBalance
        ? grossAmount - publicTokenBalance
        : 0n;
      return {
        grossAmount,
        netAmount,
        walletFee: matchingQuote?.walletFee ?? null,
        exact: matchingQuote?.exact ?? false,
        source: matchingQuote?.source ?? null,
        shortfall,
        hasSufficientBalance: publicTokenBalance !== null && shortfall === 0n,
        isValid: netAmount !== null && netAmount > 0n && publicTokenBalance !== null && shortfall === 0n,
      };
    } catch {
      return { grossAmount: null, netAmount: null, walletFee: null, exact: false, source: null, shortfall: 0n, hasSufficientBalance: false, isValid: false };
    }
  }, [shieldAmount, shieldFeeQuote, shieldToken, starknet.publicBalances]);

  const toggleAgreement = (id: string) => {
    setObligationSchedule(null);
    setSelectedAgreementIds((current) => toggleProofProfileSelection({
      current,
      selectedId: id,
      dueAgreements: dueObligations.map(({ agreement }) => agreement),
    }));
  };

  const scheduleSelectedObligationRoot = async () => {
    if (obligationAuthorizationActionPending) return;
    setFormError("");
    setObligationAuthorizationActionPending(true);
    starknet.clearTransaction();
    try {
      if (!vault.session) throw new Error("Unlock the encrypted workspace first.");
      if (!starknet.isConnected || !starknet.isMainnet) {
        throw new Error("Connect the obligation-registry administrator on Starknet Mainnet first.");
      }
      if (selectedObligations.length === 0) throw new Error("Select at least one due agreement.");
      const planned = await preparePayrollObligationRoot({
        organizationId: vault.session.organizationId,
        obligations: selectedObligations,
      });
      if (await starknet.isObligationRootActive(planned.root)) {
        const owner = await starknet.getObligationRootOwner(planned.root);
        if (BigInt(owner) !== BigInt(starknet.address)) {
          throw new Error("This active obligation root belongs to another Ready account.");
        }
        setObligationSchedule({
          root: planned.root,
          transactionHash: null,
          validAfter: null,
          state: "active",
        });
        notify("This private obligation root is already active");
        return;
      }
      const scheduled = await starknet.scheduleObligationRoot(planned.root);
      setObligationSchedule({
        root: planned.root,
        transactionHash: scheduled.transactionHash,
        validAfter: scheduled.validAfter,
        state: "active",
      });
      notify(`Obligation root active · ${scheduled.transactionHash.slice(0, 10)}…`);
    } catch (scheduleError) {
      setFormError(scheduleError instanceof Error ? scheduleError.message : "The obligation root was not scheduled.");
    } finally {
      setObligationAuthorizationActionPending(false);
    }
  };

  const shieldTreasury = async () => {
    setFormError("");
    try {
      if (!shieldFeeQuote) throw new Error("Wait for the live private-fee quote before shielding.");
      starknet.clearTransaction();
      const hash = await starknet.shieldToken(shieldToken, shieldAmount, shieldFeeQuote);
      notify(`Shield transaction submitted · ${hash.slice(0, 10)}…`);
    } catch (shieldError) {
      setFormError(shieldError instanceof Error ? shieldError.message : "Shielding was not completed.");
    }
  };

  const submitPayroll = async () => {
    setFormError("");
    setProofDeliveryNotice("");
    setPayrollReceipt(null);
    try {
      if (!vault.session || !vault.client) {
        throw new Error("Unlock the encrypted PAYO workspace before preparing payroll.");
      }
      if (recoverableSubmission) {
        throw new Error("Finish recording the previous private payroll before creating another one.");
      }
      if (!starknet.isConnected || !starknet.isMainnet) {
        throw new Error("Connect Ready on Starknet Mainnet before preparing payroll.");
      }
      const sealAddress = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS;
      if (!sealAddress) throw new Error("The proof-bound PAYO seal is not deployed/configured.");
      if (selectedObligations.length === 0) throw new Error("Select at least one due encrypted agreement.");
      const plannedObligations = await preparePayrollObligationRoot({
        organizationId: vault.session.organizationId,
        obligations: selectedObligations,
      });
      if (!(await starknet.isObligationRootActive(plannedObligations.root))) {
        throw new Error(
          "This exact encrypted obligation root is not active. Activate it below before generating a proof.",
        );
      }
      const obligationOwner = await starknet.getObligationRootOwner(plannedObligations.root);
      if (BigInt(obligationOwner) !== BigInt(starknet.address)) {
        throw new Error("The connected Ready account does not own this encrypted obligation root.");
      }
      for (const token of Object.keys(PAYROLL_TOKENS) as PayrollTokenSymbol[]) {
        const available = starknet.shieldedBalances[token];
        if (available === null) throw new Error(`The shielded ${token} balance is unavailable.`);
        if (payrollTotals[token] > available) {
          throw new Error(`The shielded ${token} treasury does not cover this payroll.`);
        }
      }
      const result = await executeProofBoundPayroll({
        client: vault.client,
        organizationId: vault.session.organizationId,
        organizationSecret: vault.session.organizationSecret,
        principal: vault.session.principal,
        chainId: starknet.chainId,
        sealAddress,
        obligations: selectedObligations,
        runRevision: Math.max(
          0,
          ...payrollRuns
            .filter(({ cycleId }) => cycleId === derivePayrollCycleId(vault.session!.organizationId, selectedObligations))
            .map(({ revision }) => revision),
        ) + 1,
        submitPayroll: starknet.runProofBoundPayroll,
        prove: selfHostedProverUrl
          ? async ({ encryptedWitness, principal, onProgress }) => {
              onProgress?.("loading");
              onProgress?.("proving");
              return vault.client!.provePayrollIntegrityRemotely({
                proverBaseUrl: selfHostedProverUrl,
                encryptedWitness,
                principal,
              });
            }
          : undefined,
        onStage: setPayrollStage,
        persistPendingSubmission,
        authorizeFxRoot: async ({ root, publicationTicket, proof }) => {
          if (await starknet.isFxRootActive(root)) return;
          const proofVersion = Number(BigInt(proof.shards[0].publicInputs.proofVersion));
          if (proofVersion !== 1 && proofVersion !== 2) {
            throw new Error("The payroll proof returned an unsupported FX publication version.");
          }
          await vault.client!.publishPayrollFxRoot({
            organizationId: vault.session!.organizationId,
            catalogRoot: root,
            publicationTicket,
            proofVersion,
            shards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
          });
          if (!(await starknet.isFxRootActive(root))) {
            throw new Error("PAYO's trusted FX publisher returned without activating the proved root.");
          }
        },
      });
      setPayrollReceipt(result);
      setProofDeliveryNotice(result.proofDeliveryWarning ?? "");
      await refreshPayrollRuns();
      notify(result.verificationQueued
        ? `Proof-bound private payroll submitted · ${result.transactionHash.slice(0, 10)}…`
        : `Private payroll recorded · ${result.transactionHash.slice(0, 10)}…`);
    } catch (payrollError) {
      setPayrollStage(null);
      setFormError(payrollError instanceof Error ? payrollError.message : "Payroll was not submitted.");
      await refreshPayrollRuns();
    }
  };

  const resumePayrollRecording = async (submittedHash = recoveryTransactionHash) => {
    setFormError("");
    setProofDeliveryNotice("");
    try {
      if (!vault.client || !recoverableSubmission) throw new Error("No recoverable payroll submission is available.");
      const result = await resumePendingPayrollSubmission({
        client: vault.client,
        pending: recoverableSubmission,
        transactionHash: submittedHash,
        persistPendingSubmission,
        onStage: setPayrollStage,
      });
      setPayrollReceipt(result);
      setProofDeliveryNotice(result.proofDeliveryWarning ?? "");
      await reconcilePayrollTransaction(result.transactionHash);
      setRecoveryTransactionHash("");
      await refreshPayrollRuns();
      notify(result.verificationQueued
        ? `Payroll recording recovered · ${result.transactionHash.slice(0, 10)}…`
        : `Confirmed payroll recording recovered · ${result.transactionHash.slice(0, 10)}…`);
    } catch (recoveryError) {
      setPayrollStage(null);
      setFormError(recoveryError instanceof Error ? recoveryError.message : "Payroll recovery failed.");
    }
  };

  const cancelPendingPayrollApproval = async () => {
    setFormError("");
    try {
      if (!vault.client || !recoverableSubmission) throw new Error("No recoverable payroll approval is available.");
      if (recoverableSubmission.transactionHash) {
        throw new Error("This payroll already has a transaction hash and cannot be cancelled.");
      }
      if (!window.confirm(
        "Cancel this approval only if Ready was rejected or closed and no transaction was submitted. Continue?",
      )) return;
      await vault.client.cancelSettlementApproval(recoverableSubmission.settlementId);
      persistPendingSubmission(null);
      setRecoveryTransactionHash("");
      setPayrollStage(null);
      starknet.clearTransaction();
      await refreshPayrollRuns();
      notify("Unsubmitted Ready approval cancelled safely");
    } catch (cancellationError) {
      setFormError(cancellationError instanceof Error ? cancellationError.message : "The pending approval could not be cancelled.");
    }
  };

  useEffect(() => {
    if (!vault.client || !recoverableSubmission) {
      automaticRecoveryRef.current = null;
      return;
    }
    const indexedHash = payrollRuns.find(({ id }) => id === recoverableSubmission.runId)?.transactionHash;
    let recoveredHash: string | null;
    try {
      recoveredHash = payrollSubmissionRecoveryHash({
        pendingTransactionHash: recoverableSubmission.transactionHash,
        indexedTransactionHash: indexedHash,
      });
    } catch (recoveryEvidenceError) {
      queueMicrotask(() => {
        setPayrollStage(null);
        setFormError(recoveryEvidenceError instanceof Error
          ? recoveryEvidenceError.message
          : "The indexed payroll transaction could not be validated.");
      });
      return;
    }
    if (!recoveredHash) return;
    const recoveryKey = `${recoverableSubmission.settlementId}:${recoveredHash}`;
    if (automaticRecoveryRef.current === recoveryKey) return;
    automaticRecoveryRef.current = recoveryKey;
    queueMicrotask(() => setFormError(""));
    void resumePendingPayrollSubmission({
      client: vault.client,
      pending: recoverableSubmission,
      transactionHash: recoveredHash,
      persistPendingSubmission,
      onStage: setPayrollStage,
    }).then(async (result) => {
      setPayrollReceipt(result);
      setProofDeliveryNotice(result.proofDeliveryWarning ?? "");
      await reconcilePayrollTransaction(result.transactionHash);
      setRecoveryTransactionHash("");
      await refreshPayrollRuns();
      notify(result.verificationQueued
        ? `Payroll confirmed and proof verification queued · ${result.transactionHash.slice(0, 10)}…`
        : `Payroll confirmed and recorded · ${result.transactionHash.slice(0, 10)}…`);
    }).catch((recoveryError) => {
      setPayrollStage(null);
      setFormError(recoveryError instanceof Error ? recoveryError.message : "On-chain payroll recovery failed.");
    });
  }, [notify, payrollRuns, persistPendingSubmission, reconcilePayrollTransaction, recoverableSubmission, refreshPayrollRuns, vault.client]);

  const recoverSealedRun = async (run: PayrollRunSummary) => {
    setFormError("");
    if (!vault.client || !vault.session) {
      setFormError("Unlock the encrypted PAYO workspace before recovering this run.");
      return;
    }
    setRecoveringRunId(run.id);
    try {
      const result = await recoverSealedProvenPayroll({
        client: vault.client,
        organizationId: vault.session.organizationId,
        runId: run.id,
        totals: run.totals,
        principal: vault.session.principal,
        persistPendingSubmission,
        onStage: setPayrollStage,
      });
      setPayrollReceipt(result);
      setProofDeliveryNotice(result.proofDeliveryWarning ?? "");
      await reconcilePayrollTransaction(result.transactionHash);
      await refreshPayrollRuns();
      notify(result.verificationQueued
        ? `Sealed Ready transaction recovered · ${result.transactionHash.slice(0, 10)}…`
        : `Sealed Ready payment recorded · ${result.transactionHash.slice(0, 10)}…`);
    } catch (recoveryError) {
      setPayrollStage(null);
      setFormError(recoveryError instanceof Error ? recoveryError.message : "The sealed run could not be recovered.");
    } finally {
      setRecoveringRunId(null);
    }
  };

  const releaseUnsubmittedRun = async (run: PayrollRunSummary) => {
    setFormError("");
    if (!vault.client) {
      setFormError("Unlock the encrypted PAYO workspace before releasing this run.");
      return;
    }
    if (run.state !== "proven" || run.transactionHash) {
      setFormError("Only a proven run with no submitted transaction can be released.");
      return;
    }
    if (!window.confirm(
      "Release this unsubmitted run? First close or reject any open Ready request. The encrypted proof stays in PAYO, but this agreement will become available for a fresh payroll attempt.",
    )) return;
    setReleasingRunId(run.id);
    try {
      await vault.client.transitionPayrollRun({ runId: run.id, state: "cancelled" });
      await refreshPayrollRuns();
      notify("Unsubmitted run released · the agreement is ready to retry");
    } catch (releaseError) {
      setFormError(releaseError instanceof Error ? releaseError.message : "The unsubmitted run could not be released.");
    } finally {
      setReleasingRunId(null);
    }
  };

  const payrollStageLabel: Record<PayrollExecutionStage, string> = {
    fx: "Reading live FX",
    authorizing: "Authorizing fresh FX",
    loading: "Loading pinned circuit",
    executing: "Building private witness",
    proving: "Generating ZK proof",
    verifying: "Verifying locally",
    encoding: "Encoding Starknet proof",
    preflight: "Checking on-chain registries",
    persisting: "Encrypting payroll records",
    wallet: "Approve in Ready",
    recording: "Recording submission",
    recorded: "Payment recorded",
    queued: "Verification queued",
  };

  const authorizePayo = async () => {
    try {
      await vault.login();
      notify("PAYO session authorized by Ready");
    } catch (authenticationError) {
      notify(authenticationError instanceof Error
        ? authenticationError.message
        : "PAYO authorization failed");
    }
  };

  const createWorkspace = async () => {
    setWorkspaceError("");
    const normalizedWorkspaceName = workspaceName.trim();
    if (!normalizedWorkspaceName) {
      setWorkspaceError("Enter an organization name before creating the encrypted workspace.");
      return;
    }
    if (recoveryPassword.length < MIN_RECOVERY_PASSWORD_LENGTH) {
      const remainingCharacters = MIN_RECOVERY_PASSWORD_LENGTH - recoveryPassword.length;
      setWorkspaceError(`Recovery password needs ${remainingCharacters} more ${remainingCharacters === 1 ? "character" : "characters"} (12 minimum).`);
      return;
    }
    try {
      await vault.createWorkspace(normalizedWorkspaceName, recoveryPassword);
      setRecoveryPassword("");
      notify("Encrypted workspace created and recovery package downloaded");
    } catch (workspaceFailure) {
      setWorkspaceError(workspaceFailure instanceof Error ? workspaceFailure.message : "Workspace creation failed.");
    }
  };

  const unlockWorkspace = async () => {
    setWorkspaceError("");
    try {
      await vault.unlockWorkspace(recoveryPassword);
      setRecoveryPassword("");
      notify("Encrypted workspace unlocked for this session");
    } catch (workspaceFailure) {
      setWorkspaceError(workspaceFailure instanceof Error ? workspaceFailure.message : "Workspace unlock failed.");
    }
  };

  const importRecoveryPackage = async (file: File | undefined) => {
    if (!file) return;
    setWorkspaceError("");
    try {
      if (file.size > 256_000) throw new Error("Recovery package is unexpectedly large.");
      vault.importRecoveryPackage(JSON.parse(await file.text()));
      notify("Recovery package imported into this browser");
    } catch (importFailure) {
      setWorkspaceError(importFailure instanceof Error ? importFailure.message : "Recovery package import failed.");
    }
  };

  const createSecondAdminRequest = async () => {
    setWorkspaceError("");
    try {
      await vault.createSecondAdminRequest(secondAdminOrganizationId, secondAdminPassword);
      setSecondAdminPassword("");
      notify("Encrypted recovery-admin request downloaded");
    } catch (requestFailure) {
      setWorkspaceError(requestFailure instanceof Error ? requestFailure.message : "Recovery-admin request failed.");
    }
  };

  const addSecondAdministrator = async (file: File | undefined) => {
    if (!file) return;
    setWorkspaceError("");
    try {
      if (file.size > 256_000) throw new Error("Recovery-admin request is unexpectedly large.");
      await vault.addSecondAdministrator(JSON.parse(await file.text()));
      notify("Second recovery administrator added with an encrypted vault-key grant");
    } catch (grantFailure) {
      setWorkspaceError(grantFailure instanceof Error ? grantFailure.message : "Second-admin grant failed.");
    }
  };

  const rotateVaultKeys = async () => {
    setWorkspaceError("");
    try {
      await vault.rotateVault(
        rotationPassword,
        revokePrincipalId.trim() ? [revokePrincipalId.trim()] : [],
      );
      setRotationPassword("");
      setRevokePrincipalId("");
      setShowVaultSecurity(false);
      notify("Vault keys rotated and a new recovery package downloaded");
    } catch (rotationFailure) {
      setWorkspaceError(rotationFailure instanceof Error ? rotationFailure.message : "Vault rotation failed.");
    }
  };

  const confirmRecoverySaved = async () => {
    setWorkspaceError("");
    try {
      await vault.confirmRecoverySaved();
      notify("Recovery package confirmed. Production payroll is now enabled.");
    } catch (recoveryFailure) {
      setWorkspaceError(recoveryFailure instanceof Error ? recoveryFailure.message : "Recovery confirmation failed.");
    }
  };

  const exportPayrollHistory = () => {
    if (!vault.session) {
      setFormError("Unlock the encrypted workspace before exporting private payroll history.");
      return;
    }
    const exportBody = {
      format: "payo-private-run-history-v1",
      organizationId: vault.session.organizationId,
      generatedAt: new Date().toISOString(),
      privacyWarning: "This locally generated file contains decrypted aggregate payroll totals. Store it securely.",
      runs: payrollRuns.map((run) => ({
        ...run,
        totals: { STRK: run.totals.STRK.toString(), USDC: run.totals.USDC.toString() },
      })),
    };
    const blob = new Blob([`${JSON.stringify(exportBody, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `payo-private-runs-${vault.session.organizationId}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    notify("Private payroll history exported locally");
  };

  const latestRun = payrollRuns[0] ?? null;
  const confirmedRuns = payrollRuns.filter(({ state }) => ["confirmed", "reconciled"].includes(state));
  const resolvedRuns = payrollRuns.filter(({ state }) =>
    ["confirmed", "reconciled", "failed", "cancelled", "disputed"].includes(state));
  const successfulRuns = resolvedRuns.filter(({ state }) => ["confirmed", "reconciled"].includes(state));
  const paidTotals = confirmedRuns.reduce<Record<PayrollTokenSymbol, bigint>>((totals, run) => ({
    STRK: totals.STRK + run.totals.STRK,
    USDC: totals.USDC + run.totals.USDC,
  }), { STRK: 0n, USDC: 0n });
  const plannedRuns = payrollRuns
    .filter(({ state, dueAt }) => runCategory(state) === "Pending" && new Date(dueAt).getTime() >= dashboardNow)
    .sort((left, right) => new Date(left.dueAt).getTime() - new Date(right.dueAt).getTime());

  return (
    <div className="product-page payroll-page">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--blue">PAYROLL DESK</span>
          <h2>Plan it once.<br /><em>Pay privately.</em></h2>
          <p>Prepare salaries for people and agents, review the batch, and settle through STRK20 without publishing everyone’s compensation.</p>
        </div>
        <div className="page-heading__actions">
          <button type="button" className="button button--soft" onClick={exportPayrollHistory} disabled={!vault.session || payrollRuns.length === 0}><Download size={17} /> Export private report</button>
          <button type="button" className="button button--ink" onClick={openPayroll}><Play size={17} /> Run payroll</button>
        </div>
      </section>

      <section className="private-payroll-runner reveal reveal--two" id="private-payroll">
        <div className="runner-heading">
          <div><span className="sticker sticker--yellow">LIVE · MAINNET</span><h3>Private payroll runner</h3><p>Run private STRK or native USDC payroll with passive live fee reserves and proof-bound PAYO enforcement.</p></div>
          <div className="runner-network"><span className={starknet.isConnected && starknet.isMainnet ? "connection-dot connection-dot--live" : "connection-dot"} /><span><small>Payroll signer</small><strong>{starknet.isConnected ? `${starknet.walletName} · ${starknet.networkName}` : "Ready not connected"}</strong></span></div>
        </div>

        <div className={`vault-gate ${vault.session ? "vault-gate--ready" : ""}`}>
          <span className="vault-gate__icon">{vault.session ? <LockKeyhole size={21} /> : <KeyRound size={21} />}</span>
          {!vault.configured ? (
            <div className="vault-gate__copy"><small>ENCRYPTED WORKSPACE</small><strong>Ready authentication is unavailable</strong><p>Restore the PAYO server and Starknet RPC configuration before storing production payroll records.</p></div>
          ) : !vault.ready || vault.loading ? (
            <div className="vault-gate__copy"><small>ENCRYPTED WORKSPACE</small><strong>Opening the private desk…</strong><p>Keys remain in this browser session.</p></div>
          ) : !vault.authenticated ? (
            <><div className="vault-gate__copy"><small>ENCRYPTED WORKSPACE</small><strong>{starknet.isConnected ? "Authorize this Ready account" : "Connect Ready to open payroll"}</strong><p>Ready signs a short-lived PAYO session. Salaries are still encrypted locally before storage.</p></div>{starknet.isConnected ? <button type="button" className="button button--ink" disabled={!starknet.isMainnet} onClick={authorizePayo}>Authorize with Ready</button> : <Link className="button button--ink" href="/wallet">Connect Ready</Link>}</>
          ) : vault.organizations.length === 0 ? (
            <>
              <div className="vault-gate__copy"><small>{vault.selectedOrganizationId ? "RECOVER EXISTING WORKSPACE" : "NEW ENCRYPTED WORKSPACE"}</small><strong>{vault.selectedOrganizationId ? "Link this Ready account securely" : "Create your private payroll vault"}</strong><p>{vault.selectedOrganizationId ? "The imported recovery key proves access without sending it to PAYO." : "A recovery file downloads once. PAYO cannot reset a lost vault password."}</p></div>
              <div className="vault-gate__form">
                {!vault.selectedOrganizationId ? (
                  <>
                    <input value={workspaceName} maxLength={160} placeholder="Organization name" aria-label="Organization name" onChange={(event) => setWorkspaceName(event.target.value)} />
                    <div className="vault-gate__field">
                      <input
                        type="password"
                        value={recoveryPassword}
                        minLength={MIN_RECOVERY_PASSWORD_LENGTH}
                        maxLength={1024}
                        autoComplete="new-password"
                        placeholder="Recovery password"
                        aria-label="New vault recovery password"
                        aria-describedby="workspace-password-help"
                        aria-invalid={recoveryPassword.length > 0 && recoveryPassword.length < MIN_RECOVERY_PASSWORD_LENGTH}
                        onChange={(event) => {
                          setRecoveryPassword(event.target.value);
                          setWorkspaceError("");
                        }}
                      />
                      <span id="workspace-password-help" className={`vault-gate__hint ${recoveryPassword.length >= MIN_RECOVERY_PASSWORD_LENGTH ? "vault-gate__hint--ready" : ""}`} aria-live="polite">
                        {recoveryPassword.length === 0
                          ? "Use at least 12 characters. It cannot be reset."
                          : recoveryPassword.length < MIN_RECOVERY_PASSWORD_LENGTH
                            ? `${recoveryPassword.length}/12 characters · add ${MIN_RECOVERY_PASSWORD_LENGTH - recoveryPassword.length} more.`
                            : `${recoveryPassword.length} characters · ready.`}
                      </span>
                    </div>
                    <button type="button" className="button button--ink" disabled={vault.loading} onClick={createWorkspace}>Create &amp; download</button>
                    <span className="label">OR RECOVER AN EXISTING WORKSPACE</span>
                    <label className="button button--soft vault-gate__import">Import recovery<input type="file" accept="application/json,.json" onChange={(event) => { void importRecoveryPackage(event.target.files?.[0]); event.currentTarget.value = ""; }} /></label>
                  </>
                ) : (
                  <>
                    <span className="label">EXISTING RECOVERY IMPORTED · {vault.selectedOrganizationId.slice(0, 8)}</span>
                    <p>Enter its password to prove vault-key control and link this Ready account. The password and secret key stay in this browser.</p>
                    <input type="password" value={recoveryPassword} minLength={12} maxLength={1024} autoComplete="current-password" placeholder="Existing recovery password" aria-label="Existing vault recovery password" onChange={(event) => setRecoveryPassword(event.target.value)} />
                    <button type="button" className="button button--ink" disabled={recoveryPassword.length < 12 || vault.loading} onClick={unlockWorkspace}>Verify recovery &amp; link Ready</button>
                    <label className="button button--soft vault-gate__import">Choose another recovery<input type="file" accept="application/json,.json" onChange={(event) => { void importRecoveryPackage(event.target.files?.[0]); event.currentTarget.value = ""; }} /></label>
                  </>
                )}
                <span className="label">OR JOIN AS RECOVERY ADMIN</span>
                <input value={secondAdminOrganizationId} placeholder="Organization UUID" aria-label="Organization ID for recovery-admin request" onChange={(event) => setSecondAdminOrganizationId(event.target.value)} />
                <input type="password" value={secondAdminPassword} minLength={12} maxLength={1024} autoComplete="new-password" placeholder="Your recovery password · 12+" aria-label="Second administrator recovery password" onChange={(event) => setSecondAdminPassword(event.target.value)} />
                <button type="button" className="button button--soft" disabled={!secondAdminOrganizationId.trim() || secondAdminPassword.length < 12 || vault.loading} onClick={createSecondAdminRequest}>Download admin request</button>
              </div>
            </>
          ) : !vault.session ? (
            <>
              <div className="vault-gate__copy"><small>WORKSPACE LOCKED</small><strong>Unlock locally to prepare payroll</strong><p>The password and decrypted vault key are never sent to PAYO.</p></div>
              <div className="vault-gate__form vault-gate__form--unlock">
                {vault.organizations.length > 1 && <select value={vault.selectedOrganizationId} aria-label="PAYO organization" onChange={(event) => vault.selectOrganization(event.target.value)}>{vault.organizations.map((organization) => <option value={organization.id} key={organization.id}>{organization.id.slice(0, 8)} · {organization.role}</option>)}</select>}
                <input type="password" value={recoveryPassword} minLength={12} maxLength={1024} autoComplete="current-password" placeholder="Recovery password" aria-label="Vault recovery password" onChange={(event) => setRecoveryPassword(event.target.value)} />
                <button type="button" className="button button--ink" disabled={recoveryPassword.length < 12 || vault.loading} onClick={unlockWorkspace}>Unlock</button>
                <label className="button button--soft vault-gate__import">Import recovery<input type="file" accept="application/json,.json" onChange={(event) => { void importRecoveryPackage(event.target.files?.[0]); event.currentTarget.value = ""; }} /></label>
              </div>
            </>
          ) : !vault.recoveryReady ? (
            <><div className="vault-gate__copy"><small>RECOVERY CONFIRMATION REQUIRED</small><strong>Keep the downloaded recovery file somewhere safe</strong><p>Production payroll stays locked until you confirm the encrypted package was saved.</p></div><div className="vault-gate__actions"><button type="button" className="button button--soft" onClick={vault.downloadRecoveryPackage}>Download again</button><button type="button" className="button button--ink" onClick={confirmRecoverySaved}>I saved it securely</button><button type="button" className="button button--soft" onClick={vault.lockWorkspace}>Lock</button></div></>
          ) : (
            <><div className="vault-gate__copy"><small>ENCRYPTED WORKSPACE · UNLOCKED</small><strong>Private records stay client-encrypted</strong><p>{selectedOrganization?.recoveryState === "second_admin" ? "Second-admin recovery is active." : "Recovery package is configured."} Plaintext payroll exists only in this browser session.</p></div><div className="vault-gate__actions">{selectedOrganization?.role === "admin" && selectedOrganization.recoveryState !== "second_admin" && <label className="button button--soft vault-gate__import">Add recovery admin<input type="file" accept="application/json,.json" onChange={(event) => { void addSecondAdministrator(event.target.files?.[0]); event.currentTarget.value = ""; }} /></label>}{selectedOrganization?.role === "admin" && <button type="button" className="button button--soft" onClick={() => setShowVaultSecurity((current) => !current)}>Rotate / revoke</button>}<button type="button" className="button button--soft" onClick={vault.lockWorkspace}>Lock workspace</button></div>{showVaultSecurity && selectedOrganization?.role === "admin" && <div className="vault-gate__form"><span className="label">FRESH DEK ROTATION</span><input type="password" value={rotationPassword} minLength={12} maxLength={1024} autoComplete="new-password" placeholder="New recovery password · 12+" aria-label="New vault rotation password" onChange={(event) => setRotationPassword(event.target.value)} /><input value={revokePrincipalId} placeholder="Optional principal ID to revoke" aria-label="Principal ID to revoke during key rotation" onChange={(event) => setRevokePrincipalId(event.target.value)} /><p>Every latest record is re-encrypted locally. A revoked administrator is removed in the same database transaction.</p><button type="button" className="button button--ink" disabled={rotationPassword.length < 12 || vault.loading} onClick={rotateVaultKeys}>Rotate keys &amp; download</button></div>}</>
          )}
          {(workspaceError || vault.error) && <p className="vault-gate__error">{workspaceError || vault.error}</p>}
        </div>

        <div className="runner-grid">
          <aside className="runner-setup">
            <div className={`runner-step ${starknet.isConnected ? "runner-step--done" : "runner-step--active"}`}>
              <span className="runner-step-number">1</span>
              <div><small>CONNECT SIGNER</small><strong>{starknet.isConnected ? shortStarknetAddress(starknet.address) : "Connect Ready wallet"}</strong><p>Ready holds the STRK20 privacy keys and asks for every approval.</p>{!starknet.isConnected && <Link className="button button--ink button--wide" href="/wallet">Connect Ready <WalletCards size={16} /></Link>}{starknet.isConnected && !starknet.isMainnet && <button type="button" className="button button--ink button--wide" onClick={() => starknet.switchToMainnet().catch((switchError) => setFormError(switchError instanceof Error ? switchError.message : "Network switch failed"))}>Switch to Mainnet</button>}</div>
            </div>

            <div className={`runner-step ${starknet.isConnected && starknet.isMainnet ? "runner-step--active" : ""}`}>
              <span className="runner-step-number">2</span>
              <div>
                <small>FUND PRIVATE TREASURY</small>
                <strong>{treasuryLabel}</strong>
                <p>{treasuryHelp}</p>
                {registrationRequired ? (
                  <a className="button button--soft button--wide" href={STRK20_SETUP_URL} target="_blank" rel="noreferrer">Register STRK20 account <ExternalLink size={15} /></a>
                ) : balanceUnavailable ? (
                  <Link className="button button--soft button--wide" href="/wallet">Retry on Wallet page <ArrowRight size={15} /></Link>
                ) : (
                  <>
                    <div className="token-switch" role="group" aria-label="Token to shield">
                      {(["STRK", "USDC"] as PayrollTokenSymbol[]).map((token) => (
                        <button type="button" key={token} className={shieldToken === token ? "token-switch__item token-switch__item--active" : "token-switch__item"} onClick={() => { setShieldToken(token); setShieldAmount(""); }} disabled={busy || !PAYROLL_TOKENS[token].privacyEnabled} title={!PAYROLL_TOKENS[token].privacyEnabled ? "Awaiting live STRK20 pool compatibility test" : undefined}>
                          <span>{token === "STRK" ? "S" : "$"}</span>{token}{!PAYROLL_TOKENS[token].privacyEnabled ? " · SOON" : ""}
                        </button>
                      ))}
                    </div>
                    <label className="amount-field">
                      <span>Total</span>
                      <input inputMode="decimal" value={shieldAmount} placeholder={shieldToken === "STRK" ? "e.g. 10" : "e.g. 100"} onChange={(event) => setShieldAmount(event.target.value)} aria-label={`Total ${shieldToken} to use for shielding`} />
                      <b>{shieldToken}</b>
                    </label>
                    <div className={`shield-quote ${shieldQuote.isValid ? "shield-quote--ready" : ""} ${shieldQuote.shortfall > 0n ? "shield-quote--insufficient" : ""}`}>
                      <div className="shield-quote__heading"><span>LIVE SHIELD QUOTE</span><i>{isQuotingShield || starknet.isRefreshingPublicBalance ? "Reading Mainnet…" : shieldFeeQuote?.exact ? "Pool verified" : shieldFeeQuote ? "Live estimate" : "Mainnet live"}</i></div>
                      <div className="shield-quote__row"><span>Public {shieldToken} balance</span><strong>{formatTokenAmount(starknet.publicBalances[shieldToken], shieldToken)} {shieldToken}</strong></div>
                      <div className="shield-quote__row"><span>Total {shieldToken}</span><strong>{formatTokenAmount(shieldQuote.grossAmount, shieldToken)} {shieldToken}</strong></div>
                      <div className="shield-quote__row"><span>{shieldQuote.exact ? "STRK20 Mainnet fee" : "Conservative fee reserve"}</span><strong>{shieldQuote.walletFee === null ? "—" : `− ${formatTokenAmount(shieldQuote.walletFee, shieldToken)} ${shieldToken}`}</strong></div>
                      <div className="shield-quote__row shield-quote__row--net"><span>{shieldQuote.exact ? "Arrives shielded" : "Estimated shielded"}</span><strong>{shieldQuote.netAmount !== null && shieldQuote.netAmount > 0n ? formatTokenAmount(shieldQuote.netAmount, shieldToken) : "0"} {shieldToken}</strong></div>
                      <p>{starknet.publicBalanceError ? <>Wallet balance unavailable. <button type="button" onClick={() => starknet.refreshPublicBalance().catch((balanceError) => setFormError(balanceError instanceof Error ? balanceError.message : "Balance refresh failed"))}>Retry</button></> : shieldQuote.shortfall > 0n ? `Insufficient ${shieldToken} · short by ${formatTokenAmount(shieldQuote.shortfall, shieldToken)} ${shieldToken}.` : shieldQuoteError ? shieldQuoteError : isQuotingShield ? "Reading the public STRK20 fee and paymaster price. Ready will not open for a quote." : shieldFeeQuote?.exact ? "Read directly from the STRK20 Mainnet pool. Ready opens only after you click Shield." : shieldFeeQuote ? "Based on the live pool fee and AVNU token price with a safety buffer. Ready shows the final reserve before approval." : "Enter an amount to read the live fee without opening Ready."}</p>
                    </div>
                    <button type="button" className="button button--soft button--wide" disabled={!starknet.isConnected || !starknet.isMainnet || !shieldQuote.isValid || starknet.publicBalances[shieldToken] === null || busy || privacyChecking || privacyUnsupported || isQuotingShield || starknet.isRefreshingPublicBalance} onClick={shieldTreasury}>{starknet.transaction?.kind === "shield" && busy ? <><LoaderCircle className="spin" size={16} /> {starknet.transaction.stage === "wallet" ? "Approve in Ready" : "Confirming"}</> : shieldQuote.shortfall > 0n ? <>Insufficient balance</> : <><ShieldCheck size={16} /> Shield {shieldQuote.isValid ? `${shieldQuote.exact ? "" : "~"}${formatTokenAmount(shieldQuote.netAmount, shieldToken)} ${shieldToken}` : "treasury"}</>}</button>
                  </>
                )}
              </div>
            </div>

            <div className="runner-step runner-step--quiet">
              <span className="runner-step-number">3</span>
              <div><small>PRIVATE BATCH</small><strong>One wallet request</strong><p>Recipient addresses and amounts become STRK20 transfer actions inside one payroll request.</p></div>
            </div>
          </aside>

          <div className="payroll-composer">
            <div className="composer-top"><div><span className="label">DUE AGREEMENTS</span><h4>Which obligations settle?</h4></div><Link className="button button--soft" href="/team">Manage agreements <ArrowRight size={15} /></Link></div>
            <div className="recipient-labels"><span>Recipient</span><span>Starknet address</span><span>Private amount</span><span /></div>
            <div className="recipient-list">
              {dueObligations.map(({ agreement, payee }, index) => {
                const selected = selectedAgreementIds.includes(agreement.id);
                const total = agreement.agreement.earningsAtomic.reduce((sum, amount) => sum + BigInt(amount), 0n);
                const planLabel = agreement.agreement.agreementVersion === "payo-agreement-v2"
                  ? agreement.agreement.termination
                    ? "Final pay"
                    : agreement.agreement.paymentPlan.kind === "checkpoint_stream"
                      ? "Checkpoint stream"
                      : agreement.agreement.paymentPlan.kind === "private_vesting"
                        ? "Private vesting"
                        : agreement.agreement.paymentPlan.kind === "milestone"
                          ? "Approved milestone"
                          : "Advanced recurring"
                  : "Recurring";
                return (
                <div className={`recipient-editor ${selected ? "recipient-editor--selected" : "recipient-editor--excluded"}`} key={agreement.id}>
                  <span className="recipient-index">{index + 1}</span>
                  <label><span>{planLabel}</span><input value={payee.displayName} readOnly /></label>
                  <label className="recipient-address"><span>Registered Starknet address</span><input value={payee.recipientAddress} spellCheck={false} readOnly /></label>
                  <label className="recipient-amount"><span>Committed amount</span><input value={formatTokenAmount(total, agreement.agreement.settlementToken)} readOnly /><select value={agreement.agreement.settlementToken} aria-label={`Committed token for recipient ${index + 1}`} disabled><option value={agreement.agreement.settlementToken}>{agreement.agreement.settlementToken}</option></select></label>
                  <button type="button" className="recipient-remove" aria-label={`${selected ? "Exclude" : "Include"} ${payee.displayName}`} disabled={busy} onClick={() => toggleAgreement(agreement.id)}>{selected ? <CheckCircle2 size={15} /> : <X size={15} />}</button>
                </div>
              );})}
              {payeesMissingAgreements.map((payee, index) => (
                <div className="recipient-editor recipient-editor--setup" key={`setup-${payee.id}`}>
                  <span className="recipient-index">{dueObligations.length + index + 1}</span>
                  <label><span>Contributor</span><input value={payee.displayName} readOnly /></label>
                  <label className="recipient-address"><span>Registered Starknet address</span><input value={payee.recipientAddress} spellCheck={false} readOnly /></label>
                  <span className="recipient-setup-status"><small>Setup required</small><strong>No pay agreement</strong></span>
                  <Link className="button button--soft recipient-setup-action" href="/team#team-directory">Set agreement</Link>
                </div>
              ))}
              {!runsLoading && vault.session && dueObligations.length === 0 && (
                <div className="directory-empty payroll-empty-guide">
                  <CalendarDays size={24} />
                  <strong>{!hasActivePayee ? "Add a payroll recipient" : !hasActiveAgreement ? "Add their private pay agreement" : scheduleSyncError ? "Payroll schedule unavailable" : locallyDueObligations.length > 0 ? "Preparing due agreements" : "No agreement is due yet"}</strong>
                  <p>{!hasActivePayee
                    ? "PAYO sends from proof-bound agreements, so the first payment starts with a registered recipient."
                    : !hasActiveAgreement
                      ? "The recipient exists. Commit their amount, token, classification, cadence, and first due time."
                      : scheduleSyncError
                        ? `Your encrypted recipients and agreements are safe, but the durable scheduler could not synchronize them: ${scheduleSyncError}`
                        : locallyDueObligations.length > 0
                          ? "The agreements are due and waiting for the durable scheduler. Retry synchronization instead of creating duplicate recipients."
                          : "The agreements exist, but their committed next-due times are still in the future."}</p>
                  <ol aria-label="Private payroll setup progress">
                    <li className={hasActivePayee ? "payroll-empty-guide__done" : "payroll-empty-guide__current"}><b>1</b> Add recipient</li>
                    <li className={hasActiveAgreement ? "payroll-empty-guide__done" : hasActivePayee ? "payroll-empty-guide__current" : ""}><b>2</b> Add pay agreement</li>
                    <li className={hasActiveAgreement ? "payroll-empty-guide__current" : ""}><b>3</b> Authorize &amp; send</li>
                  </ol>
                  {scheduleSyncError && hasActiveAgreement
                    ? <button className="button button--ink" type="button" onClick={() => void refreshPayrollRuns()} disabled={runsLoading}>{runsLoading ? <LoaderCircle className="spin" size={15} /> : null} Retry schedule sync <ArrowRight size={15} /></button>
                    : <Link className="button button--ink" href="/team#team-directory">
                        {!hasActivePayee ? "Add first recipient" : !hasActiveAgreement ? "Add pay agreement" : "Review due time"} <ArrowRight size={15} />
                      </Link>}
                </div>
              )}
            </div>

            <div className="recipient-note"><ShieldCheck size={17} /><span><strong>Authoritative proof-bound obligations</strong><small>Amounts, recipient salts, schedule commitments, classifications, and policy roots come from the encrypted agreements. They cannot be edited inside a payroll run. Active policy, FX, obligation, and verifier roots are required before Ready can open.</small></span></div>
            <div className="obligation-root-control">
              <span>
                <strong>{registryTransactionBusy
                  ? starknet.transaction?.stage === "wallet" ? "Ready approval requested" : "Authorization confirming"
                  : obligationAuthorizationActionPending
                    ? "Preparing authorization"
                    : obligationSchedule?.state === "active"
                      ? "Obligation root active"
                      : obligationSchedule?.state === "scheduled"
                        ? "Activation confirming"
                        : "Activate before payroll"}</strong>
                <small>{registryTransactionBusy
                  ? starknet.transaction?.stage === "wallet"
                    ? "Approve the single obligation-root transaction in Ready."
                    : "The authorization transaction was submitted to Mainnet."
                  : obligationAuthorizationActionPending
                    ? "Preparing the exact selected agreement root before opening Ready."
                    : obligationSchedule?.state === "active"
                      ? "The selected encrypted agreement set is authorized on-chain."
                      : obligationSchedule?.validAfter
                        ? `Submitted at ${new Date(obligationSchedule.validAfter * 1_000).toLocaleString()}. Changing the selection creates a different root.`
                        : "The registry administrator can authorize this exact encrypted agreement set immediately in one transaction."}</small>
              </span>
              <button
                type="button"
                className="button button--soft"
                disabled={!vault.session || !starknet.isConnected || !starknet.isMainnet || selectedObligations.length === 0 || busy}
                onClick={scheduleSelectedObligationRoot}
              >
                {registryTransactionBusy
                  ? <><LoaderCircle className="spin" size={15} /> {starknet.transaction?.stage === "wallet" ? "Approve in Ready" : "Confirming"}</>
                  : obligationAuthorizationActionPending
                    ? <><LoaderCircle className="spin" size={15} /> Preparing</>
                    : obligationSchedule?.state === "active"
                      ? <>Check again <ShieldCheck size={15} /></>
                      : <>Authorize batch <Clock3 size={15} /></>}
              </button>
            </div>

            <div className="composer-summary">
              <div><small>{selectedProofProfile}</small><strong>{selectedObligations.length} selected</strong></div><div><small>Private total</small><strong>{`${formatTokenAmount(payrollTotals.STRK, "STRK")} STRK · ${formatTokenAmount(payrollTotals.USDC, "USDC")} USDC`}</strong></div><div><small>Shielded treasury</small><strong>{formatTokenAmount(starknet.shieldedBalances.STRK, "STRK")} STRK · {formatTokenAmount(starknet.shieldedBalances.USDC, "USDC")} USDC</strong></div>
              {dueObligations.length === 0 ? (
                scheduleSyncError && hasActiveAgreement
                  ? <button className="button button--ink" type="button" onClick={() => void refreshPayrollRuns()} disabled={runsLoading}>Retry schedule sync <ArrowRight size={17} /></button>
                  : <Link className="button button--ink" href="/team#team-directory">{hasActiveAgreement ? "Review due time" : "Set up first payment"} <ArrowRight size={17} /></Link>
              ) : (
                <button
                  type="button"
                  className="button button--ink"
                  disabled={!vault.session || !vault.recoveryReady || !starknet.isConnected || !starknet.isMainnet || busy || Boolean(recoverableSubmission) || selectedObligations.length === 0 || (obligationSchedule?.state === "active" && !canRunPayroll)}
                  onClick={obligationSchedule?.state === "active" ? submitPayroll : scheduleSelectedObligationRoot}
                >
                  {payrollStage && payrollStage !== "queued" && payrollStage !== "recorded"
                    ? <><LoaderCircle className="spin" size={17} /> {payrollStageLabel[payrollStage]}</>
                    : registryTransactionBusy
                      ? <><LoaderCircle className="spin" size={17} /> {starknet.transaction?.stage === "wallet" ? "Approve authorization in Ready" : "Confirming authorization"}</>
                      : obligationAuthorizationActionPending
                        ? <><LoaderCircle className="spin" size={17} /> Preparing Ready authorization</>
                      : recoverableSubmission
                        ? <>Finishing previous payroll <Clock3 size={17} /></>
                      : starknet.transaction?.kind === "payroll" && walletTransactionBusy
                        ? <><LoaderCircle className="spin" size={17} /> {starknet.transaction.stage === "wallet" ? "Approve in Ready" : "Confirming on Mainnet"}</>
                        : !vault.session
                          ? <>Unlock workspace <KeyRound size={17} /></>
                          : !vault.recoveryReady
                            ? <>Confirm recovery <KeyRound size={17} /></>
                            : selectedObligations.length === 0
                              ? <>Select a due agreement <CalendarDays size={17} /></>
                              : obligationSchedule?.state !== "active"
                                ? <>Authorize batch in Ready <ShieldCheck size={17} /></>
                                : <>Prove &amp; approve payroll <ArrowRight size={17} /></>}
                </button>
              )}
            </div>

            {formError && <div className="runner-error"><X size={16} /><span>{formError}</span></div>}
            {proofDeliveryNotice && (
              <div className="transaction-receipt transaction-receipt--confirmed">
                <span className="transaction-receipt-icon"><CheckCircle2 size={20} /></span>
                <span><small>PRIVATE PAYMENT RECORDED</small><strong>Wallet submission recorded</strong><p>{proofDeliveryNotice}</p></span>
              </div>
            )}
            {recoverableSubmission && (recoveryMode === "action_required" || recoveryMode === "recording_required") && (
              <div className="runner-error runner-recovery">
                <Clock3 size={16} />
                <span>
                  <strong>{recoverableSubmission.transactionHash ? "Transaction awaiting durable recording" : "Ready approval did not complete"}</strong>
                  <p>{recoverableSubmission.transactionHash
                    ? "PAYO has the hash. Resume idempotent recording; never submit the payroll again."
                    : "PAYO kept the encrypted settlement safe and is checking Mainnet automatically. If Ready shows no submitted transaction, cancel this approval. Use hash recovery only for a transaction visible in Ready history."}</p>
                  {!recoverableSubmission.transactionHash && showManualHashRecovery && (
                    <input
                      value={recoveryTransactionHash}
                      onChange={(event) => setRecoveryTransactionHash(event.target.value)}
                      placeholder="0x… transaction hash from Ready"
                      aria-label="Ready payroll transaction hash"
                      spellCheck={false}
                    />
                  )}
                </span>
                <div className="runner-recovery__actions">
                  {recoverableSubmission.transactionHash ? (
                    <button
                      type="button"
                      className="button button--soft"
                      onClick={() => void resumePayrollRecording()}
                    >Resume recording</button>
                  ) : showManualHashRecovery ? (
                    <>
                      <button
                        type="button"
                        className="button button--soft"
                        disabled={!/^0x[0-9a-fA-F]{1,64}$/.test(recoveryTransactionHash.trim())}
                        onClick={() => void resumePayrollRecording()}
                      >Record submitted hash</button>
                      <button
                        type="button"
                        className="button button--soft"
                        onClick={() => { setShowManualHashRecovery(false); setRecoveryTransactionHash(""); }}
                      >Hide hash recovery</button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="button button--soft"
                      onClick={() => setShowManualHashRecovery(true)}
                    >I see a submitted transaction</button>
                  )}
                  {!recoverableSubmission.transactionHash && (
                    <button
                      type="button"
                      className="button button--soft"
                      disabled={starknet.transaction?.stage === "wallet" || starknet.transaction?.stage === "confirming"}
                      onClick={cancelPendingPayrollApproval}
                    >No transaction · cancel</button>
                  )}
                </div>
              </div>
            )}
            {payrollStage && !formError && (
              <div className={`transaction-receipt transaction-receipt--${payrollStage === "queued" || payrollStage === "recorded" ? "confirmed" : "confirming"}`}>
                <span className="transaction-receipt-icon">{payrollStage === "queued" || payrollStage === "recorded" ? <CheckCircle2 size={20} /> : <LoaderCircle className="spin" size={19} />}</span>
                <span><small>PAYROLLINTEGRITY · TWO SHARDS{selfHostedProverUrl ? " · SELF-HOSTED PROVER" : ""}</small><strong>{payrollStageLabel[payrollStage]}</strong><p>{payrollStage === "queued" ? "The settlement is durable; the relayer will verify both proof shards after finality." : payrollStage === "recorded" ? "The wallet payment and settlement record are complete; proof delivery is handled separately and will never request the payment again." : selfHostedProverUrl ? "The encrypted request is opened only in your authenticated self-hosted prover's volatile memory; no wallet key is shared." : "Salary inputs stay encrypted while PAYO prepares the proof-bound settlement."}</p></span>
                {payrollReceipt && <a href={`${STARKNET_MAINNET_EXPLORER}/tx/${payrollReceipt.transactionHash}`} target="_blank" rel="noreferrer">View receipt <ExternalLink size={13} /></a>}
              </div>
            )}
            {starknet.transaction && (
              <div className={`transaction-receipt transaction-receipt--${starknet.transaction.stage}`}>
                <span className="transaction-receipt-icon">{starknet.transaction.stage === "confirmed" ? <CheckCircle2 size={20} /> : starknet.transaction.stage === "failed" ? <X size={19} /> : <LoaderCircle className="spin" size={19} />}</span>
                <span><small>{starknet.transaction.stage === "wallet" ? starknet.transaction.kind === "registry" ? "READY IS REQUESTING ADMIN APPROVAL" : "READY IS PREPARING THE PROOF" : starknet.transaction.stage === "confirming" ? "SUBMITTED TO MAINNET" : starknet.transaction.stage === "confirmed" ? "TRANSACTION CONFIRMED" : "TRANSACTION NEEDS ATTENTION"}</small><strong>{starknet.transaction.label}</strong>{starknet.transaction.kind === "shield" && starknet.transaction.grossAmount !== undefined && starknet.transaction.walletFee !== undefined && starknet.transaction.token && <p>{`${starknet.transaction.feeQuoteExact ? "" : "Pre-approval estimate · "}${formatTokenAmount(starknet.transaction.grossAmount, starknet.transaction.token)} ${starknet.transaction.token} total − ${formatTokenAmount(starknet.transaction.walletFee, starknet.transaction.feeToken ?? starknet.transaction.token)} ${starknet.transaction.feeToken ?? starknet.transaction.token} private fee = ${formatTokenAmount(starknet.transaction.netAmount ?? null, starknet.transaction.token)} ${starknet.transaction.token} shielded.`}</p>}{starknet.transaction.kind === "payroll" && starknet.transaction.totals && starknet.transaction.feeReserves && <p>{(["STRK", "USDC"] as PayrollTokenSymbol[]).filter((token) => (starknet.transaction?.totals?.[token] ?? 0n) > 0n).map((token) => `${formatTokenAmount(starknet.transaction?.totals?.[token] ?? null, token)} ${token} payroll + up to ${formatTokenAmount(starknet.transaction?.feeReserves?.[token] ?? null, token)} ${token} fee eligibility reserve`).join(" · ")}. Ready charges exactly one selected fee token for the whole atomic payroll, never both.</p>}{starknet.transaction.stage === "wallet" && <p>PAYO sent one request. Rejecting it leaves a durable approval that can be safely cancelled after Ready closes.</p>}{starknet.transaction.error && <p>{starknet.transaction.error}</p>}</span>
                {starknet.transaction.hash && <a href={`${STARKNET_MAINNET_EXPLORER}/tx/${starknet.transaction.hash}`} target="_blank" rel="noreferrer">View receipt <ExternalLink size={13} /></a>}
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="payroll-stage-card reveal reveal--three">
        <div className="payroll-stage__copy">
          <div className="stage-status"><span /> {latestRun ? runStateLabel(latestRun.state).toUpperCase() : "NO PRIVATE RUNS"}</div>
          <h3>{latestRun?.cycleId ?? "Your first payroll"}</h3>
          <p>{latestRun ? `${latestRun.recipientCount} encrypted ${latestRun.recipientCount === 1 ? "recipient" : "recipients"}. Due ${runDate(latestRun.dueAt)}. No salary data was read by the server.` : "Create a proof-bound payroll above. Its encrypted manifest and durable status will appear here."}</p>
          <div className="stage-people" aria-label={latestRun ? `${latestRun.recipientCount} encrypted recipients` : "No recipients"}>
            {Array.from({ length: Math.min(latestRun?.recipientCount ?? 0, 6) }, (_, index) => (
              <span className="stage-person" key={index}><LockKeyhole size={13} /></span>
            ))}
            {(latestRun?.recipientCount ?? 0) > 6 && <b>+{latestRun!.recipientCount - 6}</b>}
          </div>
          <div className="stage-run-actions">
            <Link className="button button--ink" href={latestRun ? "/activity" : "#private-payroll"}>{latestRun ? "Open durable activity" : "Prepare first run"} <ArrowRight size={17} /></Link>
            {latestRun?.state === "proven" && !latestRun.transactionHash && (
              <>
                <button
                  type="button"
                  className="button button--soft"
                  disabled={recoveringRunId === latestRun.id}
                  onClick={() => void recoverSealedRun(latestRun)}
                >
                  {recoveringRunId === latestRun.id ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />}
                  Recover sealed submission
                </button>
                <button
                  type="button"
                  className="button button--soft"
                  disabled={busy || releasingRunId === latestRun.id || recoveringRunId === latestRun.id}
                  onClick={() => void releaseUnsubmittedRun(latestRun)}
                >
                  {releasingRunId === latestRun.id ? <LoaderCircle className="spin" size={15} /> : <X size={15} />}
                  Release only if never submitted
                </button>
              </>
            )}
          </div>
        </div>

        <div className="payday-calendar" aria-hidden="true">
          <span className="calendar-spark calendar-spark--one">✦</span>
          <span className="calendar-spark calendar-spark--two">✦</span>
          <div className="calendar-rings"><i /><i /><i /></div>
          <div className="calendar-top">{latestRun ? runDate(latestRun.dueAt, { month: "long" }).toUpperCase() : "PAYDAY"}</div>
          <strong>{latestRun ? runDate(latestRun.dueAt, { day: "numeric" }) : "—"}</strong>
          <span>{latestRun ? `${runDate(latestRun.dueAt, { weekday: "long" }).toUpperCase()} · PRIVATE` : "AWAITING A RUN"}</span>
          <div className="calendar-face"><i /><i /><b /></div>
          <div className="calendar-feet"><i /><i /></div>
        </div>

        <div className="payroll-stage__summary">
          <div><span>Encrypted total</span><strong>{latestRun ? `${formatTokenAmount(latestRun.totals.STRK, "STRK")} STRK` : "—"}</strong><small>{latestRun ? `${formatTokenAmount(latestRun.totals.USDC, "USDC")} native USDC` : "Locally decrypted only"}</small></div>
          <div className="stage-summary-row"><span><Users size={15} /> Recipients</span><b>{latestRun?.recipientCount ?? 0}</b></div>
          <div className="stage-summary-row"><span><ShieldCheck size={15} /> State</span><b>{latestRun ? runStateLabel(latestRun.state) : "None"}</b></div>
          <div className="stage-summary-row"><span><CalendarDays size={15} /> Due</span><b>{latestRun ? runDate(latestRun.dueAt, { month: "short", day: "numeric" }) : "—"}</b></div>
          <div className="funds-check"><CheckCircle2 size={17} /><span><strong>{latestRun?.transactionHash ? "Transaction recorded" : "No public amount exposed"}</strong><small>{latestRun?.transactionHash ? shortStarknetAddress(latestRun.transactionHash) : "Totals stay in the encrypted manifest"}</small></span></div>
        </div>
      </section>

      <section className="payroll-stats reveal reveal--four">
        <article className="mini-stat mini-stat--yellow">
          <span className="mini-stat__icon"><CircleDollarSign size={18} /></span>
          <div><small>Confirmed private value</small><strong>{formatTokenAmount(paidTotals.STRK, "STRK")} STRK</strong><em>{formatTokenAmount(paidTotals.USDC, "USDC")} native USDC</em></div>
        </article>
        <article className="mini-stat mini-stat--blue">
          <span className="mini-stat__icon"><Users size={18} /></span>
          <div><small>Latest recipients</small><strong>{latestRun?.recipientCount ?? 0}</strong><em>From locally decrypted manifest</em></div>
        </article>
        <article className="mini-stat mini-stat--green">
          <span className="mini-stat__icon"><ShieldCheck size={18} /></span>
          <div><small>Resolved success</small><strong>{resolvedRuns.length ? `${Math.floor(successfulRuns.length * 100 / resolvedRuns.length)}%` : "—"}</strong><em>{resolvedRuns.length ? `${successfulRuns.length} of ${resolvedRuns.length} resolved runs` : "No resolved runs yet"}</em></div>
        </article>
      </section>

      <section className="runs-section reveal reveal--five">
        <div className="section-heading">
          <div><span className="label">THE PAPER TRAIL</span><h3>Payroll runs</h3></div>
          <div className="filter-tabs" role="tablist" aria-label="Filter payroll runs">
            {filters.map((item) => (
              <button type="button" role="tab" aria-selected={filter === item} className={filter === item ? "filter-tab filter-tab--active" : "filter-tab"} key={item} onClick={() => setFilter(item)}>{item}</button>
            ))}
          </div>
        </div>

        <div className="runs-card">
          <div className="table-head"><span>Payroll</span><span>Recipients</span><span>Status</span><span>Total</span><span /></div>
          {visibleRuns.map((run, index) => (
            <button type="button" className="run-row" key={run.id} disabled={recoveringRunId === run.id} onClick={() => run.state === "proven" && !run.transactionHash ? void recoverSealedRun(run) : notify(`Run ${run.cycleId} · ${runStateLabel(run.state)}`)}>
              <span className={`run-mark run-mark--${["coral", "blue", "green", "yellow"][index % 4]}`}>{run.cycleId.slice(0, 3).toUpperCase()}</span>
              <span className="run-name"><strong>{run.cycleId}</strong><small>{run.state === "proven" && !run.transactionHash ? "Tap to recover its canonical sealed transaction" : `Due ${runDate(run.dueAt)} · updated ${runDate(run.updatedAt)}`}</small></span>
              <span className="run-recipients">{run.recipientCount} encrypted {run.recipientCount === 1 ? "recipient" : "recipients"}</span>
              <span className={`run-status run-status--${runCategory(run.state).toLowerCase().replace("attention", "draft")}`}><i />{runStateLabel(run.state)}</span>
              <strong className="run-amount">{formatTokenAmount(run.totals.STRK, "STRK")} STRK · {formatTokenAmount(run.totals.USDC, "USDC")} USDC</strong>
              {recoveringRunId === run.id ? <LoaderCircle className="run-more spin" size={18} /> : run.state === "proven" && !run.transactionHash ? <ShieldCheck className="run-more" size={18} /> : <MoreHorizontal className="run-more" size={18} />}
            </button>
          ))}
          {runsLoading && <div className="empty-row"><LoaderCircle className="spin" size={21} /><strong>Opening encrypted payroll history</strong><span>Manifests are decrypted only in this browser.</span></div>}
          {!runsLoading && visibleRuns.length === 0 && <div className="empty-row"><Sparkles size={21} /><strong>No payrolls here yet.</strong><span>{payrollRuns.length ? "Try a different status." : "The first durable private run will appear here."}</span></div>}
        </div>
      </section>

      <section className="rhythm-card reveal reveal--five">
        <div className="rhythm-icon"><Clock3 size={24} /><span>↻</span></div>
        <div><span className="label">DURABLE SCHEDULE</span><h3>{plannedRuns.length ? `${plannedRuns.length} upcoming private ${plannedRuns.length === 1 ? "run" : "runs"}.` : "No upcoming run is stored."}</h3><p>{plannedRuns.length ? plannedRuns.slice(0, 3).map(({ cycleId, dueAt }) => `${cycleId} · ${runDate(dueAt, { month: "short", day: "numeric" })}`).join("  ·  ") : "Create a payroll when the next obligation becomes due."}</p></div>
        <button type="button" className="button button--soft" onClick={openPayroll}><PencilLine size={16} /> Prepare payroll</button>
      </section>
    </div>
  );
}
