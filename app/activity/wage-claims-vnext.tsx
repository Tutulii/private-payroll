"use client";

import {
  ShieldAlert,
  CheckCircle2,
  FileText,
  LoaderCircle,
  ShieldCheck,
  WalletCards,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { usePayoVault } from "@/app/vault/payo-vault";
import { useStarknetWallet } from "@/app/starknet/starknet-wallet";
import type { ExceptionClaimKind } from "@/lib/domain/exception-protocol";
import type {
  ObligationClaimAccessGrantSummary,
  ObligationSnapshotPlanSummary,
} from "@/lib/domain/obligation-snapshot-plan";
import type {
  EmployerStatementSummary,
  PayrollStatementEvidenceGrantSummary,
} from "@/lib/domain/employer-statement";
import type { WorkerClaimSummary } from "@/lib/domain/worker-claim";
import type { WageRemediationSummary } from "@/lib/domain/wage-remediation";
import {
  prepareStoredWorkerClaimV2,
  prepareWorkerClaimV2,
  proveAndSubmitWorkerClaimV2,
} from "@/lib/client/worker-claim";
import {
  minimumWageRemediationAmount,
  openAcceptedWorkerClaimV2,
  prepareStoredWageRemediationV2,
  prepareWageRemediationV2,
  proveAndAuthorizeWageRemediationV2,
} from "@/lib/client/wage-remediation";
import {
  authorizeStoredExceptionProof,
  waitForExceptionAuthorization,
} from "@/lib/client/exception-proof-recovery";
import {
  cancelAuthorizedRemediationPayment,
  executeAuthorizedRemediationPayment,
} from "@/lib/client/remediation-payment";
import {
  prepareDurableEmployerStatementForPayroll,
  registerDurableEmployerStatement,
} from "@/lib/client/employer-statement";
import { formatTokenAmount, PAYROLL_TOKENS } from "@/lib/starknet/tokens";

const claimKinds = [
  ["missing_obligation", "Missing obligation"],
  ["below_committed_floor", "Below FX floor"],
  ["incomplete_final_pay", "Incomplete final pay"],
] as const satisfies readonly (readonly [ExceptionClaimKind, string])[];

function shortId(value: string) {
  return value.length > 16 ? value.slice(0, 8) + "…" + value.slice(-5) : value;
}

function workflowError(error: unknown) {
  return error instanceof Error ? error.message : "The private wage workflow could not be completed.";
}

function claimLabel(kind: ExceptionClaimKind) {
  return claimKinds.find(([value]) => value === kind)?.[1] ?? "Private wage exception";
}

function dedupe<T extends { id: string }>(items: readonly T[]) {
  return [...new Map(items.map((item) => [item.id, item])).values()];
}

function sameCommitment(left: string, right: string | null) {
  if (!right) return false;
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

type EmployerPayrollRun = {
  id: string;
  state: string;
  transactionHash: string | null;
  fxRoot: string | null;
};

export function WageClaimsVNextCard() {
  const vault = usePayoVault();
  const starknet = useStarknetWallet();
  const [grants, setGrants] = useState<ObligationClaimAccessGrantSummary[]>([]);
  const [statementEvidence, setStatementEvidence] = useState<PayrollStatementEvidenceGrantSummary[]>([]);
  const [workerClaims, setWorkerClaims] = useState<WorkerClaimSummary[]>([]);
  const [employerClaims, setEmployerClaims] = useState<WorkerClaimSummary[]>([]);
  const [remediations, setRemediations] = useState<WageRemediationSummary[]>([]);
  const [snapshotPlans, setSnapshotPlans] = useState<ObligationSnapshotPlanSummary[]>([]);
  const [employerStatements, setEmployerStatements] = useState<EmployerStatementSummary[]>([]);
  const [employerRuns, setEmployerRuns] = useState<EmployerPayrollRun[]>([]);
  const [evidenceNow, setEvidenceNow] = useState(() => Date.now());
  const [loading, setLoading] = useState(false);
  const [activeId, setActiveId] = useState("");
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [remediationFeedbackId, setRemediationFeedbackId] = useState("");

  const organization = vault.organizations.find(({ id }) =>
    id === vault.session?.organizationId);
  const employerMode = organization?.role === "admin" || organization?.role === "operator";

  const refresh = useCallback(async () => {
    if (!vault.client || !vault.session || !vault.authenticated) {
      setGrants([]);
      setStatementEvidence([]);
      setWorkerClaims([]);
      setEmployerClaims([]);
      setRemediations([]);
      setSnapshotPlans([]);
      setEmployerStatements([]);
      setEmployerRuns([]);
      return;
    }
    setLoading(true);
    setError("");
    try {
      const client = vault.client;
      const organizationId = vault.session.organizationId;
      const [accessResult, evidenceResult, ownedClaimsResult, ownedRemediationsResult] =
        await Promise.all([
          client.listObligationClaimAccessGrants(),
          client.listPayrollStatementEvidence(),
          client.listWorkerClaims(),
          client.listWageRemediations(),
        ]);
      let organizationClaims: WorkerClaimSummary[] = [];
      let organizationRemediations: WageRemediationSummary[] = [];
      let organizationPlans: ObligationSnapshotPlanSummary[] = [];
      let organizationStatements: EmployerStatementSummary[] = [];
      let organizationRuns: EmployerPayrollRun[] = [];
      if (employerMode) {
        const [claims, remediationRows, plans, statements, runs] = await Promise.all([
          client.listWorkerClaims(organizationId).then((result) => result.claims),
          client.listWageRemediations(organizationId).then((result) => result.remediations),
          client.listObligationSnapshotPlans(organizationId).then((result) => result.plans),
          client.listEmployerStatements(organizationId).then((result) => result.statements),
          client.listPayrollRuns(organizationId).then((result) => result.runs),
        ]);
        organizationClaims = claims;
        organizationRemediations = remediationRows;
        organizationPlans = plans;
        organizationStatements = statements;
        organizationRuns = runs.flatMap((run) =>
          typeof run.id === "string" && typeof run.state === "string"
            ? [{
                id: run.id,
                state: run.state,
                transactionHash: typeof run.transactionHash === "string"
                  ? run.transactionHash
                  : null,
                fxRoot: typeof run.fxRoot === "string" ? run.fxRoot : null,
              }]
            : []);
      }
      setGrants(accessResult.grants);
      setStatementEvidence(evidenceResult.evidence);
      setWorkerClaims(ownedClaimsResult.claims);
      setEmployerClaims(organizationClaims);
      setRemediations(dedupe([
        ...ownedRemediationsResult.remediations,
        ...organizationRemediations,
      ]));
      setSnapshotPlans(organizationPlans);
      setEmployerStatements(organizationStatements);
      setEmployerRuns(organizationRuns);
      setEvidenceNow(Date.now());
    } catch (cause) {
      setError(workflowError(cause));
    } finally {
      setLoading(false);
    }
  }, [employerMode, vault.authenticated, vault.client, vault.session]);

  useEffect(() => {
    const timer = globalThis.setTimeout(() => void refresh(), 0);
    return () => globalThis.clearTimeout(timer);
  }, [refresh]);

  const requireRuntime = () => {
    if (!vault.client || !vault.session) throw new Error("Unlock your PAYO vault first.");
    if (!starknet.isConnected || !starknet.isMainnet || !starknet.chainId) {
      throw new Error("Connect Ready on Starknet Mainnet first.");
    }
    const sealAddress = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS?.trim();
    const proverBaseUrl = process.env.NEXT_PUBLIC_PAYO_PROVER_URL?.trim();
    const bookSealAddress = process.env.NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS?.trim();
    if (!sealAddress) throw new Error("The PAYO exception seal is not configured.");
    if (!proverBaseUrl) throw new Error("The private PAYO prover is not configured.");
    if (!bookSealAddress) throw new Error("The universal PAYO payroll-book seal is not configured.");
    return {
      client: vault.client,
      principal: vault.session.principal,
      chainId: starknet.chainId,
      sealAddress,
      bookSealAddress,
      proverBaseUrl,
    };
  };

  const finishAuthorization = async (proofBundleId: string) => {
    const { client } = requireRuntime();
    setStage("Waiting for on-chain verifier authorization");
    await waitForExceptionAuthorization({
      client,
      proofBundleId,
      onPoll: (authorization) => setStage(
        authorization.transactionHash
          ? "Confirming verifier authorization"
          : "Relayer is submitting the ZK proof",
      ),
    });
  };

  const submitWorkerClaim = async (
    grant: ObligationClaimAccessGrantSummary,
    kind: ExceptionClaimKind,
    existing?: WorkerClaimSummary,
  ) => {
    setActiveId(existing?.id ?? grant.id + ":" + kind);
    setError("");
    setSuccess("");
    try {
      const runtime = requireRuntime();
      const prepared = existing
        ? await prepareStoredWorkerClaimV2({
            claim: existing,
            grant,
            statementEvidence,
            chainId: runtime.chainId,
            sealAddress: runtime.sealAddress,
            principal: runtime.principal,
          })
        : await prepareWorkerClaimV2({
            grant,
            statementEvidence,
            claimKind: kind,
            chainId: runtime.chainId,
            sealAddress: runtime.sealAddress,
            principal: runtime.principal,
          });
      await proveAndSubmitWorkerClaimV2({
        client: runtime.client,
        prepared,
        principal: runtime.principal,
        proverBaseUrl: runtime.proverBaseUrl,
        bookSealAddress: runtime.bookSealAddress,
        onStage: (value) => setStage({
          persisting_claim: "Saving the worker-owned claim",
          proving: "Generating Claim v6 ZK proof",
          persisting_proof: "Encrypting the proof for worker and employer",
          authorizing: "Queuing on-chain verifier authorization",
        }[value]),
      });
      await finishAuthorization(prepared.create.proofBundleId);
      setSuccess(claimLabel(kind) + " accepted on-chain. No salary or claim type was published.");
      await refresh();
    } catch (cause) {
      const message = workflowError(cause);
      await refresh();
      setError(message);
    } finally {
      setActiveId("");
      setStage("");
    }
  };

  const resumeWorkerClaim = async (claim: WorkerClaimSummary) => {
    const grant = grants.find(({ id }) => id === claim.claimAccessGrantId);
    if (!grant) {
      setError("The worker-owned claim access packet for this claim is unavailable.");
      return;
    }
    if (claim.state === "prepared") {
      let kind: ExceptionClaimKind = "missing_obligation";
      try {
        const runtime = requireRuntime();
        const prepared = await prepareStoredWorkerClaimV2({
          claim,
          grant,
          statementEvidence,
          chainId: runtime.chainId,
          sealAddress: runtime.sealAddress,
          principal: runtime.principal,
        });
        kind = prepared.privateRecord.claimKind;
      } catch (cause) {
        setError(workflowError(cause));
        return;
      }
      await submitWorkerClaim(grant, kind, claim);
      return;
    }
    setActiveId(claim.id);
    setError("");
    setSuccess("");
    try {
      const runtime = requireRuntime();
      setStage("Reloading the encrypted Claim v6 proof");
      await authorizeStoredExceptionProof({
        client: runtime.client,
        proofBundleId: claim.proofBundleId,
        principal: runtime.principal,
      });
      await finishAuthorization(claim.proofBundleId);
      setSuccess("Claim v6 authorization recovered and accepted on-chain.");
      await refresh();
    } catch (cause) {
      const message = workflowError(cause);
      await refresh();
      setError(message);
    } finally {
      setActiveId("");
      setStage("");
    }
  };

  const createRemediation = async (claimSummary: WorkerClaimSummary) => {
    setActiveId(claimSummary.id);
    setError("");
    setSuccess("");
    try {
      const runtime = requireRuntime();
      setStage("Opening the accepted encrypted claim");
      const acceptedClaim = openAcceptedWorkerClaimV2({
        claim: claimSummary,
        principal: runtime.principal,
      });
      let fxSnapshots;
      if (acceptedClaim.claimKind === "below_committed_floor") {
        setStage("Reading fresh private-remediation FX");
        fxSnapshots = (await runtime.client.getFxSnapshots([
          acceptedClaim.claimFact.obligationToken,
        ])).snapshots;
      }
      const selectedFxIndex = fxSnapshots?.findIndex((snapshot) =>
        snapshot.baseToken === acceptedClaim.claimFact.obligationToken
        && snapshot.referenceCurrency.toLowerCase()
          === acceptedClaim.claimFact.shortfallUnit.slice(0, 3));
      if (fxSnapshots && (selectedFxIndex === undefined || selectedFxIndex < 0)) {
        throw new Error("A matching fresh FX snapshot is unavailable for this accepted claim.");
      }
      const amountAtomic = minimumWageRemediationAmount({
        acceptedClaim,
        ...(fxSnapshots ? { fxSnapshot: fxSnapshots[selectedFxIndex!] } : {}),
      });
      const prepared = await prepareWageRemediationV2({
        acceptedClaim,
        claimState: "accepted",
        organizationId: claimSummary.organizationId,
        runId: claimSummary.runId,
        chainId: runtime.chainId,
        sealAddress: runtime.sealAddress,
        amountAtomic,
        token: acceptedClaim.claimFact.obligationToken,
        fxSnapshots,
        selectedFxIndex,
        principal: runtime.principal,
      });
      await proveAndAuthorizeWageRemediationV2({
        client: runtime.client,
        prepared,
        principal: runtime.principal,
        proverBaseUrl: runtime.proverBaseUrl,
        bookSealAddress: runtime.bookSealAddress,
        onStage: (value) => setStage({
          persisting_remediation: "Saving the exact remediation action",
          proving: "Generating Remediation v7 ZK proof",
          persisting_proof: "Encrypting the remediation proof",
          authorizing: "Queuing on-chain remediation authorization",
        }[value]),
      });
      await finishAuthorization(prepared.create.proofBundleId);
      setSuccess("Remediation v7 authorized. Ready can now settle exactly one bound private payment.");
      await refresh();
    } catch (cause) {
      const message = workflowError(cause);
      await refresh();
      setError(message);
    } finally {
      setActiveId("");
      setStage("");
    }
  };

  const continueRemediation = async (remediation: WageRemediationSummary) => {
    setActiveId(remediation.id);
    setRemediationFeedbackId(remediation.id);
    setError("");
    setSuccess("");
    try {
      const runtime = requireRuntime();
      if (remediation.state === "prepared") {
        const claimSummary = employerClaims.find(({ id }) =>
          id === remediation.workerClaimId);
        if (!claimSummary) throw new Error("The accepted Claim v6 record is unavailable.");
        const acceptedClaim = openAcceptedWorkerClaimV2({
          claim: claimSummary,
          principal: runtime.principal,
        });
        const prepared = await prepareStoredWageRemediationV2({
          remediation,
          acceptedClaim,
          chainId: runtime.chainId,
          sealAddress: runtime.sealAddress,
          principal: runtime.principal,
        });
        await proveAndAuthorizeWageRemediationV2({
          client: runtime.client,
          prepared,
          principal: runtime.principal,
          proverBaseUrl: runtime.proverBaseUrl,
          bookSealAddress: runtime.bookSealAddress,
          onStage: (value) => setStage(value === "proving"
            ? "Generating Remediation v7 ZK proof"
            : "Recovering the durable remediation"),
        });
        await finishAuthorization(remediation.proofBundleId);
        setSuccess("Remediation v7 proof recovered and authorized.");
      } else if (["proved", "authorization_pending", "failed"].includes(remediation.state)) {
        setStage("Reloading the encrypted Remediation v7 proof");
        await authorizeStoredExceptionProof({
          client: runtime.client,
          proofBundleId: remediation.proofBundleId,
          principal: runtime.principal,
        });
        await finishAuthorization(remediation.proofBundleId);
        setSuccess("Remediation v7 authorization completed.");
      } else if (remediation.state === "authorized" || remediation.state === "payment_pending") {
        starknet.assertPrivateActionAvailable();
        const result = await executeAuthorizedRemediationPayment({
          client: runtime.client,
          remediation,
          principal: runtime.principal,
          sealAddress: runtime.sealAddress,
          bookSealAddress: runtime.bookSealAddress,
          chainId: runtime.chainId,
          prepareSubmit: starknet.prepareProofBoundException,
          onStage: (value) => setStage({
            loading: "Checking exact authorized payment",
            recording: "Saving the private payment intent",
            wallet: "Approve one private payment in Ready",
            submitted: "Payment submitted; confirmation is automatic",
          }[value]),
        });
        setSuccess("Private remediation submitted · " + shortId(result.transactionHash));
      }
      await refresh();
    } catch (cause) {
      const message = workflowError(cause);
      await refresh();
      setError(message);
    } finally {
      setActiveId("");
      setStage("");
    }
  };

  const cancelRemediationPayment = async (remediation: WageRemediationSummary) => {
    setActiveId(remediation.id);
    setRemediationFeedbackId(remediation.id);
    setError("");
    setSuccess("");
    setStage("Cancelling the unsigned Ready request");
    try {
      const { client } = requireRuntime();
      await cancelAuthorizedRemediationPayment({ client, remediation });
      setSuccess(
        "Unsigned Ready request cancelled. The authorized remediation can be retried safely.",
      );
      await refresh();
    } catch (cause) {
      const message = workflowError(cause);
      await refresh();
      setError(message);
    } finally {
      setActiveId("");
      setStage("");
    }
  };


  const registerPayrollEvidence = async (
    plan: ObligationSnapshotPlanSummary,
  ) => {
    const actionId = "statement:" + plan.id;
    setActiveId(actionId);
    setError("");
    setSuccess("");
    try {
      if (!employerMode || !vault.client || !vault.session) {
        throw new Error("Unlock an employer PAYO vault first.");
      }
      if (!starknet.isConnected || !starknet.isMainnet || !starknet.address) {
        throw new Error("Connect the snapshot-owner Ready wallet on Starknet Mainnet.");
      }
      if (BigInt(starknet.address) !== BigInt(plan.ownerAddress)) {
        throw new Error(
          "The connected Ready wallet does not own this protected payday.",
        );
      }
      setStage("Validating confirmed payroll and encrypted worker evidence");
      const durable = await prepareDurableEmployerStatementForPayroll({
        client: vault.client,
        organizationId: vault.session.organizationId,
        runId: plan.runId,
        snapshotPlanId: plan.id,
        principal: vault.session.principal,
      });
      if (durable.stored.state === "prepared") {
        setStage("Ensuring the confirmed payroll FX root is active");
        await vault.client.renewHistoricalFxRoot({
          organizationId: vault.session.organizationId,
          runId: plan.runId,
          workflowType: "employer_statement",
        });
      }
      setStage(
        durable.stored.state === "submitted"
          ? "Checking the recorded Mainnet registration"
          : "Approve one employer-evidence registration in Ready",
      );
      const registered = await registerDurableEmployerStatement({
        client: vault.client,
        stored: durable.stored,
        statement: durable.statement,
        statementCommitment: durable.statementCommitment,
        registerStatement: starknet.registerEmployerStatement,
      });
      setSuccess(
        registered.recovered
          ? "Employer evidence recovered and verified on-chain."
          : "Employer evidence registered. Workers can now test FX-floor and final-pay claims.",
      );
      await refresh();
    } catch (cause) {
      const message = workflowError(cause);
      await refresh();
      setError(message);
    } finally {
      setActiveId("");
      setStage("");
    }
  };

  const workerClaimsByGrant = useMemo(() => new Map(
    grants.map((grant) => [grant.id, workerClaims.filter((claim) =>
      claim.claimAccessGrantId === grant.id)]),
  ), [grants, workerClaims]);
  const activeRemediationByClaim = useMemo(() => new Map(
    employerClaims.map((claim) => [claim.id, remediations.find((row) =>
      row.workerClaimId === claim.id && !["expired", "reconciled"].includes(row.state))]),
  ), [employerClaims, remediations]);


  const employerRunById = useMemo(
    () => new Map(employerRuns.map((run) => [run.id, run])),
    [employerRuns],
  );
  const confirmedEvidencePlans = useMemo(
    () => snapshotPlans.filter((plan) => {
      const run = employerRunById.get(plan.runId);
      return plan.state === "consumed"
        && Boolean(run?.transactionHash)
        && ["confirmed", "reconciled", "disputed"].includes(run?.state ?? "");
    }),
    [employerRunById, snapshotPlans],
  );
  const employerStatementByRun = useMemo(() => {
    const sorted = [...employerStatements].sort((left, right) => {
      const priority = (state: EmployerStatementSummary["state"]) =>
        state === "registered" ? 3 : state === "submitted" ? 2 : state === "prepared" ? 1 : 0;
      return priority(right.state) - priority(left.state);
    });
    const exact = new Map<string, EmployerStatementSummary>();
    for (const run of employerRuns) {
      const statement = sorted.find((candidate) =>
        candidate.runId === run.id && sameCommitment(candidate.fxRoot, run.fxRoot));
      if (statement) exact.set(run.id, statement);
    }
    return exact;
  }, [employerRuns, employerStatements]);

  if (!vault.session || !vault.authenticated) {
    return <section className="receipts-card wage-vnext-card">
      <span className="label">WAGE PROTECTION vNEXT</span>
      <h3>Worker-owned claims.<br />Employer-bound fixes.</h3>
      <p>Sign in with Ready and unlock your own PAYO vault. A worker never needs access to the employer&apos;s organization vault.</p>
    </section>;
  }

  return <section className="receipts-card wage-vnext-card">
    <div className="wage-vnext-heading">
      <div><span className="label">WAGE PROTECTION vNEXT</span><h3>Claim v6 → Remediation v7</h3></div>
      <button type="button" className="button button--soft" onClick={() => void refresh()} disabled={loading || Boolean(activeId)}>
        {loading ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />} Refresh
      </button>
    </div>
    <p>Claim type, salary, recipient, token and amount stay encrypted. Starknet receives only bounded commitments and nullifiers.</p>
    {stage && <p className="private-exception-feedback private-exception-feedback--progress" role="status"><LoaderCircle className="spin" size={14} /> {stage}</p>}
    {error && <p className="private-exception-feedback private-exception-feedback--error" role="alert"><ShieldAlert size={14} /> {error}</p>}
    {success && <p className="private-exception-feedback private-exception-feedback--success" role="status"><CheckCircle2 size={14} /> {success}</p>}

    <div className="wage-vnext-section">
      <div className="wage-vnext-section__title"><FileText size={17} /><span><small>WORKER</small><strong>Your protected paydays</strong></span></div>
      {grants.length === 0 && <p className="wage-vnext-empty">No worker-owned claim packet is available for this PAYO identity.</p>}
      {grants.map((grant) => {
        const existing = workerClaimsByGrant.get(grant.id) ?? [];
        return <article className="wage-vnext-item" key={grant.id}>
          <div><small>Payday {new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date(grant.plan.dueAt))}</small><strong>{shortId(grant.id)}</strong><span>{grant.plan.state} snapshot · claim until {new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date(grant.plan.claimEndsAt))}</span></div>
          {existing.length === 0 && <div className="wage-vnext-actions">
            {claimKinds.map(([kind, label]) => <button type="button" key={kind} onClick={() => void submitWorkerClaim(grant, kind)} disabled={Boolean(activeId) || grant.revokedAt !== null}>
              {activeId === grant.id + ":" + kind ? <LoaderCircle className="spin" size={14} /> : <ShieldCheck size={14} />} {label}
            </button>)}
          </div>}
          {existing.map((claim) => <div className="wage-vnext-state" key={claim.id}>
            <span><strong>Claim {shortId(claim.id)}</strong><small>{claim.state.replaceAll("_", " ")}</small></span>
            {claim.state !== "accepted" && <button type="button" onClick={() => void resumeWorkerClaim(claim)} disabled={Boolean(activeId)}>{activeId === claim.id ? <LoaderCircle className="spin" size={14} /> : <ShieldCheck size={14} />} Resume</button>}
            {claim.state === "accepted" && <i><CheckCircle2 size={13} /> On-chain accepted</i>}
          </div>)}
        </article>;
      })}
    </div>


    {employerMode && <div className="wage-vnext-section">
      <div className="wage-vnext-section__title"><FileText size={17} /><span><small>EMPLOYER EVIDENCE</small><strong>Confirmed protected payrolls</strong></span></div>
      <p>Register one encrypted statement per confirmed payday. This exposes only commitments and gives each worker their own FX-floor and final-pay evidence packet.</p>
      {confirmedEvidencePlans.length === 0 && <p className="wage-vnext-empty">No confirmed vNext payroll is waiting for employer evidence.</p>}
      {confirmedEvidencePlans.map((plan) => {
        const statement = employerStatementByRun.get(plan.runId);
        const actionId = "statement:" + plan.id;
        const expired = new Date(plan.claimEndsAt).getTime() < evidenceNow;
        return <article className="wage-vnext-item" key={plan.id}>
          <div>
            <small>Protected payday {new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date(plan.dueAt))}</small>
            <strong>{statement?.state === "registered" ? "Worker evidence registered" : "Worker evidence required"}</strong>
            <span>Run {shortId(plan.runId)} · {statement?.state.replaceAll("_", " ") ?? "not prepared"}</span>
          </div>
          {statement?.state === "registered"
            ? <i><CheckCircle2 size={13} /> On-chain registered</i>
            : statement?.state === "failed"
              ? <i><ShieldAlert size={13} /> Registration failed</i>
              : <button
                  type="button"
                  onClick={() => void registerPayrollEvidence(plan)}
                  disabled={Boolean(activeId) || expired}
                  title={expired ? "This payday's private claim window has expired." : undefined}
                >
                  {activeId === actionId ? <LoaderCircle className="spin" size={14} /> : <ShieldCheck size={14} />}
                  {statement?.state === "submitted"
                    ? "Check registration"
                    : statement?.state === "prepared"
                      ? "Resume Ready registration"
                      : "Register payroll evidence"}
                </button>}
        </article>;
      })}
    </div>}

    {employerMode && <div className="wage-vnext-section">
      <div className="wage-vnext-section__title"><WalletCards size={17} /><span><small>EMPLOYER</small><strong>Accepted claims &amp; private fixes</strong></span></div>
      {employerClaims.filter(({ state }) => state === "accepted").length === 0 && <p className="wage-vnext-empty">No accepted Claim v6 is waiting for remediation.</p>}
      {employerClaims.filter(({ state }) => state === "accepted").map((claim) => {
        const remediation = activeRemediationByClaim.get(claim.id);
        let readable = "Encrypted accepted claim";
        try {
          const opened = openAcceptedWorkerClaimV2({ claim, principal: vault.session!.principal });
          const amount = opened.claimKind === "below_committed_floor"
            ? (Number(opened.claimFact.shortfallAtomic) / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 6 })
              + " " + opened.claimFact.shortfallUnit.slice(0, 3).toUpperCase()
            : formatTokenAmount(
                BigInt(opened.claimFact.shortfallAtomic),
                PAYROLL_TOKENS[opened.claimFact.obligationToken],
              ) + " " + opened.claimFact.obligationToken;
          readable = claimLabel(opened.claimKind) + " · " + amount;
        } catch { /* The action fails closed if this employer is not an envelope recipient. */ }
        return <article className="wage-vnext-item" key={claim.id}>
          <div><small>Accepted Claim v6</small><strong>{readable}</strong><span>Claim {shortId(claim.id)}</span></div>
          {!remediation && <button type="button" onClick={() => void createRemediation(claim)} disabled={Boolean(activeId)}>{activeId === claim.id ? <LoaderCircle className="spin" size={14} /> : <ShieldCheck size={14} />} Prove exact remediation</button>}
          {remediation && <div className="wage-vnext-state">
            <span><strong>Remediation {shortId(remediation.id)}</strong><small>{remediation.state.replaceAll("_", " ")}</small></span>
            {["prepared", "proved", "authorization_pending", "failed", "authorized", "payment_pending"].includes(remediation.state) && <button type="button" onClick={() => void continueRemediation(remediation)} disabled={Boolean(activeId)}>{activeId === remediation.id ? <LoaderCircle className="spin" size={14} /> : remediation.state === "authorized" || remediation.state === "payment_pending" ? <WalletCards size={14} /> : <ShieldCheck size={14} />} {remediation.state === "authorized" ? "Pay privately" : remediation.state === "payment_pending" ? "Recover Ready payment" : "Resume"}</button>}
            {remediation.state === "payment_pending" && <button type="button" className="button button--soft" onClick={() => void cancelRemediationPayment(remediation)} disabled={Boolean(activeId)}>Cancel unsigned request</button>}
            {remediation.state === "payment_confirmed" && <i><CheckCircle2 size={13} /> Payment confirmed · reconciliation evidence pending</i>}
            {remediation.state === "reconciled" && <i><CheckCircle2 size={13} /> Payment reconciled</i>}
            {remediationFeedbackId === remediation.id && stage && <p className="private-exception-feedback private-exception-feedback--progress" role="status"><LoaderCircle className="spin" size={14} /> {stage}</p>}
            {remediationFeedbackId === remediation.id && error && <p className="private-exception-feedback private-exception-feedback--error" role="alert"><ShieldAlert size={14} /> {error}</p>}
            {remediationFeedbackId === remediation.id && success && <p className="private-exception-feedback private-exception-feedback--success" role="status"><CheckCircle2 size={14} /> {success}</p>}
          </div>}
        </article>;
      })}
    </div>}
  </section>;
}
