"use client";

import { ShieldCheck, WalletCards } from "lucide-react";
import type { ReactNode } from "react";
import type { WorkerClaimSummary } from "@/lib/domain/worker-claim";
import type { WageRemediationSummary } from "@/lib/domain/wage-remediation";
import { ResultCard, ResultDetails, ResultFacts, ResultNextStep, ResultNote, type ResultStatusTone } from "./report-results";

type StatusSummary = { label: string; tone: ResultStatusTone; explanation: string; next: string };

const claimStatuses: Record<WorkerClaimSummary["state"], StatusSummary> = {
  prepared: { label: "Ready to prove", tone: "neutral", explanation: "Your encrypted claim is saved. Its proof still needs to be generated and submitted.", next: "Continue the claim to generate its proof and submit it for verification." },
  proved: { label: "Proof created", tone: "pending", explanation: "The claim proof has been generated. On-chain acceptance is still pending.", next: "Continue to submit or check the claim’s on-chain verification." },
  authorization_pending: { label: "Awaiting verification", tone: "pending", explanation: "The claim is waiting for on-chain verification. It has not been accepted yet.", next: "Check the claim again to retrieve its verification result." },
  accepted: { label: "Claim accepted on-chain", tone: "success", explanation: "The wage claim has been accepted on-chain. The employer can now prepare a private corrective payment.", next: "Ask the employer to review this accepted claim and prepare the corrective payment." },
  rejected: { label: "Claim rejected", tone: "error", explanation: "This claim was rejected. A corrective payment has not been authorized by this claim.", next: "Review the claim’s evidence and verification details before trying again." },
};

const paymentStatuses: Record<WageRemediationSummary["state"], StatusSummary> = {
  prepared: { label: "Payment proof needed", tone: "neutral", explanation: "A corrective payment has been prepared for the accepted claim. Its proof is still needed.", next: "Continue to prove the corrective payment." },
  proved: { label: "Payment proof created", tone: "pending", explanation: "The payment proof is ready. On-chain authorization is still pending.", next: "Continue to submit or check the payment authorization." },
  authorization_pending: { label: "Awaiting authorization", tone: "pending", explanation: "The corrective payment is waiting for on-chain authorization. Payment is not yet confirmed.", next: "Check the authorization again before making the private payment." },
  authorized: { label: "Ready for payment", tone: "pending", explanation: "The corrective payment is authorized. This record does not yet confirm a completed payment.", next: "Choose “Pay privately” and approve the payment in Ready." },
  payment_pending: { label: "Payment confirmation pending", tone: "pending", explanation: "A Ready payment request exists. This record is still waiting for confirmed payment evidence.", next: "Use “Recover Ready payment” to check the existing request. If it was never signed, you can cancel that unsigned request." },
  payment_confirmed: { label: "Payment confirmed", tone: "success", explanation: "The corrective payment is confirmed. Reconciliation evidence is still pending.", next: "Refresh the record to check when reconciliation evidence becomes available." },
  reconciled: { label: "Payment reconciled", tone: "success", explanation: "The corrective payment is confirmed and its reconciliation evidence is recorded.", next: "Keep this record with the original claim for your payroll records." },
  expired: { label: "Authorization expired", tone: "error", explanation: "This payment authorization has expired. This record does not confirm a completed payment.", next: "Review the claim and payment history before preparing a fresh authorization." },
  failed: { label: "Needs attention", tone: "error", explanation: "This corrective payment needs attention. Review the recorded error and the existing payment status.", next: "Resume this record to recover its proof, authorization or payment state." },
};

export function WageClaimResultCard({ claim, audience, issue, amount, children }: {
  claim: WorkerClaimSummary;
  audience: "worker" | "employer";
  issue?: string;
  amount?: string;
  children?: ReactNode;
}) {
  const status = claimStatuses[claim.state];
  return <ResultCard kind="wage-claim" tone="claim" audience={audience === "worker" ? "Worker claim" : "Employer review"}
    title={issue ?? "Your private wage claim"} description={status.explanation} status={status.label} statusTone={status.tone} icon={ShieldCheck}>
    <ResultFacts items={[
      { label: "Claim status", value: status.label },
      ...(amount ? [{ label: "Verified shortfall", value: amount }] : []),
      { label: "Payment", value: "Tracked separately from claim acceptance" },
    ]} />
    {children}
    <ResultNextStep>{claim.state === "accepted" && audience === "employer" ? "Choose “Prove exact remediation” to prepare a private payment for this accepted shortfall." : status.next}</ResultNextStep>
    <ResultNote>Claim acceptance verifies the wage issue. Payment is complete only when the corrective payment record confirms it.</ResultNote>
    <ResultDetails><ResultFacts items={[
      { label: "Claim ID", value: claim.id }, { label: "Payroll run", value: claim.runId },
      { label: "Claim commitment", value: claim.claimFactCommitment }, { label: "Proof bundle", value: claim.proofBundleId },
      { label: "Protocol", value: "Worker claim v6" },
    ]} /></ResultDetails>
  </ResultCard>;
}

export function WageRemediationResultCard({ remediation, issue, amount, children }: {
  remediation: WageRemediationSummary; issue?: string; amount?: string; children?: ReactNode;
}) {
  const status = paymentStatuses[remediation.state];
  return <ResultCard kind="wage-payment" tone="claim" audience="Employer · corrective payment" title="Private wage correction"
    description={status.explanation} status={status.label} statusTone={status.tone} icon={WalletCards}>
    <ResultFacts items={[
      { label: "Wage issue", value: issue ?? "Encrypted accepted claim" },
      ...(amount ? [{ label: "Claim shortfall", value: amount }] : []),
      { label: "Payment status", value: status.label },
      { label: "Reconciliation", value: remediation.state === "reconciled" ? "Evidence recorded" : "Evidence pending" },
    ]} />
    {remediation.lastErrorMessage && <ResultNote warning>{remediation.lastErrorMessage}</ResultNote>}
    {children}
    <ResultNextStep>{status.next}</ResultNextStep>
    <ResultDetails><ResultFacts items={[
      { label: "Corrective payment ID", value: remediation.id }, { label: "Original claim", value: remediation.workerClaimId },
      { label: "Settlement ID", value: remediation.settlementId ?? "Not created yet" },
      { label: "Payment commitment", value: remediation.remediationFactCommitment },
      { label: "Authorization expires", value: new Date(remediation.validityExpiresAt).toLocaleString() },
      { label: "Recorded state", value: remediation.state }, { label: "Protocol", value: "Wage remediation v7" },
    ]} /></ResultDetails>
  </ResultCard>;
}
