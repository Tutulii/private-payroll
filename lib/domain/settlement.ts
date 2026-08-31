import { z } from "zod";
import { atomicAmountSchema } from "./payroll";
import { payrollTokenSchema } from "./payroll";
import { hashCanonicalJson } from "@/lib/crypto/digest";

export const settlementStates = [
  "approval_pending",
  "submitted",
  "confirmed",
  "finalized",
  "reorged",
  "failed",
  "reconciled",
] as const;
export const settlementStateSchema = z.enum(settlementStates);
export type SettlementState = z.infer<typeof settlementStateSchema>;

export const settlementWorkflowSchema = z.enum([
  "payroll",
  "wage_claim",
  "wage_remediation",
]);
export type SettlementWorkflow = z.infer<typeof settlementWorkflowSchema>;

export const tokenTotalsSchema = z.object({
  STRK: atomicAmountSchema,
  USDC: atomicAmountSchema,
}).strict().refine(
  (totals) => BigInt(totals.STRK) > 0n || BigInt(totals.USDC) > 0n,
  "At least one settlement token total must be positive.",
);
export type TokenTotals = z.infer<typeof tokenTotalsSchema>;

export const agentSettlementPaymentSchema = z.object({
  recipientAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
  token: payrollTokenSchema,
  amountAtomic: atomicAmountSchema.refine((value) => BigInt(value) > 0n, "Payment amount must be positive."),
  purposeCode: z.string().min(1).max(80),
}).strict();
export type AgentSettlementPayment = z.infer<typeof agentSettlementPaymentSchema>;

function canonicalAgentPayments(payments: readonly AgentSettlementPayment[]) {
  if (payments.length < 1 || payments.length > 50) {
    throw new Error("An agent settlement plan requires 1–50 payments.");
  }
  const canonical = payments.map((payment) => {
    const parsed = agentSettlementPaymentSchema.parse(payment);
    const recipientAddress = `0x${BigInt(parsed.recipientAddress).toString(16)}`;
    if (BigInt(recipientAddress) === 0n) throw new Error("Agent settlement recipient cannot be zero.");
    return { ...parsed, recipientAddress };
  }).sort((left, right) => {
    const tokenOrder = left.token.localeCompare(right.token);
    if (tokenOrder !== 0) return tokenOrder;
    const leftAddress = BigInt(left.recipientAddress);
    const rightAddress = BigInt(right.recipientAddress);
    if (leftAddress !== rightAddress) return leftAddress < rightAddress ? -1 : 1;
    const amountOrder = BigInt(left.amountAtomic) < BigInt(right.amountAtomic)
      ? -1
      : BigInt(left.amountAtomic) > BigInt(right.amountAtomic) ? 1 : 0;
    return amountOrder || left.purposeCode.localeCompare(right.purposeCode);
  });
  const unique = new Set(canonical.map(({ recipientAddress, token }) => `${recipientAddress}:${token}`));
  if (unique.size !== canonical.length) {
    throw new Error("Agent settlement recipients must be unique per token.");
  }
  return canonical;
}

export function commitAgentSettlementPlan(input: {
  organizationId: string;
  runId: string;
  payments: readonly AgentSettlementPayment[];
}): `0x${string}` {
  return hashCanonicalJson({
    domain: "PAYO_AGENT_SETTLEMENT_PLAN_V1",
    organizationId: input.organizationId,
    runId: input.runId,
    payments: canonicalAgentPayments(input.payments),
  });
}

export const payoActionTokenTotalsSchema = z.object({
  STRK: atomicAmountSchema,
  USDC: atomicAmountSchema,
}).strict();
export type PayoActionTokenTotals = z.infer<typeof payoActionTokenTotalsSchema>;

export function commitTokenTotals(input: {
  organizationId: string;
  runId: string;
  totals: TokenTotals;
}): `0x${string}` {
  const totals = tokenTotalsSchema.parse(input.totals);
  return hashCanonicalJson({
    domain: "PAYO_SETTLEMENT_TOTALS_V1",
    organizationId: input.organizationId,
    runId: input.runId,
    totals,
  });
}

/**
 * Commits the hidden settlement totals together with the exact exception
 * workflow and encrypted subject. A claim is intentionally allowed to carry
 * zero token totals because it seals evidence without transferring funds;
 * payroll and remediation must still have a positive private transfer total.
 */
export function commitPayoActionTokenTotals(input: {
  organizationId: string;
  runId: string;
  workflowType: SettlementWorkflow;
  subjectRecordId: string;
  totals: PayoActionTokenTotals;
}): `0x${string}` {
  const workflowType = settlementWorkflowSchema.parse(input.workflowType);
  const totals = payoActionTokenTotalsSchema.parse(input.totals);
  if (
    workflowType !== "wage_claim"
    && BigInt(totals.STRK) === 0n
    && BigInt(totals.USDC) === 0n
  ) {
    throw new Error(`${workflowType} requires a positive private settlement total.`);
  }
  return hashCanonicalJson({
    domain: "PAYO_ACTION_SETTLEMENT_TOTALS_V2",
    organizationId: input.organizationId,
    runId: input.runId,
    workflowType,
    subjectRecordId: input.subjectRecordId,
    totals,
  });
}

export const SETTLEMENT_TRANSITIONS: Readonly<Record<SettlementState, readonly SettlementState[]>> = {
  approval_pending: ["submitted", "failed"],
  submitted: ["confirmed", "failed", "reorged"],
  confirmed: ["finalized", "failed", "reorged"],
  finalized: ["reconciled", "reorged"],
  reorged: ["submitted", "failed"],
  failed: ["approval_pending"],
  reconciled: ["reorged"],
};

export function assertSettlementTransition(from: SettlementState, to: SettlementState): void {
  if (!SETTLEMENT_TRANSITIONS[from].includes(to)) {
    throw new Error(`Invalid settlement transition: ${from} -> ${to}.`);
  }
}

export type StarknetReceiptObservation = {
  finalityStatus: "PENDING" | "PRE_CONFIRMED" | "ACCEPTED_ON_L2" | "ACCEPTED_ON_L1" | "REJECTED";
  executionStatus?: "SUCCEEDED" | "REVERTED";
  transactionHash: string;
  blockNumber?: bigint;
  blockHash?: string;
  canonicalBlockHash?: string;
  headBlockNumber?: bigint;
  revertReason?: string;
};

export type SettlementObservation = {
  state: "pending" | "confirmed" | "finalized" | "reorged" | "failed";
  confirmationDepth: number;
  blockNumber?: bigint;
  blockHash?: string;
  errorCode?: string;
  errorMessage?: string;
};

export const PAYO_FINALITY_CONFIRMATIONS = 3;

export function evaluateStarknetReceipt(
  observation: StarknetReceiptObservation,
  finalityConfirmations = PAYO_FINALITY_CONFIRMATIONS,
): SettlementObservation {
  if (!Number.isInteger(finalityConfirmations) || finalityConfirmations < 1) {
    throw new Error("Finality confirmations must be a positive integer.");
  }
  if (observation.finalityStatus === "REJECTED") {
    return { state: "failed", confirmationDepth: 0, errorCode: "TRANSACTION_REJECTED", errorMessage: "Starknet rejected the transaction." };
  }
  if (observation.executionStatus === "REVERTED") {
    return {
      state: "failed",
      confirmationDepth: 0,
      blockNumber: observation.blockNumber,
      blockHash: observation.blockHash,
      errorCode: "TRANSACTION_REVERTED",
      errorMessage: observation.revertReason || "The Starknet transaction reverted.",
    };
  }
  if (observation.blockNumber === undefined || !observation.blockHash) {
    return { state: "pending", confirmationDepth: 0 };
  }
  if (
    observation.canonicalBlockHash
    && observation.canonicalBlockHash.toLowerCase() !== observation.blockHash.toLowerCase()
  ) {
    return {
      state: "reorged",
      confirmationDepth: 0,
      blockNumber: observation.blockNumber,
      blockHash: observation.blockHash,
      errorCode: "CHAIN_REORG",
      errorMessage: "The transaction block is no longer canonical.",
    };
  }
  const confirmationDepth = observation.headBlockNumber === undefined
    ? 1
    : Number(observation.headBlockNumber - observation.blockNumber + 1n);
  const safeDepth = Math.max(0, confirmationDepth);
  const finalizedByStatus = observation.finalityStatus === "ACCEPTED_ON_L1";
  return {
    state: finalizedByStatus || safeDepth >= finalityConfirmations ? "finalized" : "confirmed",
    confirmationDepth: safeDepth,
    blockNumber: observation.blockNumber,
    blockHash: observation.blockHash,
  };
}
