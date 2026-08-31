import { describe, expect, it } from "vitest";
import {
  assertSettlementTransition,
  commitAgentSettlementPlan,
  commitPayoActionTokenTotals,
  evaluateStarknetReceipt,
  tokenTotalsSchema,
} from "./settlement";

describe("durable settlement state", () => {
  it("distinguishes pending, confirmed, finalized, failed, and reorged receipts", () => {
    expect(evaluateStarknetReceipt({ finalityStatus: "PRE_CONFIRMED", transactionHash: "0x1" }).state).toBe("pending");
    expect(evaluateStarknetReceipt({
      finalityStatus: "ACCEPTED_ON_L2",
      executionStatus: "SUCCEEDED",
      transactionHash: "0x1",
      blockNumber: 10n,
      blockHash: "0xaaa",
      canonicalBlockHash: "0xaaa",
      headBlockNumber: 10n,
    })).toMatchObject({ state: "confirmed", confirmationDepth: 1 });
    expect(evaluateStarknetReceipt({
      finalityStatus: "ACCEPTED_ON_L2",
      executionStatus: "SUCCEEDED",
      transactionHash: "0x1",
      blockNumber: 10n,
      blockHash: "0xaaa",
      canonicalBlockHash: "0xaaa",
      headBlockNumber: 12n,
    })).toMatchObject({ state: "finalized", confirmationDepth: 3 });
    expect(evaluateStarknetReceipt({
      finalityStatus: "ACCEPTED_ON_L2",
      executionStatus: "SUCCEEDED",
      transactionHash: "0x1",
      blockNumber: 10n,
      blockHash: "0xaaa",
      canonicalBlockHash: "0xbbb",
      headBlockNumber: 12n,
    })).toMatchObject({ state: "reorged", errorCode: "CHAIN_REORG" });
    expect(evaluateStarknetReceipt({
      finalityStatus: "ACCEPTED_ON_L2",
      executionStatus: "REVERTED",
      transactionHash: "0x1",
      revertReason: "PAYO_REPLAY",
    })).toMatchObject({ state: "failed", errorCode: "TRANSACTION_REVERTED", errorMessage: "PAYO_REPLAY" });
  });

  it("enforces settlement transitions and exact atomic totals", () => {
    expect(() => assertSettlementTransition("approval_pending", "submitted")).not.toThrow();
    expect(() => assertSettlementTransition("approval_pending", "finalized")).toThrow(/Invalid/);
    expect(tokenTotalsSchema.parse({ STRK: "1", USDC: "0" })).toEqual({ STRK: "1", USDC: "0" });
    expect(() => tokenTotalsSchema.parse({ STRK: "0", USDC: "0" })).toThrow();
    expect(() => tokenTotalsSchema.parse({ STRK: "1.5", USDC: "0" })).toThrow();
  });

  it("allows zero-value claim sealing but requires value for payroll remediation", () => {
    expect(commitPayoActionTokenTotals({
      organizationId: "org",
      runId: "run",
      workflowType: "wage_claim",
      subjectRecordId: "claim",
      totals: { STRK: "0", USDC: "0" },
    })).toMatch(/^0x[0-9a-f]{64}$/);
    expect(() => commitPayoActionTokenTotals({
      organizationId: "org",
      runId: "run",
      workflowType: "wage_remediation",
      subjectRecordId: "remediation",
      totals: { STRK: "0", USDC: "0" },
    })).toThrow(/positive private settlement total/i);
  });

  it("commits the exact canonical agent recipients, tokens, amounts and purposes", () => {
    const input = {
      organizationId: "org",
      runId: "run",
      payments: [
        { recipientAddress: "0x002", token: "USDC" as const, amountAtomic: "25", purposeCode: "private_payroll" },
        { recipientAddress: "0x001", token: "STRK" as const, amountAtomic: "100", purposeCode: "private_payroll" },
      ],
    };
    const commitment = commitAgentSettlementPlan(input);
    expect(commitAgentSettlementPlan({ ...input, payments: [...input.payments].reverse() })).toBe(commitment);
    expect(commitAgentSettlementPlan({
      ...input,
      payments: [{ ...input.payments[0], recipientAddress: "0x003" }, input.payments[1]],
    })).not.toBe(commitment);
    expect(() => commitAgentSettlementPlan({
      ...input,
      payments: [input.payments[0], { ...input.payments[0], amountAtomic: "26" }],
    })).toThrow(/unique per token/i);
  });
});
