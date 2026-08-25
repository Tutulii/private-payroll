import { describe, expect, it } from "vitest";
import {
  assertSettlementTransition,
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
});
