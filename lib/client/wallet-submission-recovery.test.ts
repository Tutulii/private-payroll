import { describe, expect, it, vi } from "vitest";
import {
  awaitWalletOrRecoveredTransaction,
  readRecoveredSettlementTransactionHash,
} from "./wallet-submission-recovery";

describe("wallet submission recovery", () => {
  it("uses the wallet transaction hash when Ready resolves normally", async () => {
    const readRecoveredTransactionHash = vi.fn();
    await expect(awaitWalletOrRecoveredTransaction({
      submit: async () => "0xabc",
      readRecoveredTransactionHash,
      pollIntervalMs: 1,
      timeoutMs: 50,
    })).resolves.toBe("0xabc");
    expect(readRecoveredTransactionHash).not.toHaveBeenCalled();
  });

  it("continues from the durable settlement when Ready never resolves", async () => {
    const submit = vi.fn(() => new Promise<string>(() => undefined));
    const readRecoveredTransactionHash = vi.fn()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce("0xfeed");
    await expect(awaitWalletOrRecoveredTransaction({
      submit,
      readRecoveredTransactionHash,
      pollIntervalMs: 1,
      timeoutMs: 100,
    })).resolves.toBe("0xfeed");
    expect(submit).toHaveBeenCalledTimes(1);
    expect(readRecoveredTransactionHash).toHaveBeenCalledTimes(2);
  });

  it("fails immediately when the user rejects Ready", async () => {
    const readRecoveredTransactionHash = vi.fn();
    await expect(awaitWalletOrRecoveredTransaction({
      submit: async () => { throw new Error("User rejected"); },
      readRecoveredTransactionHash,
      pollIntervalMs: 10,
      timeoutMs: 100,
    })).rejects.toThrow("User rejected");
    expect(readRecoveredTransactionHash).not.toHaveBeenCalled();
  });

  it("reads only a validated transaction hash from a settlement", async () => {
    const client = {
      getSettlement: vi.fn().mockResolvedValue({ settlement: { transactionHash: "0x123" } }),
    };
    await expect(readRecoveredSettlementTransactionHash(client, "settlement-1"))
      .resolves.toBe("0x123");
    client.getSettlement.mockResolvedValue({ settlement: { transactionHash: null } });
    await expect(readRecoveredSettlementTransactionHash(client, "settlement-1"))
      .resolves.toBeNull();
  });
});
