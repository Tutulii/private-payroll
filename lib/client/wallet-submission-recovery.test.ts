import { describe, expect, it, vi } from "vitest";
import {
  awaitWalletOrRecoveredTransaction,
  readRecoveredSettlementTransactionHash,
} from "./wallet-submission-recovery";

describe("wallet submission recovery", () => {
  it("uses the wallet transaction hash when Ready resolves normally", async () => {
    const readRecoveredTransactionHash = vi.fn();
    const onRecoveryPolling = vi.fn();
    const onRecoveredTransactionHash = vi.fn();
    await expect(awaitWalletOrRecoveredTransaction({
      submit: async () => "0xabc",
      readRecoveredTransactionHash,
      onRecoveryPolling,
      onRecoveredTransactionHash,
      pollIntervalMs: 1,
      timeoutMs: 50,
    })).resolves.toBe("0xabc");
    expect(readRecoveredTransactionHash).not.toHaveBeenCalled();
    expect(onRecoveryPolling).not.toHaveBeenCalled();
    expect(onRecoveredTransactionHash).not.toHaveBeenCalled();
  });

  it("continues from the durable settlement when Ready never resolves", async () => {
    const submit = vi.fn(() => new Promise<string>(() => undefined));
    const onRecoveryPolling = vi.fn();
    const onRecoveredTransactionHash = vi.fn();
    const readRecoveredTransactionHash = vi.fn()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce("0xfeed");
    await expect(awaitWalletOrRecoveredTransaction({
      submit,
      readRecoveredTransactionHash,
      onRecoveryPolling,
      onRecoveredTransactionHash,
      pollIntervalMs: 1,
      timeoutMs: 100,
      recoveryNoticeDelayMs: 0,
    })).resolves.toBe("0xfeed");
    expect(submit).toHaveBeenCalledTimes(1);
    expect(readRecoveredTransactionHash).toHaveBeenCalledTimes(2);
    expect(onRecoveryPolling).toHaveBeenCalledTimes(1);
    expect(onRecoveredTransactionHash).toHaveBeenCalledOnce();
    expect(onRecoveredTransactionHash).toHaveBeenCalledWith("0xfeed");
  });

  it("fails immediately when the user rejects Ready", async () => {
    const readRecoveredTransactionHash = vi.fn();
    const onRecoveryPolling = vi.fn();
    const onRecoveredTransactionHash = vi.fn();
    await expect(awaitWalletOrRecoveredTransaction({
      submit: async () => { throw new Error("User rejected"); },
      readRecoveredTransactionHash,
      onRecoveryPolling,
      onRecoveredTransactionHash,
      pollIntervalMs: 10,
      timeoutMs: 100,
    })).rejects.toThrow("User rejected");
    expect(readRecoveredTransactionHash).not.toHaveBeenCalled();
    expect(onRecoveryPolling).not.toHaveBeenCalled();
    expect(onRecoveredTransactionHash).not.toHaveBeenCalled();
  });

  it("keeps the canonical recovery authoritative when a browser callback fails", async () => {
    await expect(awaitWalletOrRecoveredTransaction({
      submit: () => new Promise<string>(() => undefined),
      readRecoveredTransactionHash: async () => "0xfeed",
      onRecoveryPolling: async () => { throw new Error("render unavailable"); },
      onRecoveredTransactionHash: async () => { throw new Error("wallet state unavailable"); },
      pollIntervalMs: 1,
      timeoutMs: 100,
      recoveryNoticeDelayMs: 0,
    })).resolves.toBe("0xfeed");
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
