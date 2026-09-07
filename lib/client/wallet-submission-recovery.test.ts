import { describe, expect, it, vi } from "vitest";
import {
  awaitWalletOrRecoveredTransaction,
  isDefinitiveWalletNonSubmission,
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

  it("normalizes equivalent leading-zero wallet hashes before recording", async () => {
    await expect(awaitWalletOrRecoveredTransaction({
      submit: async () => "0x000abc",
      readRecoveredTransactionHash: vi.fn(),
      pollIntervalMs: 1,
      timeoutMs: 50,
    })).resolves.toBe("0xabc");
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

  it("keeps polling when Ready times out after an accepted approval", async () => {
    const onRecoveryPolling = vi.fn();
    const readRecoveredTransactionHash = vi.fn()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce("0xcafe");
    await expect(awaitWalletOrRecoveredTransaction({
      submit: async () => { throw new Error("Timeout"); },
      readRecoveredTransactionHash,
      onRecoveryPolling,
      pollIntervalMs: 1,
      timeoutMs: 100,
      recoveryNoticeDelayMs: 50,
    })).resolves.toBe("0xcafe");
    expect(readRecoveredTransactionHash).toHaveBeenCalledTimes(2);
    expect(onRecoveryPolling).toHaveBeenCalledTimes(1);
  });

  it("treats Wallet API UNKNOWN_ERROR as ambiguous but explicit refusal as final", () => {
    expect(isDefinitiveWalletNonSubmission({ code: 163, message: "Timeout" })).toBe(false);
    expect(isDefinitiveWalletNonSubmission({ error: { code: 113 } })).toBe(true);
    expect(isDefinitiveWalletNonSubmission(new Error("An error occurred (NOT_REGISTERED)"))).toBe(true);
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
