import { describe, expect, it, vi } from "vitest";
import {
  observeStarknetTransaction,
  processConfirmationBatch,
  type ConfirmationRpc,
} from "./confirmation-worker";

describe("Starknet confirmation worker", () => {
  it("checks canonical block identity and confirmation depth", async () => {
    const rpc: ConfirmationRpc = {
      getTransactionReceipt: vi.fn().mockResolvedValue({
        finality_status: "ACCEPTED_ON_L2",
        execution_status: "SUCCEEDED",
        block_number: 100,
        block_hash: "0xabc",
      }),
      getBlockNumber: vi.fn().mockResolvedValue(102),
      getBlockWithTxHashes: vi.fn().mockResolvedValue({ block_hash: "0xabc" }),
    };
    await expect(observeStarknetTransaction(rpc, "0x123")).resolves.toMatchObject({
      state: "finalized",
      confirmationDepth: 3,
      blockNumber: 100n,
      blockHash: "0xabc",
    });
  });

  it("detects a reorg and treats a not-yet-indexed receipt as pending", async () => {
    const reorgRpc: ConfirmationRpc = {
      getTransactionReceipt: vi.fn().mockResolvedValue({
        finality_status: "ACCEPTED_ON_L2",
        execution_status: "SUCCEEDED",
        block_number: "0x64",
        block_hash: "0xold",
      }),
      getBlockNumber: vi.fn().mockResolvedValue(101),
      getBlockWithTxHashes: vi.fn().mockResolvedValue({ block_hash: "0xnew" }),
    };
    await expect(observeStarknetTransaction(reorgRpc, "0x123")).resolves.toMatchObject({ state: "reorged" });

    const pendingRpc: ConfirmationRpc = {
      getTransactionReceipt: vi.fn().mockRejectedValue(new Error("TRANSACTION_HASH_NOT_FOUND")),
      getBlockNumber: vi.fn(),
      getBlockWithTxHashes: vi.fn(),
    };
    await expect(observeStarknetTransaction(pendingRpc, "0x123")).resolves.toEqual({
      state: "pending",
      confirmationDepth: 0,
    });
  });

  it("leases and applies every job while isolating temporary RPC failures", async () => {
    const jobs = [{ id: "job-1", settlementId: "settlement-1", attempts: 0, transactionHash: "0x1" }];
    const lease = vi.fn().mockResolvedValue(jobs);
    const observe = vi.fn().mockRejectedValue(new Error("provider unavailable"));
    const apply = vi.fn().mockResolvedValue({ state: "pending" });
    const rpc = { getTransactionReceipt: vi.fn(), getBlockNumber: vi.fn(), getBlockWithTxHashes: vi.fn() };
    const result = await processConfirmationBatch({
      rpc,
      workerId: "worker-1",
      dependencies: { lease, observe, apply },
      now: new Date("2026-08-24T00:00:00.000Z"),
    });
    expect(result).toEqual({ leased: 1, results: [{ jobId: "job-1", settlementId: "settlement-1", state: "pending" }] });
    expect(apply).toHaveBeenCalledWith(jobs[0], expect.objectContaining({ errorCode: "RPC_TEMPORARY_FAILURE" }), expect.any(Date));
  });
});
