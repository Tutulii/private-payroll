import { describe, expect, it, vi } from "vitest";
import { processEventIndexBatch } from "./chain-indexer";

function block(number: number, hash = `0x${number + 10}`, parent = `0x${number + 9}`) {
  return { block_number: number, block_hash: hash, parent_hash: parent };
}

function storedBlock(number: bigint, blockHash: string) {
  return {
    chainId: "SN_MAIN",
    blockNumber: number,
    blockHash,
    parentHash: "0x1",
    canonical: true,
    observedAt: new Date(),
  };
}

describe("durable Starknet event indexer", () => {
  it("resumes from its cursor and persists paginated events", async () => {
    const persistBlock = vi.fn(async (input: { blockNumber: bigint; blockHash: string }) => ({
      blockNumber: input.blockNumber,
      blockHash: input.blockHash,
      replayed: false,
    }));
    const rpc = {
      getBlockNumber: vi.fn(async () => 12),
      getBlockWithTxHashes: vi.fn(async (number: number) => block(number)),
      getEvents: vi.fn()
        .mockResolvedValueOnce({ events: [{ transaction_hash: "0xaa", from_address: "0xbb", keys: ["0x1"], data: ["0x2"] }], continuation_token: "next" })
        .mockResolvedValueOnce({ events: [{ transaction_hash: "0xcc", from_address: "0xbb", keys: ["0x1"], data: [] }] }),
    };
    const result = await processEventIndexBatch({
      rpc,
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      fromBlock: 10n,
      maxBlocks: 1,
      persistence: {
        getCursor: vi.fn(async () => ({ chainId: "SN_MAIN", consumer: "payo-seal", blockNumber: 10n, blockHash: "0x20", updatedAt: new Date() })),
        getBlock: vi.fn(),
        persistBlock,
        rollback: vi.fn(),
      },
    });
    expect(result.indexed).toBe(1);
    expect(persistBlock).toHaveBeenCalledWith(expect.objectContaining({
      blockNumber: 11n,
      events: [
        expect.objectContaining({ transactionHash: "0xaa", eventIndex: 0 }),
        expect.objectContaining({ transactionHash: "0xcc", eventIndex: 1 }),
      ],
    }));
  });

  it("finds a common ancestor, rolls back, and indexes the replacement chain", async () => {
    const rollback = vi.fn(async () => ({ rolledBack: 2n, cursor: { blockNumber: 10n, blockHash: "0xa0" } }));
    const rpc = {
      getBlockNumber: vi.fn(async () => 12),
      getBlockWithTxHashes: vi.fn(async (number: number) => {
        if (number === 12) return block(12, "0xc2", "0xb1");
        if (number === 11) return block(11, "0xb1", "0xa0");
        return block(10, "0xa0", "0x99");
      }),
      getEvents: vi.fn(async () => ({ events: [] })),
    };
    const result = await processEventIndexBatch({
      rpc,
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      fromBlock: 10n,
      maxBlocks: 2,
      persistence: {
        getCursor: vi.fn(async () => ({ chainId: "SN_MAIN", consumer: "payo-seal", blockNumber: 12n, blockHash: "0xold", updatedAt: new Date() })),
        getBlock: vi.fn(async (_chainId: string, number: bigint) => storedBlock(number, number === 10n ? "0xa0" : "0xold")),
        persistBlock: vi.fn(async (input) => ({ blockNumber: input.blockNumber, blockHash: input.blockHash, replayed: false })),
        rollback,
      },
    });
    expect(rollback).toHaveBeenCalledWith(expect.objectContaining({ ancestorBlockNumber: 10n, ancestorBlockHash: "0xa0" }));
    expect(result).toMatchObject({ indexed: 2, rolledBack: 2n });
  });

  it("fails closed when the common ancestor exceeds the configured bound", async () => {
    const rpc = {
      getBlockNumber: vi.fn(async () => 200),
      getBlockWithTxHashes: vi.fn(async (number: number) => block(number, `0xnew${number}`, "0x1")),
      getEvents: vi.fn(async () => ({ events: [] })),
    };
    await expect(processEventIndexBatch({
      rpc,
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      fromBlock: 1n,
      maxReorgDepth: 2,
      persistence: {
        getCursor: vi.fn(async () => ({ chainId: "SN_MAIN", consumer: "payo-seal", blockNumber: 100n, blockHash: "0xold", updatedAt: new Date() })),
        getBlock: vi.fn(async (_chainId: string, number: bigint) => storedBlock(number, "0xolder")),
        persistBlock: vi.fn(),
        rollback: vi.fn(),
      },
    })).rejects.toThrow("REORG_DEPTH_EXCEEDED");
  });
});
