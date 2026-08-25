import "server-only";

import {
  getChainCursor,
  getIndexedBlock,
  persistIndexedBlock,
  rollbackIndexedChain,
  type IndexedBlockInput,
} from "@/lib/persistence/chain-indexer-repository";

type RpcRecord = Record<string, unknown>;

export type StarknetEventIndexerRpc = {
  getBlockNumber: () => Promise<number>;
  getBlockWithTxHashes: (blockIdentifier: number) => Promise<unknown>;
  getEvents: (filter: {
    from_block: { block_number: number };
    to_block: { block_number: number };
    chunk_size: number;
    address?: string;
    keys?: string[][];
    continuation_token?: string;
  }) => Promise<unknown>;
};

type IndexerPersistence = {
  getCursor: typeof getChainCursor;
  getBlock: typeof getIndexedBlock;
  persistBlock: typeof persistIndexedBlock;
  rollback: typeof rollbackIndexedChain;
};

const defaultPersistence: IndexerPersistence = {
  getCursor: getChainCursor,
  getBlock: getIndexedBlock,
  persistBlock: persistIndexedBlock,
  rollback: rollbackIndexedChain,
};

function record(value: unknown): RpcRecord {
  return value && typeof value === "object" ? value as RpcRecord : {};
}

function stringField(value: RpcRecord, ...names: string[]): string | undefined {
  const field = names.map((name) => value[name]).find((candidate) => typeof candidate === "string");
  return typeof field === "string" ? field.toLowerCase() : undefined;
}

function bigintField(value: RpcRecord, ...names: string[]): bigint | undefined {
  const field = names.map((name) => value[name]).find((candidate) => candidate !== undefined);
  if (typeof field === "bigint") return field;
  if (typeof field === "number" && Number.isSafeInteger(field) && field >= 0) return BigInt(field);
  if (typeof field === "string" && /^(0x[0-9a-fA-F]+|\d+)$/.test(field)) return BigInt(field);
  return undefined;
}

function parseBlock(value: unknown): { blockNumber: bigint; blockHash: string; parentHash: string } {
  const block = record(value);
  const blockNumber = bigintField(block, "block_number", "blockNumber");
  const blockHash = stringField(block, "block_hash", "blockHash");
  const parentHash = stringField(block, "parent_hash", "parentHash");
  if (blockNumber === undefined || !blockHash || !parentHash) {
    throw new Error("Starknet RPC returned an incomplete accepted block.");
  }
  return { blockNumber, blockHash, parentHash };
}

async function loadBlockEvents(input: {
  rpc: StarknetEventIndexerRpc;
  blockNumber: bigint;
  address?: string;
  keys?: string[][];
}): Promise<IndexedBlockInput["events"]> {
  const events: IndexedBlockInput["events"] = [];
  let continuationToken: string | undefined;
  for (let page = 0; page < 100; page += 1) {
    const response = record(await input.rpc.getEvents({
      from_block: { block_number: Number(input.blockNumber) },
      to_block: { block_number: Number(input.blockNumber) },
      chunk_size: 100,
      ...(input.address ? { address: input.address } : {}),
      ...(input.keys ? { keys: input.keys } : {}),
      ...(continuationToken ? { continuation_token: continuationToken } : {}),
    }));
    const pageEvents = Array.isArray(response.events) ? response.events : [];
    for (const candidate of pageEvents) {
      const event = record(candidate);
      const transactionHash = stringField(event, "transaction_hash", "transactionHash");
      const contractAddress = stringField(event, "from_address", "fromAddress");
      const keys = Array.isArray(event.keys) ? event.keys.filter((key): key is string => typeof key === "string") : [];
      const data = Array.isArray(event.data) ? event.data.filter((item): item is string => typeof item === "string") : [];
      if (!transactionHash || !contractAddress) throw new Error("Starknet RPC returned an event without identity fields.");
      events.push({
        transactionHash,
        eventIndex: events.length,
        contractAddress,
        eventName: keys[0]?.toLowerCase() ?? "anonymous",
        payload: { keys, data },
      });
    }
    continuationToken = stringField(response, "continuation_token", "continuationToken");
    if (!continuationToken) return events;
  }
  throw new Error("Starknet event pagination exceeded the safety limit.");
}

export async function processEventIndexBatch(input: {
  rpc: StarknetEventIndexerRpc;
  chainId: string;
  consumer: string;
  fromBlock: bigint;
  maxBlocks?: number;
  finalityLag?: number;
  address?: string;
  keys?: string[][];
  maxReorgDepth?: number;
  prefetchConcurrency?: number;
  persistence?: IndexerPersistence;
}) {
  const persistence = input.persistence ?? defaultPersistence;
  const maxBlocks = input.maxBlocks ?? 20;
  const finalityLag = input.finalityLag ?? 0;
  const maxReorgDepth = input.maxReorgDepth ?? 128;
  const prefetchConcurrency = input.prefetchConcurrency ?? 4;
  if (!Number.isInteger(maxBlocks) || maxBlocks < 1 || maxBlocks > 100) throw new Error("Indexer batch size must be 1–100.");
  if (!Number.isInteger(finalityLag) || finalityLag < 0) throw new Error("Finality lag cannot be negative.");
  if (!Number.isInteger(maxReorgDepth) || maxReorgDepth < 1 || maxReorgDepth > 10_000) {
    throw new Error("Maximum reorg depth must be 1–10,000 blocks.");
  }
  if (!Number.isInteger(prefetchConcurrency) || prefetchConcurrency < 1 || prefetchConcurrency > 16) {
    throw new Error("Indexer prefetch concurrency must be 1–16.");
  }

  let cursor: {
    chainId: string;
    consumer: string;
    blockNumber: bigint;
    blockHash: string;
    updatedAt: Date;
  } | null = await persistence.getCursor(input.chainId, input.consumer);
  let rolledBack = 0n;
  if (cursor) {
    const canonicalCursor = parseBlock(await input.rpc.getBlockWithTxHashes(Number(cursor.blockNumber)));
    if (canonicalCursor.blockHash !== cursor.blockHash) {
      const floor = cursor.blockNumber > BigInt(maxReorgDepth)
        ? cursor.blockNumber - BigInt(maxReorgDepth)
        : input.fromBlock;
      let ancestor: { blockNumber: bigint; blockHash: string } | null = null;
      for (let blockNumber = cursor.blockNumber - 1n; blockNumber >= floor; blockNumber -= 1n) {
        const stored = await persistence.getBlock(input.chainId, blockNumber);
        if (stored) {
          const canonical = parseBlock(await input.rpc.getBlockWithTxHashes(Number(blockNumber)));
          if (canonical.blockHash === stored.blockHash) {
            ancestor = { blockNumber, blockHash: canonical.blockHash };
            break;
          }
        }
        if (blockNumber === 0n) break;
      }
      if (!ancestor && floor > input.fromBlock) throw new Error("REORG_DEPTH_EXCEEDED");
      const rollback = await persistence.rollback({
        chainId: input.chainId,
        consumer: input.consumer,
        ancestorBlockNumber: ancestor?.blockNumber ?? null,
        ancestorBlockHash: ancestor?.blockHash ?? null,
      });
      rolledBack = rollback.rolledBack;
      cursor = ancestor
        ? { ...cursor, blockNumber: ancestor.blockNumber, blockHash: ancestor.blockHash }
        : null;
    }
  }

  const head = BigInt(await input.rpc.getBlockNumber()) - BigInt(finalityLag);
  let nextBlock = cursor ? cursor.blockNumber + 1n : input.fromBlock;
  let indexed = 0;
  while (nextBlock <= head && indexed < maxBlocks) {
    const windowSize = Math.min(prefetchConcurrency, maxBlocks - indexed);
    const remainingBlocks = head - nextBlock + 1n;
    const actualWindowSize = Number(
      remainingBlocks < BigInt(windowSize) ? remainingBlocks : BigInt(windowSize),
    );
    const prefetched = await Promise.all(Array.from({ length: actualWindowSize }, async (_, offset) => {
      const blockNumber = nextBlock + BigInt(offset);
      const [blockValue, events] = await Promise.all([
        input.rpc.getBlockWithTxHashes(Number(blockNumber)),
        loadBlockEvents({ ...input, blockNumber }),
      ]);
      const block = parseBlock(blockValue);
      if (block.blockNumber !== blockNumber) {
        throw new Error("Starknet RPC returned the wrong block height.");
      }
      return { block, events };
    }));
    for (const { block, events } of prefetched) {
      await persistence.persistBlock({
        chainId: input.chainId,
        consumer: input.consumer,
        ...block,
        events,
      });
      nextBlock += 1n;
      indexed += 1;
    }
  }
  return { indexed, rolledBack, headBlockNumber: head, nextBlockNumber: nextBlock };
}
