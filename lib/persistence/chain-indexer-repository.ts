import "server-only";

import { and, desc, eq, gt, gte, inArray, lte, sql } from "drizzle-orm";
import { getDatabase } from "./db";
import { chainCursors, indexedChainBlocks, indexedChainEvents } from "./schema";

const STARKNET_HASH = /^0x[0-9a-fA-F]{1,64}$/;

export type IndexedEventInput = {
  transactionHash: string;
  eventIndex: number;
  contractAddress: string;
  eventName: string;
  payload: Record<string, unknown>;
};

export type IndexedBlockInput = {
  chainId: string;
  consumer: string;
  blockNumber: bigint;
  blockHash: string;
  parentHash: string;
  events: IndexedEventInput[];
};

function validateIdentifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 128) throw new Error(`${label} must contain 1–128 characters.`);
  return normalized;
}

function validateHash(value: string, label: string): string {
  if (!STARKNET_HASH.test(value)) throw new Error(`${label} must be a Starknet hash.`);
  return value.toLowerCase();
}

function validateFelt(value: string, label: string): string {
  return `0x${BigInt(validateHash(value, label)).toString(16)}`;
}

function lockKey(chainId: string, consumer: string): string {
  return `payo:indexer:${chainId}:${consumer}`;
}

export async function getChainCursor(chainId: string, consumer: string) {
  const [cursor] = await getDatabase()
    .select()
    .from(chainCursors)
    .where(and(eq(chainCursors.chainId, chainId), eq(chainCursors.consumer, consumer)))
    .limit(1);
  return cursor ?? null;
}

export async function getIndexedBlock(chainId: string, blockNumber: bigint) {
  const [block] = await getDatabase()
    .select()
    .from(indexedChainBlocks)
    .where(and(
      eq(indexedChainBlocks.chainId, chainId),
      eq(indexedChainBlocks.blockNumber, blockNumber),
      eq(indexedChainBlocks.canonical, true),
    ))
    .limit(1);
  return block ?? null;
}

export async function persistIndexedBlock(input: IndexedBlockInput) {
  const chainId = validateIdentifier(input.chainId, "Chain ID");
  const consumer = validateIdentifier(input.consumer, "Indexer consumer");
  if (input.blockNumber < 0n) throw new Error("Block number cannot be negative.");
  const blockHash = validateHash(input.blockHash, "Block hash");
  const parentHash = validateHash(input.parentHash, "Parent hash");
  const seenEvents = new Set<string>();
  const events = input.events.map((event) => {
    const transactionHash = validateFelt(event.transactionHash, "Event transaction hash");
    const contractAddress = validateFelt(event.contractAddress, "Event contract address");
    if (!Number.isSafeInteger(event.eventIndex) || event.eventIndex < 0) {
      throw new Error("Event index must be a non-negative safe integer.");
    }
    const identity = `${transactionHash}:${event.eventIndex}`;
    if (seenEvents.has(identity)) throw new Error("A block cannot contain duplicate event identities.");
    seenEvents.add(identity);
    return { ...event, transactionHash, contractAddress };
  });
  const now = new Date();
  const database = getDatabase();

  return database.transaction(async (transaction) => {
    await transaction.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${lockKey(chainId, consumer)}, 0))`);
    const [cursor] = await transaction
      .select()
      .from(chainCursors)
      .where(and(eq(chainCursors.chainId, chainId), eq(chainCursors.consumer, consumer)))
      .limit(1);
    if (cursor) {
      if (input.blockNumber === cursor.blockNumber && blockHash === cursor.blockHash) {
        return { blockNumber: input.blockNumber, blockHash, replayed: true };
      }
      if (input.blockNumber !== cursor.blockNumber + 1n) {
        throw new Error(`Indexer block must follow cursor ${cursor.blockNumber.toString()}.`);
      }
      if (parentHash !== cursor.blockHash) {
        throw new Error("Indexer parent hash does not match the canonical cursor.");
      }
    }

    const [existingBlock] = await transaction
      .select({
        blockHash: indexedChainBlocks.blockHash,
        canonical: indexedChainBlocks.canonical,
      })
      .from(indexedChainBlocks)
      .where(and(
        eq(indexedChainBlocks.chainId, chainId),
        eq(indexedChainBlocks.blockNumber, input.blockNumber),
      ))
      .limit(1);
    if (existingBlock?.canonical && existingBlock.blockHash !== blockHash) {
      throw new Error("A different block is stored at this height; roll back the reorg first.");
    }
    await transaction
      .insert(indexedChainBlocks)
      .values({ chainId, blockNumber: input.blockNumber, blockHash, parentHash, canonical: true })
      .onConflictDoUpdate({
        target: [indexedChainBlocks.chainId, indexedChainBlocks.blockNumber],
        set: { blockHash, parentHash, canonical: true, observedAt: now },
      });
    for (const event of events) {
      await transaction
        .insert(indexedChainEvents)
        .values({
          chainId,
          transactionHash: event.transactionHash,
          eventIndex: event.eventIndex,
          blockNumber: input.blockNumber,
          blockHash,
          contractAddress: event.contractAddress,
          eventName: event.eventName,
          payload: event.payload,
          canonical: true,
        })
        .onConflictDoUpdate({
          target: [
            indexedChainEvents.chainId,
            indexedChainEvents.transactionHash,
            indexedChainEvents.eventIndex,
          ],
          set: {
            blockNumber: input.blockNumber,
            blockHash,
            contractAddress: event.contractAddress,
            eventName: event.eventName,
            payload: event.payload,
            canonical: true,
            observedAt: now,
          },
        });
    }
    await transaction
      .insert(chainCursors)
      .values({ chainId, consumer, blockNumber: input.blockNumber, blockHash })
      .onConflictDoUpdate({
        target: [chainCursors.chainId, chainCursors.consumer],
        set: { blockNumber: input.blockNumber, blockHash, updatedAt: now },
      });
    return { blockNumber: input.blockNumber, blockHash, replayed: false };
  });
}

export type IndexedRecoveryEventInput = IndexedEventInput & {
  blockNumber: bigint;
  blockHash: string;
};

/**
 * Replaces the finalized recovery-event scope for a bounded near-head window.
 * This scan is deliberately cursorless: adding a new seal address cannot skip
 * a recently submitted wallet transaction because an older cursor is ahead.
 */
export async function replaceIndexedRecoveryEvents(input: {
  chainId: string;
  fromBlock: bigint;
  toBlock: bigint;
  addresses: readonly string[];
  eventNames: readonly string[];
  events: readonly IndexedRecoveryEventInput[];
}) {
  const chainId = validateIdentifier(input.chainId, "Chain ID");
  if (input.fromBlock < 0n || input.toBlock < input.fromBlock) {
    throw new Error("Recovery event window is invalid.");
  }
  const addresses = [...new Set(input.addresses.map((value) => validateFelt(value, "Recovery address")))];
  const eventNames = [...new Set(input.eventNames.map((value) => validateFelt(value, "Recovery event selector")))];
  if (addresses.length === 0 || eventNames.length === 0) {
    throw new Error("Recovery event replacement requires an address and selector scope.");
  }
  const allowedAddresses = new Set(addresses);
  const allowedEventNames = new Set(eventNames);
  const seenEvents = new Set<string>();
  const events = input.events.map((event) => {
    const transactionHash = validateFelt(event.transactionHash, "Recovery transaction hash");
    const contractAddress = validateFelt(event.contractAddress, "Recovery contract address");
    const eventName = validateFelt(event.eventName, "Recovery event selector");
    const blockHash = validateHash(event.blockHash, "Recovery block hash");
    if (!Number.isSafeInteger(event.eventIndex) || event.eventIndex < 0) {
      throw new Error("Recovery event index must be a non-negative safe integer.");
    }
    if (event.blockNumber < input.fromBlock || event.blockNumber > input.toBlock) {
      throw new Error("Recovery event lies outside its finalized scan window.");
    }
    if (!allowedAddresses.has(contractAddress) || !allowedEventNames.has(eventName)) {
      throw new Error("Recovery event lies outside its configured contract scope.");
    }
    const identity = `${transactionHash}:${event.eventIndex}`;
    if (seenEvents.has(identity)) throw new Error("Recovery scan contains duplicate event identities.");
    seenEvents.add(identity);
    return { ...event, transactionHash, contractAddress, eventName, blockHash };
  });
  const database = getDatabase();
  const now = new Date();

  return database.transaction(async (transaction) => {
    await transaction.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${lockKey(chainId, "submission-recovery-tail")}, 0))`);
    await transaction
      .update(indexedChainEvents)
      .set({ canonical: false, observedAt: now })
      .where(and(
        eq(indexedChainEvents.chainId, chainId),
        gte(indexedChainEvents.blockNumber, input.fromBlock),
        lte(indexedChainEvents.blockNumber, input.toBlock),
        inArray(indexedChainEvents.contractAddress, addresses),
        inArray(indexedChainEvents.eventName, eventNames),
      ));
    for (const event of events) {
      await transaction
        .insert(indexedChainEvents)
        .values({
          chainId,
          transactionHash: event.transactionHash,
          eventIndex: event.eventIndex,
          blockNumber: event.blockNumber,
          blockHash: event.blockHash,
          contractAddress: event.contractAddress,
          eventName: event.eventName,
          payload: event.payload,
          canonical: true,
        })
        .onConflictDoUpdate({
          target: [
            indexedChainEvents.chainId,
            indexedChainEvents.transactionHash,
            indexedChainEvents.eventIndex,
          ],
          set: {
            blockNumber: event.blockNumber,
            blockHash: event.blockHash,
            contractAddress: event.contractAddress,
            eventName: event.eventName,
            payload: event.payload,
            canonical: true,
            observedAt: now,
          },
        });
    }
    return { indexed: events.length, fromBlock: input.fromBlock, toBlock: input.toBlock };
  });
}

export async function rollbackIndexedChain(input: {
  chainId: string;
  consumer: string;
  ancestorBlockNumber: bigint | null;
  ancestorBlockHash: string | null;
}) {
  const chainId = validateIdentifier(input.chainId, "Chain ID");
  const consumer = validateIdentifier(input.consumer, "Indexer consumer");
  if ((input.ancestorBlockNumber === null) !== (input.ancestorBlockHash === null)) {
    throw new Error("Rollback ancestor number and hash must both be present or absent.");
  }
  const ancestorHash = input.ancestorBlockHash === null
    ? null
    : validateHash(input.ancestorBlockHash, "Rollback ancestor hash");
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await transaction.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${lockKey(chainId, consumer)}, 0))`);
    const [cursor] = await transaction
      .select()
      .from(chainCursors)
      .where(and(eq(chainCursors.chainId, chainId), eq(chainCursors.consumer, consumer)))
      .limit(1);
    if (!cursor) return { rolledBack: 0n, cursor: null };
    const ancestorNumber = input.ancestorBlockNumber;
    if (ancestorNumber !== null && ancestorNumber > cursor.blockNumber) {
      throw new Error("Rollback ancestor cannot be ahead of the cursor.");
    }
    const firstRemoved = ancestorNumber === null ? -1n : ancestorNumber;
    await transaction
      .update(indexedChainBlocks)
      .set({ canonical: false })
      .where(and(eq(indexedChainBlocks.chainId, chainId), gt(indexedChainBlocks.blockNumber, firstRemoved)));
    await transaction
      .update(indexedChainEvents)
      .set({ canonical: false })
      .where(and(eq(indexedChainEvents.chainId, chainId), gt(indexedChainEvents.blockNumber, firstRemoved)));
    if (ancestorNumber === null || ancestorHash === null) {
      await transaction
        .delete(chainCursors)
        .where(and(eq(chainCursors.chainId, chainId), eq(chainCursors.consumer, consumer)));
      return { rolledBack: cursor.blockNumber + 1n, cursor: null };
    }
    await transaction
      .update(chainCursors)
      .set({ blockNumber: ancestorNumber, blockHash: ancestorHash, updatedAt: new Date() })
      .where(and(eq(chainCursors.chainId, chainId), eq(chainCursors.consumer, consumer)));
    return {
      rolledBack: cursor.blockNumber - ancestorNumber,
      cursor: { blockNumber: ancestorNumber, blockHash: ancestorHash },
    };
  });
}

export async function listRecentIndexedBlocks(chainId: string, fromBlock: bigint, limit = 128) {
  return getDatabase()
    .select()
    .from(indexedChainBlocks)
    .where(and(
      eq(indexedChainBlocks.chainId, chainId),
      eq(indexedChainBlocks.canonical, true),
      gt(indexedChainBlocks.blockNumber, fromBlock - 1n),
    ))
    .orderBy(desc(indexedChainBlocks.blockNumber))
    .limit(limit);
}
