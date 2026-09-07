import type { IndexedRecoveryEventInput } from "@/lib/persistence/chain-indexer-repository";

const STARKNET_FELT = /^0x[0-9a-fA-F]{1,64}$/;

type RpcRecord = Record<string, unknown>;

export type RecoveryTailIndexRpc = {
  getEvents: (filter: {
    from_block: { block_number: number };
    to_block: { block_number: number };
    chunk_size: number;
    keys: string[][];
    continuation_token?: string;
  }) => Promise<unknown>;
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

function normalizeFelt(value: string, label: string): string {
  if (!STARKNET_FELT.test(value)) throw new Error(`${label} must be a Starknet felt.`);
  return `0x${BigInt(value).toString(16)}`;
}

function requireNonNegative(value: bigint, label: string): bigint {
  if (value < 0n) throw new Error(`${label} cannot be negative.`);
  return value;
}

/**
 * Builds a cursorless finalized-chain window. Since every worker pass derives
 * this from the current address/selector set, a newly configured seal cannot
 * inherit a cursor which has already skipped its transaction.
 */
export function buildRecoveryTailIndexPlan(input: {
  configuredFromBlock: bigint;
  chainHead: bigint;
  finalityLag: number;
  lookbackBlocks: number;
  addresses: readonly string[];
  selectors: readonly string[];
}) {
  if (!Number.isInteger(input.finalityLag) || input.finalityLag < 0) {
    throw new Error("Recovery finality lag cannot be negative.");
  }
  if (!Number.isInteger(input.lookbackBlocks) || input.lookbackBlocks < 1 || input.lookbackBlocks > 10_000) {
    throw new Error("Recovery lookback must be 1–10,000 blocks.");
  }
  const configuredFromBlock = requireNonNegative(input.configuredFromBlock, "Indexer start block");
  const chainHead = requireNonNegative(input.chainHead, "Chain head");
  const addresses = [...new Set(input.addresses.map((value) => normalizeFelt(value, "Recovery address")))].sort();
  const selectors = [...new Set(input.selectors.map((value) => normalizeFelt(value, "Recovery selector")))].sort();
  if (addresses.length === 0 || selectors.length === 0) {
    throw new Error("Recovery indexing requires at least one address and selector.");
  }

  const finalizedHead = chainHead > BigInt(input.finalityLag)
    ? chainHead - BigInt(input.finalityLag)
    : 0n;
  const lookback = BigInt(input.lookbackBlocks - 1);
  const lookbackStart = finalizedHead > lookback ? finalizedHead - lookback : 0n;
  const fromBlock = configuredFromBlock > lookbackStart ? configuredFromBlock : lookbackStart;

  return {
    fromBlock,
    toBlock: finalizedHead,
    hasRange: fromBlock <= finalizedHead,
    addresses,
    selectors,
  };
}

/**
 * Reads every configured recovery selector across the bounded range and then
 * filters addresses locally. Event ordinals use the same block-local ordering
 * as the historical indexer so the two paths cannot create duplicate evidence.
 */
export async function scanRecoveryTailEvents(input: {
  rpc: RecoveryTailIndexRpc;
  plan: ReturnType<typeof buildRecoveryTailIndexPlan>;
}): Promise<IndexedRecoveryEventInput[]> {
  if (!input.plan.hasRange) return [];
  if (input.plan.fromBlock > BigInt(Number.MAX_SAFE_INTEGER)
    || input.plan.toBlock > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("Recovery block range exceeds safe RPC integers.");
  }
  const allowedAddresses = new Set(input.plan.addresses);
  const allowedSelectors = new Set(input.plan.selectors);
  const blockEventOrdinals = new Map<string, number>();
  const events: IndexedRecoveryEventInput[] = [];
  let continuationToken: string | undefined;

  for (let page = 0; page < 100; page += 1) {
    const response = record(await input.rpc.getEvents({
      from_block: { block_number: Number(input.plan.fromBlock) },
      to_block: { block_number: Number(input.plan.toBlock) },
      chunk_size: 100,
      keys: [[...input.plan.selectors]],
      ...(continuationToken ? { continuation_token: continuationToken } : {}),
    }));
    const pageEvents = Array.isArray(response.events) ? response.events : [];
    for (const candidate of pageEvents) {
      const event = record(candidate);
      const rawTransactionHash = stringField(event, "transaction_hash", "transactionHash");
      const rawBlockHash = stringField(event, "block_hash", "blockHash");
      const blockNumber = bigintField(event, "block_number", "blockNumber");
      const rawContractAddress = stringField(event, "from_address", "fromAddress");
      const keys = Array.isArray(event.keys) ? event.keys.filter((key): key is string => typeof key === "string") : [];
      const data = Array.isArray(event.data) ? event.data.filter((item): item is string => typeof item === "string") : [];
      if (!rawTransactionHash || !rawBlockHash || blockNumber === undefined || !rawContractAddress || !keys[0]) {
        throw new Error("Starknet RPC returned an incomplete finalized recovery event.");
      }
      const transactionHash = normalizeFelt(rawTransactionHash, "Recovery transaction hash");
      const blockHash = normalizeFelt(rawBlockHash, "Recovery block hash");
      if (blockNumber < input.plan.fromBlock || blockNumber > input.plan.toBlock) {
        throw new Error("Starknet RPC returned a recovery event outside the requested range.");
      }
      const contractAddress = normalizeFelt(rawContractAddress, "Recovery event address");
      const eventName = normalizeFelt(keys[0], "Recovery event selector");
      if (!allowedAddresses.has(contractAddress) || !allowedSelectors.has(eventName)) continue;
      const blockIdentity = blockNumber.toString();
      const eventIndex = blockEventOrdinals.get(blockIdentity) ?? 0;
      blockEventOrdinals.set(blockIdentity, eventIndex + 1);
      events.push({
        transactionHash,
        eventIndex,
        blockNumber,
        blockHash,
        contractAddress,
        eventName,
        payload: { keys, data },
      });
    }
    continuationToken = stringField(response, "continuation_token", "continuationToken");
    if (!continuationToken) return events;
  }
  throw new Error("Starknet recovery-event pagination exceeded the safety limit.");
}
