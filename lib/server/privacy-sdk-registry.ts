import "server-only";

import {
  directPrivacyHistoryTransactionSchema,
  directPrivacyHistoryCursorSchema,
  serializedPrivateRegistrySchema,
  type DirectPrivacyHistoryTransaction,
  type SerializedPrivateRegistry,
} from "@/lib/domain/direct-privacy";
import type { PrivacySdkCodecs } from "./privacy-sdk-loader";

type AddressMapLike<T> = {
  entries(): IterableIterator<[bigint, T]>;
};

type SdkRegistry = {
  channels: AddressMapLike<unknown>;
  notes: AddressMapLike<Array<{
    id: bigint;
    amount: bigint;
    created?: number;
    witness: unknown;
    viewingKey?: string | number | bigint;
    sender: string | number | bigint;
    open?: boolean;
  }>>;
  cursor?: {
    blockId: unknown;
    incomingChannels: AddressMapLike<{
      channelKey: bigint;
      subchannelIdIndex: number;
      noteIndexes: AddressMapLike<number>;
      totalNoteCounts: AddressMapLike<number>;
    }>;
  };
};

type AddressMapConstructor = new <T>(
  entries?: Iterable<[bigint, T]>,
) => AddressMapLike<T> & { set(key: bigint, value: T): unknown };

function felt(value: string | number | bigint): `0x${string}` {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= 1n << 256n) throw new Error("Private registry contains a non-canonical felt.");
  return `0x${parsed.toString(16)}`;
}

function blockIdentifier(input: unknown): number | "latest" | "pre_confirmed" | { block_number: number } | { block_hash: `0x${string}` } {
  if (typeof input === "number" && Number.isInteger(input) && input >= 0) return input;
  if (input === "latest" || input === "pre_confirmed") return input;
  if (input && typeof input === "object") {
    if ("block_number" in input && Number.isInteger((input as { block_number: unknown }).block_number)) {
      return { block_number: (input as { block_number: number }).block_number };
    }
    if ("block_hash" in input) return { block_hash: felt(String((input as { block_hash: unknown }).block_hash)) };
  }
  throw new Error("Private registry cursor has an unsupported block identifier.");
}

export function serializePrivacyRegistry(
  registryInput: unknown,
  codecs: PrivacySdkCodecs,
  channelTotal: number | null = null,
): SerializedPrivateRegistry {
  const registry = registryInput as SdkRegistry;
  if (!registry?.channels?.entries || !registry?.notes?.entries) {
    throw new Error("The Privacy SDK returned an invalid private registry.");
  }
  return serializedPrivateRegistrySchema.parse({
    version: "payo-private-registry-v1",
    channels: Array.from(registry.channels.entries(), ([recipient, channel]) => ({
      recipient: felt(recipient),
      channel: codecs.channelSerde.encode(channel),
    })),
    notes: Array.from(registry.notes.entries(), ([token, notes]) => ({
      token: felt(token),
      notes: notes.map((note) => ({
        id: felt(note.id),
        amount: BigInt(note.amount).toString(),
        created: note.created ?? null,
        witness: codecs.witnessSerde.encode(note.witness),
        viewingKey: note.viewingKey === undefined ? null : felt(note.viewingKey),
        sender: felt(note.sender),
        open: note.open ?? false,
      })),
    })),
    cursor: registry.cursor ? {
      blockId: blockIdentifier(registry.cursor.blockId),
      incomingChannels: Array.from(
        registry.cursor.incomingChannels.entries(),
        ([sender, cursor]) => ({
          sender: felt(sender),
          channelKey: felt(cursor.channelKey),
          subchannelIdIndex: cursor.subchannelIdIndex,
          noteIndexes: Array.from(cursor.noteIndexes.entries(), ([token, index]) => [felt(token), index]),
          totalNoteCounts: Array.from(cursor.totalNoteCounts.entries(), ([token, count]) => [felt(token), count]),
        }),
      ),
    } : null,
    channelTotal,
  });
}

export function deserializePrivacyRegistry(
  serializedInput: SerializedPrivateRegistry,
  codecs: PrivacySdkCodecs,
  AddressMap: AddressMapConstructor,
): unknown {
  const serialized = serializedPrivateRegistrySchema.parse(serializedInput);
  const channels = new AddressMap(serialized.channels.map(({ recipient, channel }) => [
    BigInt(recipient),
    codecs.channelSerde.decode(channel),
  ] as [bigint, unknown]));
  const notes = new AddressMap(serialized.notes.map(({ token, notes: tokenNotes }) => [
    BigInt(token),
    tokenNotes.map((note) => ({
      id: BigInt(note.id),
      amount: BigInt(note.amount),
      ...(note.created === null ? {} : { created: note.created }),
      witness: codecs.witnessSerde.decode(note.witness),
      ...(note.viewingKey === null ? {} : { viewingKey: BigInt(note.viewingKey) }),
      sender: BigInt(note.sender),
      ...(note.open ? { open: true } : {}),
    })),
  ] as [bigint, unknown[]]));
  const cursor = serialized.cursor ? {
    blockId: serialized.cursor.blockId,
    incomingChannels: new AddressMap(serialized.cursor.incomingChannels.map((entry) => [
      BigInt(entry.sender),
      {
        channelKey: BigInt(entry.channelKey),
        subchannelIdIndex: entry.subchannelIdIndex,
        noteIndexes: new AddressMap(entry.noteIndexes.map(([token, index]) => [BigInt(token), index])),
        totalNoteCounts: new AddressMap(entry.totalNoteCounts.map(([token, count]) => [BigInt(token), count])),
      },
    ])),
  } : undefined;
  return { channels, notes, ...(cursor ? { cursor } : {}) };
}

export function serializePrivacyHistoryCursor(input: unknown) {
  const cursor = input as {
    subchannels?: Array<{
      channelKey: bigint;
      token: bigint;
      channelKind: string;
      counterparty: bigint;
      nextIndex?: number;
    }>;
    beginBlockNumber?: number;
    historyComplete?: boolean;
  };
  return directPrivacyHistoryCursorSchema.parse({
    subchannels: (cursor.subchannels ?? []).map((entry) => ({
      channelKey: felt(entry.channelKey),
      token: felt(entry.token),
      channelKind: entry.channelKind,
      counterparty: felt(entry.counterparty),
      nextIndex: entry.nextIndex ?? null,
    })),
    beginBlockNumber: cursor.beginBlockNumber ?? null,
    historyComplete: cursor.historyComplete ?? false,
  });
}

export function deserializePrivacyHistoryCursor(input: unknown) {
  const cursor = directPrivacyHistoryCursorSchema.parse(input);
  return {
    subchannels: cursor.subchannels.map((entry) => ({
      channelKey: BigInt(entry.channelKey),
      token: BigInt(entry.token),
      channelKind: entry.channelKind,
      counterparty: BigInt(entry.counterparty),
      ...(entry.nextIndex === null ? {} : { nextIndex: entry.nextIndex }),
    })),
    ...(cursor.beginBlockNumber === null ? {} : { beginBlockNumber: cursor.beginBlockNumber }),
    historyComplete: cursor.historyComplete,
  };
}

type SdkHistoryTransaction = {
  blockNumber: number;
  transactionHash: bigint;
  notes: Array<{
    channelKind: string;
    token: bigint;
    noteIndex: number;
    noteId: bigint;
    counterparty: bigint;
    amount: bigint;
    salt: bigint;
  }>;
  deposits: Array<{ fromAddress: bigint; token: bigint; amount: bigint }>;
  withdrawals: Array<{ toAddress: bigint; token: bigint; amount: bigint }>;
  openNoteDeposits: Array<{
    depositor: bigint;
    token: bigint;
    noteId: bigint;
    amount: bigint;
  }>;
  registeredPubkey?: bigint;
};

/** Converts SDK history into a JSON-safe shape before it enters treasury encryption. */
export function serializePrivacyHistoryTransaction(
  input: unknown,
): DirectPrivacyHistoryTransaction {
  const transaction = input as SdkHistoryTransaction;
  if (!transaction || !Array.isArray(transaction.notes)) {
    throw new Error("The Privacy SDK returned an invalid private-history transaction.");
  }
  return directPrivacyHistoryTransactionSchema.parse({
    blockNumber: transaction.blockNumber,
    transactionHash: felt(transaction.transactionHash),
    notes: transaction.notes.map((note) => ({
      channelKind: note.channelKind,
      token: felt(note.token),
      noteIndex: note.noteIndex,
      noteId: felt(note.noteId),
      counterparty: felt(note.counterparty),
      amount: BigInt(note.amount).toString(),
      salt: felt(note.salt),
    })),
    deposits: transaction.deposits.map((deposit) => ({
      fromAddress: felt(deposit.fromAddress),
      token: felt(deposit.token),
      amount: BigInt(deposit.amount).toString(),
    })),
    withdrawals: transaction.withdrawals.map((withdrawal) => ({
      toAddress: felt(withdrawal.toAddress),
      token: felt(withdrawal.token),
      amount: BigInt(withdrawal.amount).toString(),
    })),
    openNoteDeposits: transaction.openNoteDeposits.map((deposit) => ({
      depositor: felt(deposit.depositor),
      token: felt(deposit.token),
      noteId: felt(deposit.noteId),
      amount: BigInt(deposit.amount).toString(),
    })),
    registeredPubkey: transaction.registeredPubkey === undefined
      ? null
      : felt(transaction.registeredPubkey),
  });
}

/**
 * Merge newest-first pages without accepting two different plaintexts for the
 * same Starknet transaction hash. The result remains bounded before encryption.
 */
export function mergePrivacyHistory(
  existing: readonly DirectPrivacyHistoryTransaction[],
  incoming: readonly DirectPrivacyHistoryTransaction[],
  maximum = 1_024,
): DirectPrivacyHistoryTransaction[] {
  if (!Number.isInteger(maximum) || maximum < 1 || maximum > 1_024) {
    throw new Error("Private-history retention is outside PAYO's bound.");
  }
  const byHash = new Map<string, DirectPrivacyHistoryTransaction>();
  for (const raw of [...existing, ...incoming]) {
    const transaction = directPrivacyHistoryTransactionSchema.parse(raw);
    const key = BigInt(transaction.transactionHash).toString(16);
    const prior = byHash.get(key);
    if (prior && JSON.stringify(prior) !== JSON.stringify(transaction)) {
      throw new Error("The private indexer returned conflicting history for one transaction.");
    }
    byHash.set(key, transaction);
  }
  return [...byHash.values()]
    .sort((left, right) => right.blockNumber - left.blockNumber
      || (BigInt(right.transactionHash) > BigInt(left.transactionHash) ? 1 : -1))
    .slice(0, maximum);
}
