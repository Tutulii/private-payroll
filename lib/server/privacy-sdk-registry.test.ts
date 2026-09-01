import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import {
  deserializePrivacyHistoryCursor,
  deserializePrivacyRegistry,
  mergePrivacyHistory,
  serializePrivacyHistoryCursor,
  serializePrivacyHistoryTransaction,
  serializePrivacyRegistry,
} from "./privacy-sdk-registry";
import { loadPinnedPrivacySdk } from "./privacy-sdk-loader";

const sdkRoot = resolve(
  process.cwd(),
  "node_modules/@starkware-libs/starknet-privacy-sdk",
);

describe("encrypted Privacy SDK state codec", () => {
  it("round-trips channels, notes and discovery cursors without bigint loss", async () => {
    const runtime = await loadPinnedPrivacySdk(sdkRoot);
    const internalUrl = pathToFileURL(
      resolve(sdkRoot, "dist/internal/channel.js"),
    );
    const internal = await import(internalUrl.href);
    const channels = new runtime.sdk.AddressMap([
      [2n, new internal.Channel(41n, 43n, [[7n, { tokenIndex: 1, noteNonce: 3 }]])],
    ]);
    const notes = new runtime.sdk.AddressMap([[7n, [{
      id: 101n,
      amount: 250n,
      created: 12,
      witness: new internal.Witness(43n, 2, 99n),
      viewingKey: 55n,
      sender: 3n,
      open: false,
    }]]]);
    const registry = {
      channels,
      notes,
      cursor: {
        blockId: { block_hash: "0x123" },
        incomingChannels: new runtime.sdk.AddressMap([[3n, {
          channelKey: 43n,
          subchannelIdIndex: 2,
          noteIndexes: new runtime.sdk.AddressMap([[7n, 3]]),
          totalNoteCounts: new runtime.sdk.AddressMap([[7n, 4]]),
        }]]),
      },
    };

    const serialized = serializePrivacyRegistry(registry, runtime.codecs, 1);
    const restored = deserializePrivacyRegistry(
      serialized,
      runtime.codecs,
      runtime.sdk.AddressMap,
    ) as typeof registry;

    expect(restored.channels.get(2n)).toMatchObject({ key: 43n, publicKey: 41n });
    expect(restored.notes.get(7n)?.[0]).toMatchObject({
      id: 101n,
      amount: 250n,
      sender: 3n,
      viewingKey: 55n,
    });
    expect(restored.cursor.incomingChannels.get(3n)?.noteIndexes.get(7n)).toBe(3);
  });

  it("round-trips private history cursors without exposing history rows", () => {
    const serialized = serializePrivacyHistoryCursor({
      subchannels: [{
        channelKey: 1n,
        token: 2n,
        channelKind: "outgoing",
        counterparty: 3n,
        nextIndex: 4,
      }],
      beginBlockNumber: 10,
      historyComplete: false,
    });
    expect(deserializePrivacyHistoryCursor(serialized)).toEqual({
      subchannels: [{
        channelKey: 1n,
        token: 2n,
        channelKind: "outgoing",
        counterparty: 3n,
        nextIndex: 4,
      }],
      beginBlockNumber: 10,
      historyComplete: false,
    });
  });

  it("serializes and deduplicates bounded private history without bigint loss", () => {
    const first = serializePrivacyHistoryTransaction({
      blockNumber: 12,
      transactionHash: 101n,
      notes: [{
        channelKind: "outgoing",
        token: 7n,
        noteIndex: 2,
        noteId: 33n,
        counterparty: 9n,
        amount: 44n,
        salt: 55n,
      }],
      deposits: [{ fromAddress: 1n, token: 7n, amount: 50n }],
      withdrawals: [],
      openNoteDeposits: [],
    });
    const second = serializePrivacyHistoryTransaction({
      blockNumber: 13,
      transactionHash: 102n,
      notes: [],
      deposits: [],
      withdrawals: [{ toAddress: 8n, token: 7n, amount: 3n }],
      openNoteDeposits: [],
      registeredPubkey: 99n,
    });
    expect(first.notes[0]).toMatchObject({ amount: "44", noteId: "0x21" });
    expect(mergePrivacyHistory([first], [first, second])).toEqual([second, first]);
    expect(mergePrivacyHistory([first], [second], 1)).toEqual([second]);
  });

  it("rejects conflicting history for one transaction hash", () => {
    const transaction = serializePrivacyHistoryTransaction({
      blockNumber: 12,
      transactionHash: 101n,
      notes: [],
      deposits: [],
      withdrawals: [],
      openNoteDeposits: [],
    });
    expect(() => mergePrivacyHistory([transaction], [{
      ...transaction,
      blockNumber: 13,
    }])).toThrow("conflicting history");
  });
});
