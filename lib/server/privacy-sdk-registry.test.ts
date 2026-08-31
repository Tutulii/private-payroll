import { describe, expect, it } from "vitest";
import {
  deserializePrivacyHistoryCursor,
  deserializePrivacyRegistry,
  serializePrivacyHistoryCursor,
  serializePrivacyRegistry,
} from "./privacy-sdk-registry";
import { loadPinnedPrivacySdk } from "./privacy-sdk-loader";

const sdkRoot = "/data/data/com.termux/files/usr/tmp/payo-starknet-privacy-rc2/sdk";

describe("encrypted Privacy SDK state codec", () => {
  it("round-trips channels, notes and discovery cursors without bigint loss", async () => {
    const runtime = await loadPinnedPrivacySdk(sdkRoot);
    const internal = await import(
      "/data/data/com.termux/files/usr/tmp/payo-starknet-privacy-rc2/sdk/dist/internal/channel.js"
    );
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
});
