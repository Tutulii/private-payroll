import { describe, expect, it } from "vitest";
import type { AgentExecutionRequest } from "@/lib/domain/capability";
import {
  emptyDirectPrivacyState,
} from "@/lib/domain/direct-privacy";
import type { PrivacyDiscovery } from "./privacy-sdk-loader";
import { discoverDirectPrivacySnapshot } from "./direct-privacy-agent-driver";
import { serializePrivacyHistoryCursor } from "./privacy-sdk-registry";
import {
  findDirectPrivacyReadinessFailure,
  isExactPinnedBlockReference,
  type DirectPrivacyDiscoveredChannel,
} from "./direct-privacy-discovery";

function channel(input: {
  registered?: boolean;
  open?: boolean;
  tokens?: bigint[];
} = {}): DirectPrivacyDiscoveredChannel {
  return {
    publicKey: input.registered === false ? undefined : 11n,
    key: input.open === false ? undefined : 22n,
    tokens: new Map((input.tokens ?? [7n]).map((token, index) => [token, {
      tokenIndex: index,
      noteNonce: 0,
    }])),
  };
}

const snapshotConfig = {
  policyAccountAddress: "0x777",
  tokenAddresses: { STRK: "0x111", USDC: "0x222" },
} as const;

const snapshotRequest = {
  requestVersion: "payo-agent-execution-v1",
  runId: "payroll-run-0001",
  intents: [{
    intentVersion: "payo-payment-intent-v1",
    intentId: "intent-strk-0001",
    organizationId: "organization-0001",
    runId: "payroll-run-0001",
    action: "request_execution",
    token: "STRK",
    recipientAddress: "0x456",
    amountAtomic: "10",
    purposeCode: "private_payroll",
    capabilityNonce: "capability-nonce-0001",
    createdAt: "2026-08-30T00:00:00.000Z",
    validUntil: "2026-08-30T00:05:00.000Z",
  }],
} satisfies AgentExecutionRequest;

describe("direct private block pin and channel readiness", () => {
  it("accepts only the exact response hash", () => {
    expect(isExactPinnedBlockReference("0xabc", "0x0abc")).toBe(true);
    expect(isExactPinnedBlockReference({ block_hash: "0xabc" }, "0xabc")).toBe(true);
    expect(isExactPinnedBlockReference({ block_number: 12 }, "0xabc")).toBe(false);
    expect(isExactPinnedBlockReference("latest", "0xabc")).toBe(false);
    expect(isExactPinnedBlockReference("0xabd", "0xabc")).toBe(false);
  });

  it("recovers an empty local registry from one pinned snapshot and encryptable history", async () => {
    const blockHash = "0xabc" as const;
    const treasury = 0x777n;
    const recipient = 0x456n;
    const token = 0x111n;
    const channels = new Map<bigint, DirectPrivacyDiscoveredChannel>([
      [treasury, channel({ tokens: [token] })],
      [recipient, channel({ tokens: [token] })],
    ]);
    const notes = new Map<bigint, unknown[]>([[token, []]]);
    const notesCursor = { blockId: blockHash, incomingChannels: new Map() };
    const historyCursor = {
      subchannels: [],
      beginBlockNumber: 4,
      historyComplete: true,
    };
    const discovery = {
      discoverNotes: async (_address: bigint, _viewingKey: bigint, params?: Record<string, unknown>) => {
        expect(params?.blockIdentifier).toBe(blockHash);
        return { timestamp: { block_hash: blockHash }, notes, cursor: notesCursor };
      },
      discoverChannels: async (
        _address: bigint,
        _viewingKey: bigint,
        recipients: bigint[] | "all" | "total-only",
        params?: Record<string, unknown>,
      ) => {
        expect(recipients).toBe("all");
        expect(params?.blockIdentifier).toBe(blockHash);
        return { timestamp: blockHash, channels, total: 2 };
      },
      fetchHistory: async (
        _address: bigint,
        _notesCursor: unknown,
        _channelCursor: unknown,
        options?: Record<string, unknown>,
      ) => {
        expect(options?.blockIdentifier).toBe(blockHash);
        return {
          blockRef: blockHash,
          transactions: [{
            blockNumber: 4,
            transactionHash: 0x99n,
            notes: [{
              channelKind: "outgoing",
              token,
              noteIndex: 0,
              noteId: 0x88n,
              counterparty: recipient,
              amount: 10n,
              salt: 7n,
            }],
            deposits: [],
            withdrawals: [],
            openNoteDeposits: [],
          }],
          cursor: historyCursor,
        };
      },
    } as unknown as PrivacyDiscovery;
    const snapshot = await discoverDirectPrivacySnapshot({
      discovery,
      pinned: { number: 4, hash: blockHash, timestamp: 10 },
      context: { config: snapshotConfig, viewingKey: "0x123", state: emptyDirectPrivacyState() },
      job: { request: snapshotRequest },
    });
    expect(snapshot.channelTotal).toBe(2);
    expect(snapshot.registry.notes).toBe(notes);
    expect(snapshot.history).toEqual([
      expect.objectContaining({ transactionHash: "0x99", blockNumber: 4 }),
    ]);
    expect(snapshot.historyCursor).toEqual(historyCursor);
    expect(snapshot.historyPinnedBlock).toEqual({ number: 4, hash: blockHash });
  });

  it("restarts history backfill from the canonical pin after its old branch reorgs", async () => {
    const currentHash = "0xbbb" as const;
    const oldHash = "0xaaa" as const;
    const token = 0x111n;
    const channels = new Map<bigint, DirectPrivacyDiscoveredChannel>([
      [0x777n, channel({ tokens: [token] })],
      [0x456n, channel({ tokens: [token] })],
    ]);
    const freshCursor = {
      subchannels: [{
        channelKey: 22n,
        token,
        channelKind: "outgoing",
        counterparty: 0x456n,
        nextIndex: 1,
      }],
      beginBlockNumber: 8,
      historyComplete: false,
    };
    let historyCalls = 0;
    const discovery = {
      discoverNotes: async () => ({
        timestamp: currentHash,
        notes: new Map([[token, []]]),
        cursor: { blockId: currentHash, incomingChannels: new Map() },
      }),
      discoverChannels: async () => ({
        timestamp: currentHash,
        channels,
        total: 2,
      }),
      fetchHistory: async (
        _address: bigint,
        _notes: unknown,
        _channels: unknown,
        options?: Record<string, unknown>,
      ) => {
        historyCalls += 1;
        if (options?.blockIdentifier === oldHash) {
          throw Object.assign(new Error("Block reorged during /v1/history"), { name: "ReorgError" });
        }
        return {
          blockRef: currentHash,
          transactions: [{
            blockNumber: 8,
            transactionHash: 0x102n,
            notes: [],
            deposits: [],
            withdrawals: [],
            openNoteDeposits: [],
          }],
          cursor: freshCursor,
        };
      },
    } as unknown as PrivacyDiscovery;
    const state = emptyDirectPrivacyState();
    state.history = [{
      blockNumber: 7,
      transactionHash: "0x101",
      notes: [],
      deposits: [],
      withdrawals: [],
      openNoteDeposits: [],
      registeredPubkey: null,
    }];
    state.historyCursor = {
      subchannels: [],
      beginBlockNumber: 7,
      historyComplete: false,
    };
    state.historyPinnedBlock = { number: 7, hash: oldHash };

    const snapshot = await discoverDirectPrivacySnapshot({
      discovery,
      pinned: { number: 8, hash: currentHash, timestamp: 10 },
      context: { config: snapshotConfig, viewingKey: "0x123", state },
      job: { request: snapshotRequest },
    });
    expect(historyCalls).toBe(2);
    expect(snapshot.history.map(({ transactionHash }) => transactionHash)).toEqual(["0x102", "0x101"]);
    expect(snapshot.historyCursor).toEqual(serializePrivacyHistoryCursor(freshCursor));
    expect(snapshot.historyPinnedBlock).toEqual({ number: 8, hash: currentHash });
  });

  it("accepts a ready treasury and recipient token channel", () => {
    const channels = new Map<bigint, DirectPrivacyDiscoveredChannel>([
      [1n, channel()],
      [2n, channel()],
    ]);
    expect(findDirectPrivacyReadinessFailure({
      channels,
      treasuryAddress: 1n,
      requirements: [{ recipient: 1n, token: 7n }, { recipient: 2n, token: 7n }],
    })).toBeNull();
  });

  it("allows registered missing channel state for bounded atomic setup", () => {
    const channels = new Map<bigint, DirectPrivacyDiscoveredChannel>([
      [1n, channel({ open: false })],
      [2n, channel({ tokens: [8n] })],
    ]);
    expect(findDirectPrivacyReadinessFailure({
      channels,
      treasuryAddress: 1n,
      requirements: [{ recipient: 1n, token: 7n }, { recipient: 2n, token: 7n }],
      allowSetup: true,
    })).toBeNull();
  });

  it("does not let atomic setup bypass recipient registration", () => {
    expect(findDirectPrivacyReadinessFailure({
      channels: new Map([[1n, channel()]]),
      treasuryAddress: 1n,
      requirements: [{ recipient: 2n, token: 7n }],
      allowSetup: true,
    })?.code).toBe("DIRECT_RECIPIENT_REGISTRATION_REQUIRED");
  });

  it.each([
    {
      title: "unregistered treasury",
      channels: new Map([[2n, channel()]]),
      code: "DIRECT_TREASURY_REGISTRATION_REQUIRED",
    },
    {
      title: "unregistered recipient",
      channels: new Map([[1n, channel()]]),
      code: "DIRECT_RECIPIENT_REGISTRATION_REQUIRED",
    },
    {
      title: "missing channel",
      channels: new Map([[1n, channel()], [2n, channel({ open: false })]]),
      code: "DIRECT_CHANNEL_SETUP_REQUIRED",
    },
    {
      title: "missing token subchannel",
      channels: new Map([[1n, channel()], [2n, channel({ tokens: [8n] })]]),
      code: "DIRECT_TOKEN_CHANNEL_SETUP_REQUIRED",
    },
  ])("fails before proving for $title", ({ channels, code }) => {
    expect(findDirectPrivacyReadinessFailure({
      channels,
      treasuryAddress: 1n,
      requirements: [{ recipient: 1n, token: 7n }, { recipient: 2n, token: 7n }],
    })?.code).toBe(code);
  });

  it("rejects malformed token nonce state", () => {
    const malformed = channel();
    malformed.tokens = new Map([[7n, { tokenIndex: 0, noteNonce: -1 }]]);
    expect(findDirectPrivacyReadinessFailure({
      channels: new Map([[1n, channel()], [2n, malformed]]),
      treasuryAddress: 1n,
      requirements: [{ recipient: 1n, token: 7n }, { recipient: 2n, token: 7n }],
    })?.code).toBe("DIRECT_DISCOVERY_RESPONSE_INVALID");
  });
});
