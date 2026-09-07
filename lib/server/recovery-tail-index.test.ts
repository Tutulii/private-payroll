import { describe, expect, it, vi } from "vitest";
import {
  buildRecoveryTailIndexPlan,
  scanRecoveryTailEvents,
} from "./recovery-tail-index";

const base = {
  configuredFromBlock: 100n,
  chainHead: 1_000n,
  finalityLag: 2,
  lookbackBlocks: 128,
  addresses: ["0x0bbb", "0x0aaa"],
  selectors: ["0x02", "0x01"],
};

describe("approval recovery tail index", () => {
  it("builds a normalized finalized near-head range", () => {
    const plan = buildRecoveryTailIndexPlan(base);

    expect(plan).toMatchObject({
      fromBlock: 871n,
      toBlock: 998n,
      hasRange: true,
      addresses: ["0xaaa", "0xbbb"],
      selectors: ["0x1", "0x2"],
    });
  });

  it("never scans before the configured deployment floor", () => {
    expect(buildRecoveryTailIndexPlan({
      ...base,
      configuredFromBlock: 950n,
    }).fromBlock).toBe(950n);
  });

  it("uses the historical indexer's block-local ordinal after filtering addresses", async () => {
    const plan = buildRecoveryTailIndexPlan(base);
    const getEvents = vi.fn().mockResolvedValue({
      events: [{
        block_number: 997,
        block_hash: "0xb997",
        transaction_hash: "0x0feed",
        from_address: "0x999",
        keys: ["0x1"],
        data: [],
      }, {
        block_number: 997,
        block_hash: "0xb997",
        transaction_hash: "0xfeed",
        from_address: "0x0bbb",
        keys: ["0x02"],
        data: ["0xcafe"],
      }],
    });

    await expect(scanRecoveryTailEvents({ rpc: { getEvents }, plan })).resolves.toEqual([{
      blockNumber: 997n,
      blockHash: "0xb997",
      transactionHash: "0xfeed",
      eventIndex: 0,
      contractAddress: "0xbbb",
      eventName: "0x2",
      payload: { keys: ["0x02"], data: ["0xcafe"] },
    }]);
    expect(getEvents).toHaveBeenCalledWith(expect.objectContaining({
      from_block: { block_number: 871 },
      to_block: { block_number: 998 },
      keys: [["0x1", "0x2"]],
    }));
    expect(getEvents.mock.calls[0][0]).not.toHaveProperty("address");
  });

  it("keeps pagination inside the same finalized range", async () => {
    const plan = buildRecoveryTailIndexPlan(base);
    const getEvents = vi.fn()
      .mockResolvedValueOnce({ events: [], continuation_token: "next" })
      .mockResolvedValueOnce({ events: [] });

    await expect(scanRecoveryTailEvents({ rpc: { getEvents }, plan })).resolves.toEqual([]);
    expect(getEvents).toHaveBeenCalledTimes(2);
    expect(getEvents.mock.calls[1][0]).toMatchObject({ continuation_token: "next" });
  });
});
