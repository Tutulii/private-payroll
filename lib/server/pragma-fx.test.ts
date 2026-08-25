import { describe, expect, it, vi } from "vitest";
import { readPragmaFxSnapshots } from "./pragma-fx";

describe("Pragma FX adapter", () => {
  it("pins reads to one block and preserves the on-chain aggregated source count", async () => {
    const rpc = {
      getBlockNumber: vi.fn().mockResolvedValue(321),
      callContract: vi.fn()
        .mockResolvedValueOnce(["0x296dcb", "0x8", "0x3e8", "0xc", "0x0", "0x0"])
        .mockResolvedValueOnce(["0xf4240", "0x6", "0x3e8", "0x9", "0x0", "0x0"]),
    };
    const result = await readPragmaFxSnapshots({
      rpc,
      tokens: ["STRK", "USDC"],
      now: new Date(1_010_000),
    });
    expect(result.blockNumber).toBe(321);
    expect(result.snapshots).toMatchObject([
      { baseToken: "STRK", medianPriceAtomic: "27150", aggregatedSourceCount: 12 },
      { baseToken: "USDC", medianPriceAtomic: "1000000", aggregatedSourceCount: 9 },
    ]);
    expect(rpc.callContract).toHaveBeenCalledTimes(2);
    expect(rpc.callContract.mock.calls.every((call) => call[1] === 321)).toBe(true);
  });

  it("rejects stale and under-sourced observations", async () => {
    await expect(readPragmaFxSnapshots({
      rpc: {
        getBlockNumber: vi.fn().mockResolvedValue(1),
        callContract: vi.fn().mockResolvedValue(["0xf4240", "0x6", "0x1", "0x2"]),
      },
      tokens: ["USDC"],
      now: new Date(10_000_000),
    })).rejects.toThrow(/stale|future/);
  });
});
