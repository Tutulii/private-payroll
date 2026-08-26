import { describe, expect, it, vi } from "vitest";
import { readPragmaFxSnapshots, readPragmaProtectedFxSnapshots } from "./pragma-fx";

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

  it("pins protected median and TWAP reads to the same block", async () => {
    const rpc = {
      getBlockNumber: vi.fn().mockResolvedValue(765),
      getBlockTimestamp: vi.fn().mockResolvedValue(100_000),
      callContract: vi.fn()
        .mockResolvedValueOnce(["0x1312d0", "0x6", "0x1866e", "0x5"])
        .mockResolvedValueOnce(["0x124f80", "0x6"]),
    };
    const result = await readPragmaProtectedFxSnapshots({ rpc, tokens: ["STRK"] });
    expect(result).toMatchObject({
      blockNumber: 765,
      blockTimestamp: 100_000,
      snapshots: [{
        pairId: "STRK/USD",
        spotMedianPriceAtomic: "1250000",
        twapPriceAtomic: "1200000",
        selectedPriceAtomic: "1200000",
        conservativePriceAtomic: "1188000",
        sourceCount: 5,
      }],
    });
    expect(rpc.getBlockTimestamp).toHaveBeenCalledWith(765);
    expect(rpc.callContract).toHaveBeenCalledTimes(2);
    expect(rpc.callContract.mock.calls.every((call) => call[1] === 765)).toBe(true);
    expect(rpc.callContract.mock.calls[1][0]).toMatchObject({
      entrypoint: "calculate_twap",
      calldata: expect.arrayContaining(["0xa8c0", "0xdde0"]),
    });
  });

  it("fails closed for stale, under-sourced, unsupported, and unavailable protected pairs", async () => {
    const baseRpc = {
      getBlockNumber: vi.fn().mockResolvedValue(1),
      getBlockTimestamp: vi.fn().mockResolvedValue(100_000),
    };
    await expect(readPragmaProtectedFxSnapshots({
      rpc: {
        ...baseRpc,
        callContract: vi.fn()
          .mockResolvedValueOnce(["0xf4240", "0x6", "0x1", "0x5"])
          .mockResolvedValueOnce(["0xf4240", "0x6"]),
      },
      tokens: ["USDC"],
    })).rejects.toThrow(/stale|future/);
    await expect(readPragmaProtectedFxSnapshots({
      rpc: {
        ...baseRpc,
        callContract: vi.fn()
          .mockResolvedValueOnce(["0xf4240", "0x6", "0x1866e", "0x2"])
          .mockResolvedValueOnce(["0xf4240", "0x6"]),
      },
      tokens: ["USDC"],
    })).rejects.toThrow(/only 2 aggregated sources/);
    await expect(readPragmaProtectedFxSnapshots({
      rpc: { ...baseRpc, callContract: vi.fn() },
      tokens: ["ETH" as never],
    })).rejects.toThrow(/supported PAYO FX token/);
    await expect(readPragmaProtectedFxSnapshots({
      rpc: { ...baseRpc, callContract: vi.fn().mockRejectedValue(new Error("pair missing")) },
      tokens: ["STRK"],
    })).rejects.toMatchObject({ pair: "STRK/USD", component: "median" });
  });
});
