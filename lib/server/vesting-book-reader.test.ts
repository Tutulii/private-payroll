import { describe, expect, it, vi } from "vitest";
import {
  appendPayrollBookRoot,
  initialPayrollBookRoot,
  type PayrollBookCheckpoint,
} from "@/lib/domain/vesting-tax";
import { readTrustedPayrollBookSnapshot } from "./vesting-book-reader";

const chainId = "0x534e5f4d41494e";
const sealAddress = "0x456";
const ownerAddress = "0x123";
const periodStart = 1n;
const periodEnd = 1_000n;
const blockNumber = 789;
const entries = [`0x${"11".repeat(32)}`, `0x${"22".repeat(32)}`] as const;

function checkpoint(): PayrollBookCheckpoint {
  const base: PayrollBookCheckpoint = {
    checkpointVersion: "payo-payroll-book-checkpoint-v1",
    chainId,
    sealAddress,
    ownerAddress,
    periodStart: periodStart.toString(),
    periodEnd: periodEnd.toString(),
    entryCount: entries.length,
    accumulatorRoot: `0x${"00".repeat(32)}`,
  };
  let root = initialPayrollBookRoot(base);
  entries.forEach((entryCommitment, index) => {
    root = appendPayrollBookRoot({ previousRoot: root, entryCommitment, index });
  });
  return { ...base, accumulatorRoot: root };
}

function splitCommitment(value: string): [string, string] {
  const parsed = BigInt(value);
  return [
    (parsed & ((1n << 128n) - 1n)).toString(),
    (parsed >> 128n).toString(),
  ];
}

describe("PAYO trusted payroll-book reader", () => {
  it("pins every read to one block and reconstructs the exact accumulator", async () => {
    const expected = checkpoint();
    const callContract = vi.fn().mockImplementation((call, pinnedBlock) => {
      expect(pinnedBlock).toBe(blockNumber);
      if (call.entrypoint === "get_payroll_book") {
        return Promise.resolve(["1", String(entries.length), expected.accumulatorRoot, "700"]);
      }
      const index = Number(BigInt(call.calldata[3]));
      return Promise.resolve(splitCommitment(entries[index]));
    });
    const snapshot = await readTrustedPayrollBookSnapshot({
      rpc: { callContract },
      chainId,
      sealAddress,
      ownerAddress,
      periodStart,
      periodEnd,
      blockNumber,
      observedAt: new Date("2026-09-04T00:00:00.000Z"),
    });
    expect(snapshot.checkpoint).toEqual({
      ...expected,
      ownerAddress: `0x${BigInt(ownerAddress).toString(16).padStart(64, "0")}`,
      sealAddress: `0x${BigInt(sealAddress).toString(16).padStart(64, "0")}`,
    });
    expect(snapshot.entries).toEqual(entries.map((entryCommitment, index) => ({
      index,
      entryCommitment,
    })));
    expect(callContract).toHaveBeenCalledTimes(3);
  });

  it("represents an absent zero-entry book with its deterministic initial root", async () => {
    const snapshot = await readTrustedPayrollBookSnapshot({
      rpc: { callContract: vi.fn().mockResolvedValue(["0", "0", "0", "0"]) },
      chainId,
      sealAddress,
      ownerAddress,
      periodStart,
      periodEnd,
      blockNumber,
    });
    expect(snapshot.entries).toEqual([]);
    expect(snapshot.checkpoint.accumulatorRoot).toBe(initialPayrollBookRoot(snapshot.checkpoint));
  });

  it.each([
    [["2", "0", "0", "0"], "Cairo boolean"],
    [["0", "1", "0", "0"], "absent payroll book"],
    [["1", "0", "0", "1"], "cannot contain zero"],
    [["1"], "expected 4"],
  ])("rejects malformed or contradictory book state", async (response, message) => {
    await expect(readTrustedPayrollBookSnapshot({
      rpc: { callContract: vi.fn().mockResolvedValue(response) },
      chainId,
      sealAddress,
      ownerAddress,
      periodStart,
      periodEnd,
      blockNumber,
    })).rejects.toThrow(message);
  });

  it("rejects an entry list that does not reconstruct the on-chain root", async () => {
    const callContract = vi.fn().mockImplementation((call) => call.entrypoint === "get_payroll_book"
      ? Promise.resolve(["1", "1", `0x03${"33".repeat(31)}`, "700"])
      : Promise.resolve(splitCommitment(entries[0])));
    await expect(readTrustedPayrollBookSnapshot({
      rpc: { callContract },
      chainId,
      sealAddress,
      ownerAddress,
      periodStart,
      periodEnd,
      blockNumber,
    })).rejects.toThrow("does not reconstruct");
  });
});
