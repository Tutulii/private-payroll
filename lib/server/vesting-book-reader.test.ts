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

function bookRecord(input: {
  exists?: string;
  entryCount?: string;
  contributorCount?: string;
  disclosedEntryCount?: string;
  undisclosedEntryCount?: string;
  ordinaryEntryCount?: string;
  vestingEntryCount?: string;
  agentEntryCount?: string;
  claimEntryCount?: string;
  remediationEntryCount?: string;
  strkGross?: string;
  strkDeductions?: string;
  strkNet?: string;
  usdcGross?: string;
  usdcDeductions?: string;
  usdcNet?: string;
  accumulatorRoot?: string;
  updatedAt?: string;
} = {}): string[] {
  const u256 = (value = "0") => splitCommitment(value);
  return [
    input.exists ?? "1",
    input.entryCount ?? "2",
    input.contributorCount ?? "2",
    input.disclosedEntryCount ?? "2",
    input.undisclosedEntryCount ?? "0",
    input.ordinaryEntryCount ?? "2",
    input.vestingEntryCount ?? "0",
    input.agentEntryCount ?? "0",
    input.claimEntryCount ?? "0",
    input.remediationEntryCount ?? "0",
    ...u256(input.strkGross ?? "10"),
    ...u256(input.strkDeductions ?? "3"),
    ...u256(input.strkNet ?? "7"),
    ...u256(input.usdcGross ?? "20"),
    ...u256(input.usdcDeductions ?? "5"),
    ...u256(input.usdcNet ?? "15"),
    input.accumulatorRoot ?? "0",
    input.updatedAt ?? "700",
  ];
}

describe("PAYO trusted payroll-book reader", () => {
  it("pins every read to one block and reconstructs the exact accumulator", async () => {
    const expected = checkpoint();
    const callContract = vi.fn().mockImplementation((call, pinnedBlock) => {
      expect(pinnedBlock).toBe(blockNumber);
      if (call.entrypoint === "get_payroll_book") {
        return Promise.resolve(bookRecord({ accumulatorRoot: expected.accumulatorRoot }));
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
      rpc: { callContract: vi.fn().mockResolvedValue(Array.from({ length: 24 }, () => "0")) },
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
    [bookRecord({ exists: "2" }), "Cairo boolean"],
    [bookRecord({ exists: "0" }), "absent payroll book"],
    [bookRecord({ entryCount: "0", disclosedEntryCount: "0", ordinaryEntryCount: "0" }), "cannot contain zero"],
    [["1"], "expected 24"],
    [bookRecord({ disclosedEntryCount: "1" }), "disclosure counters"],
    [bookRecord({ ordinaryEntryCount: "1" }), "kind counters"],
    [bookRecord({ strkNet: "8" }), "STRK totals"],
    [bookRecord({ usdcDeductions: "6" }), "USDC totals"],
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
      ? Promise.resolve(bookRecord({
        entryCount: "1",
        contributorCount: "1",
        disclosedEntryCount: "1",
        ordinaryEntryCount: "1",
        accumulatorRoot: `0x03${"33".repeat(31)}`,
      }))
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

  it("decodes the deployed Mainnet ABI and reconstructs a real registered payroll book", async () => {
    const mainnetSeal = "0x5208cc07cb4153235ab5c6ecd1936ee77f9be7a2ea09f6cc69518a6362493f";
    const mainnetOwner = "0x0309eca7155f96dc41d77063a9f9948bb3b99858259022f205df79a986aacff4";
    const mainnetPeriodStart = 1_767_225_600n;
    const mainnetPeriodEnd = 1_798_761_600n;
    const mainnetEntry = "0xd887df1d0ff3be13dc315fc6c38f9b9e062848f47a9bc76f911b6a93a5f06a61";
    const mainnetRpcRoot = "0x19d891983281ad379261363dc5769b0c3967227ebefe61964dfa93e7d327bf3";
    const mainnetRoot = "0x019d891983281ad379261363dc5769b0c3967227ebefe61964dfa93e7d327bf3";
    const callContract = vi.fn().mockImplementation((call) => call.entrypoint === "get_payroll_book"
      ? Promise.resolve([
        "0x1", "0x1", "0x1", "0x1", "0x0", "0x1", "0x0", "0x0", "0x0", "0x0",
        "0x0", "0x0", "0x0", "0x0", "0x0", "0x0",
        "0xc350", "0x0", "0x2af8", "0x0", "0x9858", "0x0",
        mainnetRpcRoot, "0x6a9cca18",
      ])
      : Promise.resolve(splitCommitment(mainnetEntry)));

    const snapshot = await readTrustedPayrollBookSnapshot({
      rpc: { callContract },
      chainId,
      sealAddress: mainnetSeal,
      ownerAddress: mainnetOwner,
      periodStart: mainnetPeriodStart,
      periodEnd: mainnetPeriodEnd,
      blockNumber: 14_437_900,
      observedAt: new Date("2026-09-06T00:00:00.000Z"),
    });

    expect(snapshot.checkpoint).toMatchObject({ entryCount: 1, accumulatorRoot: mainnetRoot });
    expect(snapshot.entries).toEqual([{ index: 0, entryCommitment: mainnetEntry }]);
  });
});
