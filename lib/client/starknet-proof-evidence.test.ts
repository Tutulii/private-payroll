import { describe, expect, it, vi } from "vitest";
import { hash } from "starknet";
import { verifyLiveProofTransaction } from "./starknet-proof-evidence";

const now = new Date("2026-08-28T07:00:00.000Z");
const proofEvent = (sealAddress = "0x456") => ({
  from_address: sealAddress,
  keys: [hash.getSelectorFromName("SealedShardVerified"), "0x7", "0x8", "0x1"],
  data: [],
});

describe("live Starknet proof evidence", () => {
  it("recognizes a successful accepted proof transaction", async () => {
    const reader = { getTransactionReceipt: vi.fn().mockResolvedValue({
      finality_status: "ACCEPTED_ON_L2",
      execution_status: "SUCCEEDED",
    }) };
    await expect(verifyLiveProofTransaction({ transactionHash: "0x123", reader, now })).resolves.toEqual({
      status: "confirmed",
      transactionHash: "0x123",
      finalityStatus: "ACCEPTED_ON_L2",
      executionStatus: "SUCCEEDED",
      checkedAt: now.toISOString(),
    });
  });

  it("verifies the proof version against both on-chain seal shards", async () => {
    const reader = {
      getTransactionReceipt: vi.fn().mockResolvedValue({
        finality_status: "ACCEPTED_ON_L2",
        execution_status: "SUCCEEDED",
        events: [proofEvent()],
      }),
      callContract: vi.fn().mockImplementation(async (call: { entrypoint: string; calldata?: string[] }) => {
        if (call.entrypoint === "get_run_status") return ["0x5"];
        if (call.entrypoint === "is_sealed_shard_verified") return ["0x1"];
        throw new Error("Unexpected contract read");
      }),
      getChainId: vi.fn().mockResolvedValue("0x1"),
    };
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x123",
      proofState: {
        chainId: "0x1",
        sealAddress: "0x456",
        runNullifierHigh: "7",
        runNullifierLow: "8",
        proofVersion: "4",
      },
      expectedSealAddress: "0x456",
      reader,
      now,
    })).resolves.toMatchObject({
      status: "confirmed",
      proofStateStatus: "verified",
      proofStateValue: 5,
      shardsVerified: [true, true],
    });
    expect(reader.callContract).toHaveBeenCalledTimes(3);
  });

  it("does not describe a receipt as proof-verified when the seal state disagrees", async () => {
    const reader = {
      getTransactionReceipt: vi.fn().mockResolvedValue({
        finality_status: "ACCEPTED_ON_L2",
        execution_status: "SUCCEEDED",
        events: [proofEvent()],
      }),
      callContract: vi.fn().mockImplementation(async (call: { entrypoint: string }) => (
        call.entrypoint === "get_run_status" ? ["0x2"] : ["0x1"]
      )),
      getChainId: vi.fn().mockResolvedValue("0x1"),
    };
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x123",
      proofState: {
        chainId: "0x1",
        sealAddress: "0x456",
        runNullifierHigh: "7",
        runNullifierLow: "8",
        proofVersion: "4",
      },
      expectedSealAddress: "0x456",
      reader,
      now,
    })).resolves.toMatchObject({
      status: "confirmed",
      proofStateStatus: "mismatch",
      proofStateValue: 2,
    });
  });

  it("accepts a finalized payroll seal after its proof stage", async () => {
    const reader = {
      getTransactionReceipt: vi.fn().mockResolvedValue({
        finality_status: "ACCEPTED_ON_L2",
        execution_status: "SUCCEEDED",
        events: [proofEvent()],
      }),
      callContract: vi.fn().mockImplementation(async (call: { entrypoint: string }) => (
        call.entrypoint === "get_run_status" ? ["0x3"] : ["0x1"]
      )),
      getChainId: vi.fn().mockResolvedValue("0x1"),
    };
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x123",
      proofState: {
        chainId: "0x1",
        sealAddress: "0x456",
        runNullifierHigh: "7",
        runNullifierLow: "8",
        proofVersion: "2",
      },
      expectedSealAddress: "0x456",
      reader,
      now,
    })).resolves.toMatchObject({ status: "confirmed", proofStateStatus: "verified", proofStateValue: 3 });
  });

  it("rejects proof state from an unconfigured seal or a different chain", async () => {
    const reader = {
      getTransactionReceipt: vi.fn().mockResolvedValue({
        finality_status: "ACCEPTED_ON_L2",
        execution_status: "SUCCEEDED",
        events: [proofEvent("0x999")],
      }),
      callContract: vi.fn().mockResolvedValue(["0x5"]),
      getChainId: vi.fn().mockResolvedValue("0x1"),
    };
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x123",
      proofState: {
        chainId: "0x1",
        sealAddress: "0x999",
        runNullifierHigh: "7",
        runNullifierLow: "8",
        proofVersion: "4",
      },
      expectedSealAddress: "0x456",
      reader,
      now,
    })).resolves.toMatchObject({ status: "confirmed", proofStateStatus: "mismatch" });
    expect(reader.callContract).not.toHaveBeenCalled();

    reader.getChainId.mockResolvedValue("0x2");
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x123",
      proofState: {
        chainId: "0x1",
        sealAddress: "0x456",
        runNullifierHigh: "7",
        runNullifierLow: "8",
        proofVersion: "4",
      },
      expectedSealAddress: "0x456",
      reader,
      now,
    })).resolves.toMatchObject({ status: "confirmed", proofStateStatus: "mismatch" });
    expect(reader.callContract).not.toHaveBeenCalled();
  });

  it("requires the confirmation receipt to identify the bound seal and nullifier", async () => {
    const reader = {
      getTransactionReceipt: vi.fn().mockResolvedValue({
        finality_status: "ACCEPTED_ON_L2",
        execution_status: "SUCCEEDED",
        events: [{ ...proofEvent(), keys: [hash.getSelectorFromName("SealedShardVerified"), "0xaa", "0x8", "0x1"] }],
      }),
      callContract: vi.fn().mockResolvedValue(["0x5"]),
      getChainId: vi.fn().mockResolvedValue("0x1"),
    };
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x123",
      proofState: {
        chainId: "0x1",
        sealAddress: "0x456",
        runNullifierHigh: "7",
        runNullifierLow: "8",
        proofVersion: "4",
      },
      expectedSealAddress: "0x456",
      reader,
      now,
    })).resolves.toMatchObject({ status: "confirmed", proofStateStatus: "mismatch" });
    expect(reader.callContract).not.toHaveBeenCalled();
  });

  it("accepts a direct bundle proof whose seal has no per-shard cursor", async () => {
    const reader = {
      getTransactionReceipt: vi.fn().mockResolvedValue({
        finality_status: "ACCEPTED_ON_L2",
        execution_status: "SUCCEEDED",
        events: [{
          from_address: "0x456",
          keys: [hash.getSelectorFromName("PayrollStateChanged"), "0x7", "0x8"],
          data: [],
        }],
      }),
      callContract: vi.fn().mockImplementation(async (call: { entrypoint: string }) => (
        call.entrypoint === "get_run_status" ? ["0x4"] : ["0x0"]
      )),
      getChainId: vi.fn().mockResolvedValue("0x1"),
    };
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x123",
      proofState: {
        chainId: "0x1",
        sealAddress: "0x456",
        runNullifierHigh: "7",
        runNullifierLow: "8",
        proofVersion: "3",
      },
      expectedSealAddress: "0x456",
      reader,
      now,
    })).resolves.toMatchObject({
      status: "confirmed",
      proofStateStatus: "verified",
      proofStateValue: 4,
      shardsVerified: [false, false],
    });
  });

  it("distinguishes failed, pending and unavailable receipts", async () => {
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x1",
      reader: { getTransactionReceipt: vi.fn().mockResolvedValue({ value: { finalityStatus: "ACCEPTED_ON_L2", executionStatus: "REVERTED" } }) },
      now,
    })).resolves.toMatchObject({ status: "failed" });
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x2",
      reader: { getTransactionReceipt: vi.fn().mockResolvedValue({ finality_status: "RECEIVED" }) },
      now,
    })).resolves.toMatchObject({ status: "pending" });
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x3",
      reader: { getTransactionReceipt: vi.fn().mockRejectedValue(new Error("RPC offline")) },
      now,
    })).resolves.toMatchObject({ status: "unavailable" });
    await expect(verifyLiveProofTransaction({
      transactionHash: "0x4",
      reader: { getTransactionReceipt: vi.fn(() => new Promise(() => undefined)) },
      timeoutMs: 1,
      now,
    })).resolves.toMatchObject({ status: "unavailable" });
  });
});
