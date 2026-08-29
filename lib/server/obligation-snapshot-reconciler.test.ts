import { describe, expect, it, vi } from "vitest";
import { hash } from "starknet";
import {
  readRegisteredObligationSnapshot,
  reconcileObligationSnapshotPlan,
  type SnapshotReconciliationRpc,
} from "./obligation-snapshot-reconciler";

const sealAddress = "0x456";
const plan = {
  id: "01a00000-0000-7000-8000-000000000001",
  ownerAddress: "0x123",
  agreementRoot: `0x${"11".repeat(32)}`,
  claimRoot: `0x${"22".repeat(32)}`,
  policyRoot: `0x${"33".repeat(32)}`,
  runNullifier: `0x${"44".repeat(32)}`,
  snapshotFact: `0x${"55".repeat(32)}`,
  dueAt: "2026-08-28T01:00:00.000Z",
  graceEndsAt: "2026-08-28T02:00:00.000Z",
  claimEndsAt: "2026-09-28T01:00:00.000Z",
  registrationTransactionHash: "0xabc",
};

function limbs(value: string) {
  const parsed = BigInt(value);
  return [(parsed >> 128n).toString(), (parsed & ((1n << 128n) - 1n)).toString()];
}

function seconds(value: string) {
  return String(Math.floor(new Date(value).getTime() / 1_000));
}

function snapshotFelts(overrides: Partial<{
  ownerAddress: string;
  agreementRoot: string;
  claimRoot: string;
  policyRoot: string;
  snapshotFact: string;
  registeredAt: string;
  exists: string;
}> = {}) {
  const agreement = limbs(overrides.agreementRoot ?? plan.agreementRoot);
  const claim = limbs(overrides.claimRoot ?? plan.claimRoot);
  const policy = limbs(overrides.policyRoot ?? plan.policyRoot);
  const fact = limbs(overrides.snapshotFact ?? plan.snapshotFact);
  return [
    overrides.exists ?? "1",
    overrides.ownerAddress ?? plan.ownerAddress,
    ...agreement,
    ...claim,
    ...policy,
    ...fact,
    seconds(plan.dueAt),
    seconds(plan.graceEndsAt),
    seconds(plan.claimEndsAt),
    overrides.registeredAt ?? String(BigInt(seconds(plan.dueAt)) - 60n),
    "0",
  ];
}

function receipt(overrides: Partial<{
  sealAddress: string;
  runNullifier: string;
  snapshotFact: string;
  executionStatus: string;
  finalityStatus: string;
}> = {}) {
  const run = limbs(overrides.runNullifier ?? plan.runNullifier);
  const fact = limbs(overrides.snapshotFact ?? plan.snapshotFact);
  return {
    execution_status: overrides.executionStatus ?? "SUCCEEDED",
    finality_status: overrides.finalityStatus ?? "ACCEPTED_ON_L2",
    events: [{
      from_address: overrides.sealAddress ?? sealAddress,
      keys: [
        hash.getSelectorFromName("ObligationSnapshotRegistered"),
        ...run,
        plan.ownerAddress,
      ],
      data: [
        ...fact,
        seconds(plan.dueAt),
        seconds(plan.graceEndsAt),
        seconds(plan.claimEndsAt),
      ],
    }],
  };
}

function rpc(input: {
  felts?: string[];
  transactionReceipt?: unknown;
} = {}): SnapshotReconciliationRpc {
  return {
    getBlockNumber: vi.fn().mockResolvedValue(1234),
    callContract: vi.fn().mockResolvedValue(input.felts ?? snapshotFelts()),
    getTransactionReceipt: vi.fn().mockResolvedValue(input.transactionReceipt ?? receipt()),
  };
}

describe("obligation snapshot reconciliation", () => {
  it("reads every snapshot field at one pinned block", async () => {
    const reader = rpc();
    await expect(readRegisteredObligationSnapshot(reader, {
      sealAddress,
      runNullifier: plan.runNullifier,
    })).resolves.toMatchObject({
      exists: true,
      ownerAddress: plan.ownerAddress,
      agreementRootHigh: limbs(plan.agreementRoot)[0],
      snapshotFactLow: limbs(plan.snapshotFact)[1],
      blockNumber: 1234,
    });
    expect(reader.callContract).toHaveBeenCalledWith({
      contractAddress: sealAddress,
      entrypoint: "get_snapshot",
      calldata: limbs(plan.runNullifier),
    }, 1234);
  });

  it("marks a plan registered only after exact canonical state and receipt evidence", async () => {
    const reader = rpc();
    const markRegistered = vi.fn().mockResolvedValue({ id: plan.id, state: "registered" });
    await expect(reconcileObligationSnapshotPlan({
      plan,
      sealAddress,
      rpc: reader,
      dependencies: { markRegistered },
    })).resolves.toEqual({
      plan: { id: plan.id, state: "registered" },
      blockNumber: 1234,
    });
    expect(reader.getTransactionReceipt).toHaveBeenCalledWith("0xabc");
    expect(markRegistered).toHaveBeenCalledWith({
      planId: plan.id,
      transactionHash: "0xabc",
      registeredAt: new Date((Number(seconds(plan.dueAt)) - 60) * 1_000),
    });
  });

  it("fails closed when the on-chain snapshot is absent or any immutable root differs", async () => {
    const markRegistered = vi.fn();
    await expect(reconcileObligationSnapshotPlan({
      plan,
      sealAddress,
      rpc: rpc({ felts: snapshotFelts({ exists: "0" }) }),
      dependencies: { markRegistered },
    })).rejects.toMatchObject({ code: "SNAPSHOT_NOT_REGISTERED" });
    await expect(reconcileObligationSnapshotPlan({
      plan,
      sealAddress,
      rpc: rpc({ felts: snapshotFelts({ claimRoot: `0x${"99".repeat(32)}` }) }),
      dependencies: { markRegistered },
    })).rejects.toMatchObject({ code: "SNAPSHOT_BINDING_MISMATCH" });
    expect(markRegistered).not.toHaveBeenCalled();
  });

  it("rejects late registration and a receipt for another snapshot", async () => {
    await expect(reconcileObligationSnapshotPlan({
      plan,
      sealAddress,
      rpc: rpc({ felts: snapshotFelts({ registeredAt: String(BigInt(seconds(plan.dueAt)) + 1n) }) }),
      dependencies: { markRegistered: vi.fn() },
    })).rejects.toMatchObject({ code: "SNAPSHOT_REGISTERED_LATE" });
    await expect(reconcileObligationSnapshotPlan({
      plan,
      sealAddress,
      rpc: rpc({ transactionReceipt: receipt({ snapshotFact: `0x${"aa".repeat(32)}` }) }),
      dependencies: { markRegistered: vi.fn() },
    })).rejects.toMatchObject({ code: "SNAPSHOT_RECEIPT_MISMATCH" });
  });

  it("does not require a user-supplied transaction hash when exact canonical state is already registered", async () => {
    const markRegistered = vi.fn().mockResolvedValue({ id: plan.id, state: "registered" });
    const reader = rpc();
    await reconcileObligationSnapshotPlan({
      plan: { ...plan, registrationTransactionHash: null },
      sealAddress,
      rpc: reader,
      dependencies: { markRegistered },
    });
    expect(reader.getTransactionReceipt).not.toHaveBeenCalled();
    expect(markRegistered).toHaveBeenCalledWith(expect.objectContaining({ transactionHash: null }));
  });
});
