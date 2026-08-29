import { describe, expect, it, vi } from "vitest";
import { hash } from "starknet";
import {
  readRegisteredEmployerStatement,
  reconcileEmployerStatement,
  type EmployerStatementReconciliationRpc,
} from "./employer-statement-reconciler";

const sealAddress = "0x456";
const snapshot = {
  runNullifier: "0x" + "11".repeat(32),
  snapshotFact: "0x" + "22".repeat(32),
};
const statement = {
  id: "01a00000-0000-7000-8000-000000000011",
  ownerAddress: "0x123",
  statementFact: "0x" + "33".repeat(32),
  manifestRoot: "0x" + "44".repeat(32),
  fxRoot: "0x" + "55".repeat(32),
  availabilityCommitment: "0x" + "66".repeat(32),
  observedAt: "2026-08-28T01:00:00.000Z",
  registrationTransactionHash: "0xabc",
};

function limbs(value: string) {
  const parsed = BigInt(value);
  return [
    (parsed >> 128n).toString(),
    (parsed & ((1n << 128n) - 1n)).toString(),
  ];
}

function seconds(value: string) {
  return String(Math.floor(new Date(value).getTime() / 1_000));
}

function statementFelts(overrides: Partial<{
  exists: string;
  ownerAddress: string;
  runNullifier: string;
  snapshotFact: string;
  manifestRoot: string;
  fxRoot: string;
  availabilityCommitment: string;
  observedAt: string;
  source: string;
}> = {}) {
  return [
    overrides.exists ?? "1",
    overrides.ownerAddress ?? statement.ownerAddress,
    ...limbs(overrides.runNullifier ?? snapshot.runNullifier),
    ...limbs(overrides.snapshotFact ?? snapshot.snapshotFact),
    ...limbs(overrides.manifestRoot ?? statement.manifestRoot),
    ...limbs(overrides.fxRoot ?? statement.fxRoot),
    ...limbs(
      overrides.availabilityCommitment ?? statement.availabilityCommitment,
    ),
    overrides.observedAt ?? seconds(statement.observedAt),
    overrides.source ?? "2",
  ];
}

function receipt(overrides: Partial<{
  sealAddress: string;
  runNullifier: string;
  statementFact: string;
  observedAt: string;
  executionStatus: string;
  finalityStatus: string;
}> = {}) {
  return {
    execution_status: overrides.executionStatus ?? "SUCCEEDED",
    finality_status: overrides.finalityStatus ?? "ACCEPTED_ON_L2",
    events: [{
      from_address: overrides.sealAddress ?? sealAddress,
      keys: [
        hash.getSelectorFromName("EmployerStatementRegistered"),
        ...limbs(overrides.runNullifier ?? snapshot.runNullifier),
      ],
      data: [
        ...limbs(overrides.statementFact ?? statement.statementFact),
        overrides.observedAt ?? seconds(statement.observedAt),
      ],
    }],
  };
}

function rpc(input: {
  felts?: string[];
  transactionReceipt?: unknown;
} = {}): EmployerStatementReconciliationRpc {
  return {
    getBlockNumber: vi.fn().mockResolvedValue(4321),
    callContract: vi.fn().mockResolvedValue(input.felts ?? statementFelts()),
    getTransactionReceipt: vi.fn().mockResolvedValue(
      input.transactionReceipt ?? receipt(),
    ),
  };
}

describe("employer statement reconciliation", () => {
  it("reads every statement field at one pinned block", async () => {
    const reader = rpc();
    await expect(readRegisteredEmployerStatement(reader, {
      sealAddress,
      statementFact: statement.statementFact,
    })).resolves.toMatchObject({
      exists: true,
      ownerAddress: statement.ownerAddress,
      runNullifierHigh: limbs(snapshot.runNullifier)[0],
      manifestRootLow: limbs(statement.manifestRoot)[1],
      observedAt: seconds(statement.observedAt),
      source: "2",
      blockNumber: 4321,
    });
    expect(reader.callContract).toHaveBeenCalledWith({
      contractAddress: sealAddress,
      entrypoint: "get_statement",
      calldata: limbs(statement.statementFact),
    }, 4321);
  });

  it("marks registered only after exact state and finalized event evidence", async () => {
    const reader = rpc();
    const reconciledAt = new Date("2026-08-28T01:02:00.000Z");
    const markRegistered = vi.fn().mockResolvedValue({
      id: statement.id,
      state: "registered",
    });
    await expect(reconcileEmployerStatement({
      statement,
      snapshot,
      sealAddress,
      rpc: reader,
      reconciledAt,
      dependencies: { markRegistered },
    })).resolves.toEqual({
      statement: { id: statement.id, state: "registered" },
      blockNumber: 4321,
    });
    expect(reader.getTransactionReceipt).toHaveBeenCalledWith("0xabc");
    expect(markRegistered).toHaveBeenCalledWith({
      statementId: statement.id,
      transactionHash: "0xabc",
      registeredAt: reconciledAt,
    });
  });

  it("fails closed on absent, altered or wrong-source on-chain state", async () => {
    const markRegistered = vi.fn();
    await expect(reconcileEmployerStatement({
      statement,
      snapshot,
      sealAddress,
      rpc: rpc({ felts: statementFelts({ exists: "0" }) }),
      dependencies: { markRegistered },
    })).rejects.toMatchObject({ code: "STATEMENT_NOT_REGISTERED" });
    await expect(reconcileEmployerStatement({
      statement,
      snapshot,
      sealAddress,
      rpc: rpc({
        felts: statementFelts({ manifestRoot: "0x" + "99".repeat(32) }),
      }),
      dependencies: { markRegistered },
    })).rejects.toMatchObject({ code: "STATEMENT_BINDING_MISMATCH" });
    await expect(reconcileEmployerStatement({
      statement,
      snapshot,
      sealAddress,
      rpc: rpc({ felts: statementFelts({ source: "3" }) }),
      dependencies: { markRegistered },
    })).rejects.toMatchObject({ code: "STATEMENT_BINDING_MISMATCH" });
    expect(markRegistered).not.toHaveBeenCalled();
  });

  it("rejects missing or mismatched finalized transaction evidence", async () => {
    await expect(reconcileEmployerStatement({
      statement: { ...statement, registrationTransactionHash: null },
      snapshot,
      sealAddress,
      rpc: rpc(),
      dependencies: { markRegistered: vi.fn() },
    })).rejects.toMatchObject({ code: "STATEMENT_TRANSACTION_MISSING" });
    await expect(reconcileEmployerStatement({
      statement,
      snapshot,
      sealAddress,
      rpc: rpc({
        transactionReceipt: receipt({
          statementFact: "0x" + "aa".repeat(32),
        }),
      }),
      dependencies: { markRegistered: vi.fn() },
    })).rejects.toMatchObject({ code: "STATEMENT_RECEIPT_MISMATCH" });
  });
});
