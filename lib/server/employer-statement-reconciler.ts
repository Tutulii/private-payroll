import "server-only";

import { hash, type Call } from "starknet";
import { ApiError } from "@/lib/server/auth";
import { markEmployerStatementRegistered } from "@/lib/persistence/employer-statement-repository";

type EmployerStatementBinding = {
  id: string;
  ownerAddress: string;
  statementFact: string;
  manifestRoot: string;
  fxRoot: string;
  availabilityCommitment: string;
  observedAt: string;
  registrationTransactionHash: string | null;
};

type SnapshotBinding = {
  runNullifier: string;
  snapshotFact: string;
};

export type EmployerStatementReconciliationRpc = {
  getBlockNumber: () => Promise<number>;
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
  getTransactionReceipt: (transactionHash: string) => Promise<unknown>;
};

type RegisteredEmployerStatement = {
  exists: boolean;
  ownerAddress: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  snapshotFactHigh: string;
  snapshotFactLow: string;
  manifestRootHigh: string;
  manifestRootLow: string;
  fxRootHigh: string;
  fxRootLow: string;
  availabilityHigh: string;
  availabilityLow: string;
  observedAt: string;
  source: string;
  blockNumber: number;
};

function resultFelts(response: unknown): string[] {
  const values = Array.isArray(response)
    ? response
    : response && typeof response === "object"
      ? (response as { result?: unknown }).result
      : undefined;
  if (!Array.isArray(values)) {
    throw new Error("PAYO employer-statement read returned no felts.");
  }
  return values.map((value, index) => {
    try {
      const parsed = BigInt(String(value));
      if (parsed < 0n) throw new Error();
      return parsed.toString();
    } catch {
      throw new Error("PAYO employer-statement felt " + index + " is invalid.");
    }
  });
}

function limbs(value: string): readonly [string, string] {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("Employer-statement commitment is not 32 bytes.");
  }
  const parsed = BigInt(value);
  return [
    (parsed >> 128n).toString(),
    (parsed & ((1n << 128n) - 1n)).toString(),
  ] as const;
}

function unixSeconds(value: string): string {
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds)) {
    throw new Error("Employer-statement date is invalid.");
  }
  return String(Math.floor(milliseconds / 1_000));
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object"
    ? value as Record<string, unknown>
    : {};
}

function receiptHasRegistrationEvent(input: {
  receipt: unknown;
  sealAddress: string;
  statement: EmployerStatementBinding;
  snapshot: SnapshotBinding;
}): boolean {
  const wrapper = record(input.receipt);
  const receipt = record(wrapper.value ?? wrapper);
  const execution = String(
    receipt.execution_status ?? receipt.executionStatus ?? "",
  ).toUpperCase();
  const finality = String(
    receipt.finality_status ?? receipt.finalityStatus ?? "",
  ).toUpperCase();
  if (
    execution !== "SUCCEEDED"
    || !["ACCEPTED_ON_L1", "ACCEPTED_ON_L2"].includes(finality)
  ) {
    return false;
  }
  const events = receipt.events;
  if (!Array.isArray(events)) return false;
  const selector = BigInt(hash.getSelectorFromName("EmployerStatementRegistered"));
  const [runHigh, runLow] = limbs(input.snapshot.runNullifier);
  const [factHigh, factLow] = limbs(input.statement.statementFact);
  const expectedKeys = [selector, BigInt(runHigh), BigInt(runLow)];
  const expectedData = [
    BigInt(factHigh),
    BigInt(factLow),
    BigInt(unixSeconds(input.statement.observedAt)),
  ];
  return events.some((candidate) => {
    const event = record(candidate);
    const from = event.from_address ?? event.fromAddress;
    const keys = event.keys;
    const data = event.data;
    if (
      typeof from !== "string"
      || BigInt(from) !== BigInt(input.sealAddress)
      || !Array.isArray(keys)
      || !Array.isArray(data)
      || keys.length < expectedKeys.length
      || data.length < expectedData.length
    ) {
      return false;
    }
    try {
      return expectedKeys.every(
        (value, index) => BigInt(String(keys[index])) === value,
      ) && expectedData.every(
        (value, index) => BigInt(String(data[index])) === value,
      );
    } catch {
      return false;
    }
  });
}

export async function readRegisteredEmployerStatement(
  rpc: Pick<EmployerStatementReconciliationRpc, "getBlockNumber" | "callContract">,
  input: { sealAddress: string; statementFact: string },
): Promise<RegisteredEmployerStatement> {
  const blockNumber = await rpc.getBlockNumber();
  const [factHigh, factLow] = limbs(input.statementFact);
  const felts = resultFelts(await rpc.callContract({
    contractAddress: input.sealAddress,
    entrypoint: "get_statement",
    calldata: [factHigh, factLow],
  }, blockNumber));
  if (felts.length !== 14) {
    throw new Error(
      "PAYO employer statement returned " + felts.length + " felts; expected 14.",
    );
  }
  if (felts[0] !== "0" && felts[0] !== "1") {
    throw new Error("PAYO employer-statement existence flag is invalid.");
  }
  return {
    exists: felts[0] === "1",
    ownerAddress: "0x" + BigInt(felts[1]).toString(16),
    runNullifierHigh: felts[2],
    runNullifierLow: felts[3],
    snapshotFactHigh: felts[4],
    snapshotFactLow: felts[5],
    manifestRootHigh: felts[6],
    manifestRootLow: felts[7],
    fxRootHigh: felts[8],
    fxRootLow: felts[9],
    availabilityHigh: felts[10],
    availabilityLow: felts[11],
    observedAt: felts[12],
    source: felts[13],
    blockNumber,
  };
}

function limbPairMatches(
  commitment: string,
  high: string,
  low: string,
): boolean {
  const [expectedHigh, expectedLow] = limbs(commitment);
  return BigInt(expectedHigh) === BigInt(high)
    && BigInt(expectedLow) === BigInt(low);
}

function assertRegisteredEmployerStatement(
  statement: EmployerStatementBinding,
  snapshot: SnapshotBinding,
  state: RegisteredEmployerStatement,
) {
  if (!state.exists) {
    throw new ApiError(
      409,
      "The employer statement is not registered on the configured PAYO seal.",
      "STATEMENT_NOT_REGISTERED",
    );
  }
  const checks: Array<[boolean, string]> = [
    [BigInt(state.ownerAddress) === BigInt(statement.ownerAddress), "owner"],
    [
      limbPairMatches(
        snapshot.runNullifier,
        state.runNullifierHigh,
        state.runNullifierLow,
      ),
      "run nullifier",
    ],
    [
      limbPairMatches(
        snapshot.snapshotFact,
        state.snapshotFactHigh,
        state.snapshotFactLow,
      ),
      "snapshot fact",
    ],
    [
      limbPairMatches(
        statement.manifestRoot,
        state.manifestRootHigh,
        state.manifestRootLow,
      ),
      "manifest root",
    ],
    [
      limbPairMatches(statement.fxRoot, state.fxRootHigh, state.fxRootLow),
      "FX root",
    ],
    [
      limbPairMatches(
        statement.availabilityCommitment,
        state.availabilityHigh,
        state.availabilityLow,
      ),
      "availability commitment",
    ],
    [
      BigInt(state.observedAt) === BigInt(unixSeconds(statement.observedAt)),
      "observation time",
    ],
    [BigInt(state.source) === 2n, "evidence source"],
  ];
  const mismatch = checks.find(([matches]) => !matches);
  if (mismatch) {
    throw new ApiError(
      409,
      "The on-chain employer statement differs from encrypted evidence at "
        + mismatch[1]
        + ".",
      "STATEMENT_BINDING_MISMATCH",
    );
  }
}

export async function reconcileEmployerStatement(input: {
  statement: EmployerStatementBinding;
  snapshot: SnapshotBinding;
  sealAddress: string;
  rpc: EmployerStatementReconciliationRpc;
  reconciledAt?: Date;
  dependencies?: {
    markRegistered: typeof markEmployerStatementRegistered;
  };
}) {
  if (!input.statement.registrationTransactionHash) {
    throw new ApiError(
      409,
      "Record the employer-statement transaction before reconciliation.",
      "STATEMENT_TRANSACTION_MISSING",
    );
  }
  const state = await readRegisteredEmployerStatement(input.rpc, {
    sealAddress: input.sealAddress,
    statementFact: input.statement.statementFact,
  });
  assertRegisteredEmployerStatement(input.statement, input.snapshot, state);

  let receipt: unknown;
  try {
    receipt = await input.rpc.getTransactionReceipt(
      input.statement.registrationTransactionHash,
    );
  } catch {
    throw new ApiError(
      409,
      "Employer-statement registration receipt is not finalized yet.",
      "STATEMENT_RECEIPT_PENDING",
    );
  }
  if (!receiptHasRegistrationEvent({
    receipt,
    sealAddress: input.sealAddress,
    statement: input.statement,
    snapshot: input.snapshot,
  })) {
    throw new ApiError(
      409,
      "The recorded transaction does not contain this exact finalized employer-statement registration.",
      "STATEMENT_RECEIPT_MISMATCH",
    );
  }

  const markRegistered = input.dependencies?.markRegistered
    ?? markEmployerStatementRegistered;
  const stored = await markRegistered({
    statementId: input.statement.id,
    transactionHash: input.statement.registrationTransactionHash,
    registeredAt: input.reconciledAt ?? new Date(),
  });
  return { statement: stored, blockNumber: state.blockNumber };
}
