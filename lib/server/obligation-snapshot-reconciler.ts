import "server-only";

import { hash, type Call } from "starknet";
import { ApiError } from "@/lib/server/auth";
import { markObligationSnapshotRegistered } from "@/lib/persistence/obligation-snapshot-plan-repository";

type SnapshotPlanBinding = {
  id: string;
  ownerAddress: string;
  agreementRoot: string;
  claimRoot: string;
  policyRoot: string;
  runNullifier: string;
  snapshotFact: string;
  dueAt: string;
  graceEndsAt: string;
  claimEndsAt: string;
  registrationTransactionHash: string | null;
};

export type SnapshotReconciliationRpc = {
  getBlockNumber: () => Promise<number>;
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
  getTransactionReceipt: (transactionHash: string) => Promise<unknown>;
};

type RegisteredSnapshot = {
  exists: boolean;
  ownerAddress: string;
  agreementRootHigh: string;
  agreementRootLow: string;
  claimRootHigh: string;
  claimRootLow: string;
  policyRootHigh: string;
  policyRootLow: string;
  snapshotFactHigh: string;
  snapshotFactLow: string;
  dueAt: string;
  graceEndsAt: string;
  claimEndsAt: string;
  registeredAt: string;
  claimCount: string;
  blockNumber: number;
};

function resultFelts(response: unknown): string[] {
  const values = Array.isArray(response)
    ? response
    : response && typeof response === "object"
      ? (response as { result?: unknown }).result
      : undefined;
  if (!Array.isArray(values)) throw new Error("PAYO snapshot read returned no felts.");
  return values.map((value, index) => {
    try {
      const parsed = BigInt(String(value));
      if (parsed < 0n) throw new Error();
      return parsed.toString();
    } catch {
      throw new Error(`PAYO snapshot felt ${index} is invalid.`);
    }
  });
}

function limbs(value: string): readonly [string, string] {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error("Snapshot commitment is not 32 bytes.");
  const parsed = BigInt(value);
  return [(parsed >> 128n).toString(), (parsed & ((1n << 128n) - 1n)).toString()] as const;
}

function unixSeconds(value: string): string {
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds)) throw new Error("Snapshot date is invalid.");
  return String(Math.floor(milliseconds / 1_000));
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? value as Record<string, unknown> : {};
}

function receiptHasRegistrationEvent(input: {
  receipt: unknown;
  sealAddress: string;
  plan: SnapshotPlanBinding;
}): boolean {
  const wrapper = record(input.receipt);
  const receipt = record(wrapper.value ?? wrapper);
  const execution = String(receipt.execution_status ?? receipt.executionStatus ?? "").toUpperCase();
  const finality = String(receipt.finality_status ?? receipt.finalityStatus ?? "").toUpperCase();
  if (execution !== "SUCCEEDED" || !["ACCEPTED_ON_L1", "ACCEPTED_ON_L2"].includes(finality)) return false;
  const events = receipt.events;
  if (!Array.isArray(events)) return false;
  const selector = BigInt(hash.getSelectorFromName("ObligationSnapshotRegistered"));
  const [runHigh, runLow] = limbs(input.plan.runNullifier);
  const [factHigh, factLow] = limbs(input.plan.snapshotFact);
  const expectedKeys = [selector, BigInt(runHigh), BigInt(runLow), BigInt(input.plan.ownerAddress)];
  const expectedData = [
    BigInt(factHigh),
    BigInt(factLow),
    BigInt(unixSeconds(input.plan.dueAt)),
    BigInt(unixSeconds(input.plan.graceEndsAt)),
    BigInt(unixSeconds(input.plan.claimEndsAt)),
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
    ) return false;
    try {
      return expectedKeys.every((value, index) => BigInt(String(keys[index])) === value)
        && expectedData.every((value, index) => BigInt(String(data[index])) === value);
    } catch {
      return false;
    }
  });
}

export async function readRegisteredObligationSnapshot(
  rpc: Pick<SnapshotReconciliationRpc, "getBlockNumber" | "callContract">,
  input: { sealAddress: string; runNullifier: string },
): Promise<RegisteredSnapshot> {
  const blockNumber = await rpc.getBlockNumber();
  const [runHigh, runLow] = limbs(input.runNullifier);
  const felts = resultFelts(await rpc.callContract({
    contractAddress: input.sealAddress,
    entrypoint: "get_snapshot",
    calldata: [runHigh, runLow],
  }, blockNumber));
  if (felts.length !== 15) throw new Error(`PAYO snapshot returned ${felts.length} felts; expected 15.`);
  if (felts[0] !== "0" && felts[0] !== "1") throw new Error("PAYO snapshot existence flag is invalid.");
  return {
    exists: felts[0] === "1",
    ownerAddress: `0x${BigInt(felts[1]).toString(16)}`,
    agreementRootHigh: felts[2],
    agreementRootLow: felts[3],
    claimRootHigh: felts[4],
    claimRootLow: felts[5],
    policyRootHigh: felts[6],
    policyRootLow: felts[7],
    snapshotFactHigh: felts[8],
    snapshotFactLow: felts[9],
    dueAt: felts[10],
    graceEndsAt: felts[11],
    claimEndsAt: felts[12],
    registeredAt: felts[13],
    claimCount: felts[14],
    blockNumber,
  };
}

function assertRegisteredSnapshot(plan: SnapshotPlanBinding, state: RegisteredSnapshot) {
  if (!state.exists) {
    throw new ApiError(409, "The snapshot is not registered on the configured PAYO seal.", "SNAPSHOT_NOT_REGISTERED");
  }
  const fields: Array<[string | bigint, string | bigint, string]> = [
    [state.ownerAddress, plan.ownerAddress, "owner"],
    ...([
      [plan.agreementRoot, state.agreementRootHigh, state.agreementRootLow, "agreement root"],
      [plan.claimRoot, state.claimRootHigh, state.claimRootLow, "claim root"],
      [plan.policyRoot, state.policyRootHigh, state.policyRootLow, "policy root"],
      [plan.snapshotFact, state.snapshotFactHigh, state.snapshotFactLow, "snapshot fact"],
    ] as const).map(([root, high, low, label]) => {
      const [expectedHigh, expectedLow] = limbs(root);
      return BigInt(expectedHigh) === BigInt(high) && BigInt(expectedLow) === BigInt(low)
        ? [0n, 0n, label] as [bigint, bigint, string]
        : [1n, 0n, label] as [bigint, bigint, string];
    }),
    [state.dueAt, unixSeconds(plan.dueAt), "payday"],
    [state.graceEndsAt, unixSeconds(plan.graceEndsAt), "grace deadline"],
    [state.claimEndsAt, unixSeconds(plan.claimEndsAt), "claim deadline"],
  ];
  const mismatch = fields.find(([actual, expected]) => BigInt(actual) !== BigInt(expected));
  if (mismatch) {
    throw new ApiError(
      409,
      `The on-chain snapshot differs from the encrypted plan at ${mismatch[2]}.`,
      "SNAPSHOT_BINDING_MISMATCH",
    );
  }
  if (BigInt(state.registeredAt) > BigInt(state.dueAt)) {
    throw new ApiError(409, "The snapshot was not registered before payday.", "SNAPSHOT_REGISTERED_LATE");
  }
}

export async function reconcileObligationSnapshotPlan(input: {
  plan: SnapshotPlanBinding;
  sealAddress: string;
  rpc: SnapshotReconciliationRpc;
  dependencies?: { markRegistered: typeof markObligationSnapshotRegistered };
}) {
  const state = await readRegisteredObligationSnapshot(input.rpc, {
    sealAddress: input.sealAddress,
    runNullifier: input.plan.runNullifier,
  });
  assertRegisteredSnapshot(input.plan, state);
  if (input.plan.registrationTransactionHash) {
    let receipt: unknown;
    try {
      receipt = await input.rpc.getTransactionReceipt(input.plan.registrationTransactionHash);
    } catch {
      throw new ApiError(409, "Snapshot registration receipt is not finalized yet.", "SNAPSHOT_RECEIPT_PENDING");
    }
    if (!receiptHasRegistrationEvent({
      receipt,
      sealAddress: input.sealAddress,
      plan: input.plan,
    })) {
      throw new ApiError(
        409,
        "The recorded transaction does not contain this exact finalized snapshot registration.",
        "SNAPSHOT_RECEIPT_MISMATCH",
      );
    }
  }
  const registeredAtSeconds = BigInt(state.registeredAt);
  if (registeredAtSeconds > 253_402_300_799n) throw new Error("Snapshot registration time is outside the supported range.");
  const markRegistered = input.dependencies?.markRegistered ?? markObligationSnapshotRegistered;
  const stored = await markRegistered({
    planId: input.plan.id,
    transactionHash: input.plan.registrationTransactionHash,
    registeredAt: new Date(Number(registeredAtSeconds) * 1_000),
  });
  return { plan: stored, blockNumber: state.blockNumber };
}
