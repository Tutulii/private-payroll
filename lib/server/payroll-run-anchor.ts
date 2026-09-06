import "server-only";

import { num, type Call } from "starknet";

export type PayrollRunAnchorRpc = {
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

export type PayrollRunAnchor = {
  exists: boolean;
  invoked: boolean;
  agreementRootHigh: string;
  agreementRootLow: string;
  manifestRootHigh: string;
  manifestRootLow: string;
  policyRootHigh: string;
  policyRootLow: string;
  fxRootHigh: string;
  fxRootLow: string;
  snapshotFactHigh: string;
  snapshotFactLow: string;
  authorizedAt: string;
  invokedAt: string;
  blockNumber: number;
};

function resultFelts(response: unknown): string[] {
  const values = Array.isArray(response)
    ? response
    : response && typeof response === "object"
      ? (response as { result?: unknown }).result
      : undefined;
  if (!Array.isArray(values)) {
    throw new Error("PAYO run anchor returned no felt result.");
  }
  return values.map((value, index) => {
    try {
      const parsed = BigInt(String(value));
      if (parsed < 0n) throw new Error();
      return parsed.toString();
    } catch {
      throw new Error(`PAYO run anchor felt ${index} is invalid.`);
    }
  });
}

function booleanFelt(value: string, label: string): boolean {
  const parsed = BigInt(value);
  if (parsed !== 0n && parsed !== 1n) {
    throw new Error(`${label} is not a Cairo boolean.`);
  }
  return parsed === 1n;
}

function boundedUnsigned(value: string, bits: number, label: string): string {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= 1n << BigInt(bits)) {
    throw new Error(`${label} is outside u${bits}.`);
  }
  return parsed.toString();
}

export async function readPayrollRunAnchor(
  rpc: PayrollRunAnchorRpc,
  input: {
    sealAddress: string;
    runNullifierHigh: string;
    runNullifierLow: string;
    blockNumber: number;
  },
): Promise<PayrollRunAnchor> {
  if (!Number.isSafeInteger(input.blockNumber) || input.blockNumber < 0) {
    throw new Error("PAYO run-anchor block number is invalid.");
  }
  const felts = resultFelts(await rpc.callContract({
    contractAddress: input.sealAddress,
    entrypoint: "get_run_anchor",
    calldata: [
      num.toHex(BigInt(input.runNullifierHigh)),
      num.toHex(BigInt(input.runNullifierLow)),
    ],
  }, input.blockNumber));
  if (felts.length !== 14) {
    throw new Error(`PAYO run anchor returned ${felts.length} felts; expected 14.`);
  }
  return {
    exists: booleanFelt(felts[0], "Run-anchor existence"),
    invoked: booleanFelt(felts[1], "Run-anchor invocation"),
    agreementRootHigh: boundedUnsigned(felts[2], 128, "Run-anchor agreement-root high limb"),
    agreementRootLow: boundedUnsigned(felts[3], 128, "Run-anchor agreement-root low limb"),
    manifestRootHigh: boundedUnsigned(felts[4], 128, "Run-anchor manifest-root high limb"),
    manifestRootLow: boundedUnsigned(felts[5], 128, "Run-anchor manifest-root low limb"),
    policyRootHigh: boundedUnsigned(felts[6], 128, "Run-anchor policy-root high limb"),
    policyRootLow: boundedUnsigned(felts[7], 128, "Run-anchor policy-root low limb"),
    fxRootHigh: boundedUnsigned(felts[8], 128, "Run-anchor FX-root high limb"),
    fxRootLow: boundedUnsigned(felts[9], 128, "Run-anchor FX-root low limb"),
    snapshotFactHigh: boundedUnsigned(felts[10], 128, "Run-anchor snapshot-fact high limb"),
    snapshotFactLow: boundedUnsigned(felts[11], 128, "Run-anchor snapshot-fact low limb"),
    authorizedAt: boundedUnsigned(felts[12], 64, "Run-anchor authorization time"),
    invokedAt: boundedUnsigned(felts[13], 64, "Run-anchor invocation time"),
    blockNumber: input.blockNumber,
  };
}

export function assertInvokedPayrollFxAnchor(
  anchor: PayrollRunAnchor,
  catalogRoot: string,
): void {
  if (!anchor.exists || !anchor.invoked) {
    throw new Error("The protected payroll run anchor is not finalized on-chain.");
  }
  let expected: bigint;
  try {
    expected = BigInt(catalogRoot);
  } catch {
    throw new Error("The historical payroll FX root is invalid.");
  }
  if (expected < 0n || expected >= 1n << 256n) {
    throw new Error("The historical payroll FX root is outside bytes32.");
  }
  const observed = (BigInt(anchor.fxRootHigh) << 128n) | BigInt(anchor.fxRootLow);
  if (observed !== expected) {
    throw new Error("The protected payroll run anchor is bound to a different FX root.");
  }
}

type PayrollBookRunAnchor = {
  exists: boolean;
  status: number;
  payrollState: readonly string[];
  transitionState: readonly string[];
  verifiedMask: number;
};

function exactBytes32(value: string, label: string): bigint {
  try {
    const parsed = BigInt(value);
    if (parsed < 0n || parsed >= 1n << 256n) throw new Error();
    return parsed;
  } catch {
    throw new Error(`${label} is outside bytes32.`);
  }
}

function joinedStateCommitment(
  fields: readonly string[],
  highIndex: number,
  label: string,
): bigint {
  try {
    const high = BigInt(fields[highIndex]);
    const low = BigInt(fields[highIndex + 1]);
    if (high < 0n || high >= 1n << 128n || low < 0n || low >= 1n << 128n) {
      throw new Error();
    }
    return (high << 128n) | low;
  } catch {
    throw new Error(`${label} has invalid u128 limbs.`);
  }
}

function stateInteger(value: string | undefined, label: string): bigint {
  try {
    const parsed = BigInt(value ?? "");
    if (parsed < 0n) throw new Error();
    return parsed;
  } catch {
    throw new Error(`${label} is not a non-negative integer.`);
  }
}

/**
 * Accepts the current universal payroll-book finalization as the canonical
 * equivalent of the legacy exception-seal run anchor. The contract can reach
 * INVOKED only after all four proof shards are verified and the exact private
 * payment consumes the authorization.
 */
export function assertInvokedPayrollBookFxAnchor(
  anchor: PayrollBookRunAnchor,
  catalogRoot: string,
  runNullifier: string,
): void {
  if (!anchor.exists || anchor.status !== 3) {
    throw new Error("The universal payroll-book authorization is not invoked on-chain.");
  }
  if (anchor.verifiedMask !== 15) {
    throw new Error("The universal payroll-book authorization is missing proof shards.");
  }
  if (anchor.payrollState.length !== 14 || anchor.transitionState.length !== 55) {
    throw new Error("The universal payroll-book authorization returned malformed state.");
  }
  if (
    stateInteger(anchor.payrollState[0], "Payroll-book payroll proof version") !== 2n
    || stateInteger(anchor.payrollState[1], "Payroll-book payroll schema version") !== 1n
    || stateInteger(anchor.transitionState[0], "Payroll-book transition proof version") !== 3n
    || stateInteger(anchor.transitionState[1], "Payroll-book transition schema version") !== 1n
  ) {
    throw new Error("The universal payroll-book authorization has an unsupported proof version.");
  }
  const entryKind = stateInteger(anchor.transitionState[2], "Payroll-book entry kind");
  if (entryKind > 2n) {
    throw new Error("The universal payroll-book entry is not a payroll finalization.");
  }
  const expectedFx = exactBytes32(catalogRoot, "The historical payroll FX root");
  const expectedRun = exactBytes32(runNullifier, "The historical payroll run nullifier");
  if (
    joinedStateCommitment(anchor.payrollState, 8, "Payroll-book payroll FX root") !== expectedFx
    || joinedStateCommitment(anchor.transitionState, 9, "Payroll-book transition FX root") !== expectedFx
  ) {
    throw new Error("The universal payroll-book authorization is bound to a different FX root.");
  }
  if (
    joinedStateCommitment(anchor.payrollState, 10, "Payroll-book payroll run nullifier") !== expectedRun
    || joinedStateCommitment(anchor.transitionState, 11, "Payroll-book transition run nullifier") !== expectedRun
  ) {
    throw new Error("The universal payroll-book authorization is bound to a different payroll run.");
  }
}
