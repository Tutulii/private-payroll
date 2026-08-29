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
