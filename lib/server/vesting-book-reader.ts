import "server-only";

import { num, validateAndParseAddress, type Call } from "starknet";
import {
  initialPayrollBookRoot,
  payrollBookCheckpointSchema,
} from "@/lib/domain/vesting-tax";
import {
  trustedPayrollBookSnapshotSchema,
  verifyTrustedPayrollBookSnapshot,
  type TrustedPayrollBookSnapshot,
} from "@/lib/disclosure/payroll-book-report";

const U32_LIMIT = 1n << 32n;
const U64_LIMIT = 1n << 64n;
const U128_LIMIT = 1n << 128n;
const STARKNET_FIELD_PRIME = (1n << 251n) + (17n << 192n) + 1n;
export const PAYO_MAX_REPORT_BOOK_ENTRIES = 5_000;

export type VestingBookRpc = {
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

function resultFelts(response: unknown, label: string): bigint[] {
  const values = Array.isArray(response)
    ? response
    : response && typeof response === "object"
      ? (response as { result?: unknown }).result
      : undefined;
  if (!Array.isArray(values)) throw new Error(`${label} returned no felt result.`);
  return values.map((value, index) => {
    try {
      const parsed = BigInt(String(value));
      if (parsed < 0n || parsed >= STARKNET_FIELD_PRIME) throw new Error();
      return parsed;
    } catch {
      throw new Error(`${label} felt ${index} is outside the Starknet field.`);
    }
  });
}

function bounded(value: bigint, limit: bigint, label: string): bigint {
  if (value < 0n || value >= limit) throw new Error(`${label} is outside its canonical range.`);
  return value;
}

function booleanFelt(value: bigint, label: string): boolean {
  if (value !== 0n && value !== 1n) throw new Error(`${label} is not a Cairo boolean.`);
  return value === 1n;
}

function commitment(value: bigint): `0x${string}` {
  return `0x${value.toString(16).padStart(64, "0")}`;
}

async function mapWithConcurrency<T>(
  count: number,
  concurrency: number,
  task: (index: number) => Promise<T>,
): Promise<T[]> {
  const output = new Array<T>(count);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(count, concurrency) }, async () => {
    while (cursor < count) {
      const index = cursor;
      cursor += 1;
      output[index] = await task(index);
    }
  });
  await Promise.all(workers);
  return output;
}

/**
 * Reads a complete public payroll-book commitment list at one immutable block.
 * The resulting snapshot is safe to use as independent evidence when opening
 * an encrypted employer, worker, or tax-authority report.
 */
export async function readTrustedPayrollBookSnapshot(input: {
  rpc: VestingBookRpc;
  chainId: string;
  sealAddress: string;
  ownerAddress: string;
  periodStart: bigint;
  periodEnd: bigint;
  blockNumber: number;
  observedAt?: Date;
}): Promise<TrustedPayrollBookSnapshot> {
  if (!Number.isSafeInteger(input.blockNumber) || input.blockNumber < 0) {
    throw new Error("Payroll-book block number is invalid.");
  }
  const chainId = num.toHex(BigInt(input.chainId));
  const sealAddress = validateAndParseAddress(input.sealAddress);
  const ownerAddress = validateAndParseAddress(input.ownerAddress);
  const periodStart = bounded(input.periodStart, U64_LIMIT, "Payroll-book period start");
  const periodEnd = bounded(input.periodEnd, U64_LIMIT, "Payroll-book period end");
  if (periodEnd <= periodStart) throw new Error("Payroll-book period end must follow its start.");
  const calldata = [ownerAddress, num.toHex(periodStart), num.toHex(periodEnd)];
  const book = resultFelts(await input.rpc.callContract({
    contractAddress: sealAddress,
    entrypoint: "get_payroll_book",
    calldata,
  }, input.blockNumber), "PAYO payroll book");
  if (book.length !== 4) {
    throw new Error(`PAYO payroll book returned ${book.length} felts; expected 4.`);
  }
  const exists = booleanFelt(book[0], "Payroll-book existence");
  const entryCount = Number(bounded(book[1], U32_LIMIT, "Payroll-book entry count"));
  bounded(book[2], STARKNET_FIELD_PRIME, "Payroll-book accumulator root");
  bounded(book[3], U64_LIMIT, "Payroll-book update time");
  if (entryCount > PAYO_MAX_REPORT_BOOK_ENTRIES) {
    throw new Error(
      `Payroll book has ${entryCount} entries; the safe export limit is ${PAYO_MAX_REPORT_BOOK_ENTRIES}.`,
    );
  }
  if (!exists && (entryCount !== 0 || book[2] !== 0n || book[3] !== 0n)) {
    throw new Error("An absent payroll book returned non-zero state.");
  }
  if (exists && entryCount === 0) {
    throw new Error("An initialized payroll book cannot contain zero entries.");
  }
  const checkpointBase = {
    checkpointVersion: "payo-payroll-book-checkpoint-v1" as const,
    chainId,
    sealAddress,
    ownerAddress,
    periodStart: periodStart.toString(),
    periodEnd: periodEnd.toString(),
    entryCount,
    accumulatorRoot: commitment(book[2]),
  };
  const checkpoint = payrollBookCheckpointSchema.parse(exists
    ? checkpointBase
    : { ...checkpointBase, accumulatorRoot: initialPayrollBookRoot(checkpointBase) });
  const entries = await mapWithConcurrency(entryCount, 12, async (index) => {
    const value = resultFelts(await input.rpc.callContract({
      contractAddress: sealAddress,
      entrypoint: "get_payroll_book_entry",
      calldata: [...calldata, num.toHex(index)],
    }, input.blockNumber), `PAYO payroll-book entry ${index}`);
    if (value.length !== 2) {
      throw new Error(`PAYO payroll-book entry ${index} returned ${value.length} felts; expected 2.`);
    }
    const low = bounded(value[0], U128_LIMIT, `Payroll-book entry ${index} low limb`);
    const high = bounded(value[1], U128_LIMIT, `Payroll-book entry ${index} high limb`);
    return { index, entryCommitment: commitment((high << 128n) | low) };
  });
  return verifyTrustedPayrollBookSnapshot(trustedPayrollBookSnapshotSchema.parse({
    snapshotVersion: "payo-trusted-payroll-book-snapshot-v1",
    checkpoint,
    entries,
    observedAt: (input.observedAt ?? new Date()).toISOString(),
    blockNumber: input.blockNumber.toString(),
  }));
}
