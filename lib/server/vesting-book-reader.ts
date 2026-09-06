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
const PAYROLL_BOOK_RECORD_FELTS = 24;
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

function u256FromFelts(low: bigint, high: bigint, label: string): bigint {
  return (
    bounded(high, U128_LIMIT, `${label} high limb`) << 128n
  ) | bounded(low, U128_LIMIT, `${label} low limb`);
}

function decodePayrollBookRecord(book: bigint[]) {
  if (book.length !== PAYROLL_BOOK_RECORD_FELTS) {
    throw new Error(
      `PAYO payroll book returned ${book.length} felts; expected ${PAYROLL_BOOK_RECORD_FELTS}.`,
    );
  }
  const exists = booleanFelt(book[0], "Payroll-book existence");
  const entryCount = Number(bounded(book[1], U32_LIMIT, "Payroll-book entry count"));
  bounded(book[2], U64_LIMIT, "Payroll-book contributor count");
  const disclosedEntryCount = bounded(book[3], U32_LIMIT, "Payroll-book disclosed entry count");
  const undisclosedEntryCount = bounded(book[4], U32_LIMIT, "Payroll-book undisclosed entry count");
  const kindCounts = [
    bounded(book[5], U32_LIMIT, "Payroll-book ordinary entry count"),
    bounded(book[6], U32_LIMIT, "Payroll-book vesting entry count"),
    bounded(book[7], U32_LIMIT, "Payroll-book agent entry count"),
    bounded(book[8], U32_LIMIT, "Payroll-book claim entry count"),
    bounded(book[9], U32_LIMIT, "Payroll-book remediation entry count"),
  ];
  const strkGross = u256FromFelts(book[10], book[11], "Payroll-book STRK gross");
  const strkDeductions = u256FromFelts(book[12], book[13], "Payroll-book STRK deductions");
  const strkNet = u256FromFelts(book[14], book[15], "Payroll-book STRK net");
  const usdcGross = u256FromFelts(book[16], book[17], "Payroll-book USDC gross");
  const usdcDeductions = u256FromFelts(book[18], book[19], "Payroll-book USDC deductions");
  const usdcNet = u256FromFelts(book[20], book[21], "Payroll-book USDC net");
  const accumulatorRoot = bounded(book[22], STARKNET_FIELD_PRIME, "Payroll-book accumulator root");
  const updatedAt = bounded(book[23], U64_LIMIT, "Payroll-book update time");

  if (!exists && book.slice(1).some((value) => value !== 0n)) {
    throw new Error("An absent payroll book returned non-zero state.");
  }
  if (exists && entryCount === 0) {
    throw new Error("An initialized payroll book cannot contain zero entries.");
  }
  if (disclosedEntryCount + undisclosedEntryCount !== BigInt(entryCount)) {
    throw new Error("Payroll-book disclosure counters do not equal its entry count.");
  }
  if (kindCounts.reduce((sum, value) => sum + value, 0n) !== BigInt(entryCount)) {
    throw new Error("Payroll-book kind counters do not equal its entry count.");
  }
  if (strkGross !== strkDeductions + strkNet) {
    throw new Error("Payroll-book STRK totals do not balance.");
  }
  if (usdcGross !== usdcDeductions + usdcNet) {
    throw new Error("Payroll-book USDC totals do not balance.");
  }

  return { exists, entryCount, accumulatorRoot, updatedAt };
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
  const { exists, entryCount, accumulatorRoot } = decodePayrollBookRecord(book);
  if (entryCount > PAYO_MAX_REPORT_BOOK_ENTRIES) {
    throw new Error(
      `Payroll book has ${entryCount} entries; the safe export limit is ${PAYO_MAX_REPORT_BOOK_ENTRIES}.`,
    );
  }
  const checkpointBase = {
    checkpointVersion: "payo-payroll-book-checkpoint-v1" as const,
    chainId,
    sealAddress,
    ownerAddress,
    periodStart: periodStart.toString(),
    periodEnd: periodEnd.toString(),
    entryCount,
    accumulatorRoot: commitment(accumulatorRoot),
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
