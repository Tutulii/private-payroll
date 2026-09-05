import { keccak_256 } from "@noble/hashes/sha3.js";
import { hash, shortString } from "starknet";
import { z } from "zod";
import {
  concatBytes,
  encodeU32,
  encodeUint,
  normalizedHexBytes,
  toHex,
  utf8,
} from "@/lib/crypto/encoding";
import { atomicAmountSchema, payrollTokenSchema } from "./payroll";
import { commitmentSchema, starknetAddressSchema } from "./records";

const u32Schema = z.number().int().nonnegative().max(0xffff_ffff);
const unixSecondsSchema = z
  .string()
  .regex(/^(0|[1-9]\d*)$/)
  .refine((value) => BigInt(value) <= 0xffff_ffff_ffff_ffffn, "Timestamp must fit in u64.");

export const vestingScheduleTermsSchema = z.object({
  scheduleVersion: z.literal("payo-private-vesting-v1"),
  agreementIdCommitment: commitmentSchema,
  recipientCommitment: commitmentSchema,
  tokenAddress: starknetAddressSchema,
  startsAt: unixSecondsSchema,
  cliffAt: unixSecondsSchema,
  endsAt: unixSecondsSchema,
  totalAtomic: atomicAmountSchema,
  planSalt: commitmentSchema,
}).strict().superRefine((terms, context) => {
  const start = BigInt(terms.startsAt);
  const cliff = BigInt(terms.cliffAt);
  const end = BigInt(terms.endsAt);
  if (cliff < start) {
    context.addIssue({ code: "custom", path: ["cliffAt"], message: "Vesting cliff precedes its start." });
  }
  if (end <= start || cliff > end) {
    context.addIssue({ code: "custom", path: ["endsAt"], message: "Vesting end does not follow its valid window." });
  }
  if (BigInt(terms.totalAtomic) === 0n) {
    context.addIssue({ code: "custom", path: ["totalAtomic"], message: "Vesting total must be positive." });
  }
});
export type VestingScheduleTerms = z.infer<typeof vestingScheduleTermsSchema>;

export const vestingStateSchema = z.object({
  stateVersion: z.literal("payo-vesting-state-v1"),
  scheduleId: commitmentSchema,
  releasedAtomic: atomicAmountSchema,
  releaseSequence: u32Schema,
  stateSalt: commitmentSchema,
}).strict();
export type VestingState = z.infer<typeof vestingStateSchema>;

export const vestingTransitionSchema = z.object({
  transitionVersion: z.literal("payo-vesting-transition-v1"),
  schedule: vestingScheduleTermsSchema,
  previous: vestingStateSchema,
  releaseAt: unixSecondsSchema,
  payableAtomic: atomicAmountSchema,
  next: vestingStateSchema,
  runNullifier: commitmentSchema,
}).strict();
export type VestingTransition = z.infer<typeof vestingTransitionSchema>;

export const payrollBookEntrySchema = z.object({
  entryVersion: z.literal("payo-payroll-book-entry-v1"),
  chainId: starknetAddressSchema,
  sealAddress: starknetAddressSchema,
  ownerAddress: starknetAddressSchema,
  periodStart: unixSecondsSchema,
  periodEnd: unixSecondsSchema,
  agreementRoot: commitmentSchema,
  manifestRoot: commitmentSchema,
  runNullifier: commitmentSchema,
  payrollProofVersion: u32Schema.refine((value) => value > 0, "Proof version must be positive."),
  vestingScheduleId: commitmentSchema,
  vestingStateCommitment: commitmentSchema,
}).strict().superRefine((entry, context) => {
  if (BigInt(entry.periodEnd) <= BigInt(entry.periodStart)) {
    context.addIssue({ code: "custom", path: ["periodEnd"], message: "Book period end must follow its start." });
  }
  const hasSchedule = BigInt(entry.vestingScheduleId) !== 0n;
  const hasState = BigInt(entry.vestingStateCommitment) !== 0n;
  if (hasSchedule !== hasState) {
    context.addIssue({
      code: "custom",
      path: ["vestingStateCommitment"],
      message: "A payroll-book entry must bind both vesting identifiers or neither.",
    });
  }
});
export type PayrollBookEntry = z.infer<typeof payrollBookEntrySchema>;

export const payrollBookCheckpointSchema = z.object({
  checkpointVersion: z.literal("payo-payroll-book-checkpoint-v1"),
  chainId: starknetAddressSchema,
  sealAddress: starknetAddressSchema,
  ownerAddress: starknetAddressSchema,
  periodStart: unixSecondsSchema,
  periodEnd: unixSecondsSchema,
  entryCount: u32Schema,
  accumulatorRoot: commitmentSchema,
}).strict();
export type PayrollBookCheckpoint = z.infer<typeof payrollBookCheckpointSchema>;

export const payrollBookDisclosureLineSchema = z.object({
  recipientReference: z.string().min(1).max(240),
  jurisdictionCode: z.string().regex(/^[A-Z]{2}(-[A-Z0-9]{1,3})?$/),
  token: payrollTokenSchema,
  grossAtomic: atomicAmountSchema,
  deductionsAtomic: atomicAmountSchema,
  netAtomic: atomicAmountSchema,
}).strict().superRefine((line, context) => {
  if (BigInt(line.grossAtomic) - BigInt(line.deductionsAtomic) !== BigInt(line.netAtomic)) {
    context.addIssue({ code: "custom", path: ["netAtomic"], message: "Tax line arithmetic does not balance." });
  }
});

export const payrollBookDisclosureEntrySchema = z.object({
  index: u32Schema,
  entry: payrollBookEntrySchema,
  entryCommitment: commitmentSchema,
  lines: z.array(payrollBookDisclosureLineSchema).min(1).max(50),
  integrityVerificationTransactionHash: starknetAddressSchema,
  settlementTransactionHash: starknetAddressSchema,
}).strict();
export type PayrollBookDisclosureEntry = z.infer<typeof payrollBookDisclosureEntrySchema>;

export const completePayrollBookSchema = z.object({
  packageVersion: z.literal("payo-complete-payroll-book-v1"),
  scope: z.enum(["employer", "tax_authority"]),
  checkpoint: payrollBookCheckpointSchema,
  entries: z.array(payrollBookDisclosureEntrySchema),
  generatedAt: z.string().datetime(),
}).strict();
export type CompletePayrollBook = z.infer<typeof completePayrollBookSchema>;

const ZERO_COMMITMENT = `0x${"00".repeat(32)}` as const;
const STARK_FIELD_PRIME = (1n << 251n) + 17n * (1n << 192n) + 1n;

function hashFixed(domain: string, ...fields: Uint8Array[]): `0x${string}` {
  return toHex(keccak_256(concatBytes(utf8(domain), ...fields)));
}

function addressBytes(value: string): Uint8Array {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= STARK_FIELD_PRIME) throw new Error("Address is outside the Starknet field.");
  return encodeUint(parsed, 32);
}

function commitmentBytes(value: string): Uint8Array {
  return normalizedHexBytes(commitmentSchema.parse(value), 32);
}

function commitmentLimbs(value: string): [bigint, bigint] {
  const bytes = commitmentBytes(value);
  return [
    BigInt(toHex(bytes.slice(0, 16))),
    BigInt(toHex(bytes.slice(16))),
  ];
}

function poseidon(values: readonly bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements([...values]));
}

function feltCommitment(value: bigint): `0x${string}` {
  return toHex(encodeUint(value, 32));
}

export function vestingScheduleId(input: VestingScheduleTerms): `0x${string}` {
  const terms = vestingScheduleTermsSchema.parse(input);
  return hashFixed(
    "PAYO_VESTING_SCHEDULE_V1",
    commitmentBytes(terms.agreementIdCommitment),
    commitmentBytes(terms.recipientCommitment),
    addressBytes(terms.tokenAddress),
    encodeUint(BigInt(terms.startsAt), 8),
    encodeUint(BigInt(terms.cliffAt), 8),
    encodeUint(BigInt(terms.endsAt), 8),
    encodeUint(BigInt(terms.totalAtomic), 16),
    commitmentBytes(terms.planSalt),
  );
}

export function vestingStateSalt(planSalt: string, releaseSequence: number): `0x${string}` {
  if (!Number.isInteger(releaseSequence) || releaseSequence < 0 || releaseSequence > 0xffff_ffff) {
    throw new Error("Vesting state-salt sequence must fit in u32.");
  }
  return hashFixed(
    "PAYO_VESTING_STATE_SALT_V1",
    commitmentBytes(planSalt),
    encodeU32(releaseSequence),
  );
}

export function vestingStateCommitment(input: VestingState): `0x${string}` {
  const state = vestingStateSchema.parse(input);
  return hashFixed(
    "PAYO_VESTING_STATE_V1",
    commitmentBytes(state.scheduleId),
    encodeUint(BigInt(state.releasedAtomic), 16),
    encodeU32(state.releaseSequence),
    commitmentBytes(state.stateSalt),
  );
}

export function vestedAt(input: VestingScheduleTerms, at: bigint): bigint {
  const schedule = vestingScheduleTermsSchema.parse(input);
  const start = BigInt(schedule.startsAt);
  const cliff = BigInt(schedule.cliffAt);
  const end = BigInt(schedule.endsAt);
  const total = BigInt(schedule.totalAtomic);
  if (at < cliff) return 0n;
  if (at >= end) return total;
  if (at <= start) return 0n;
  const elapsed = at - start;
  const duration = end - start;
  return (total / duration) * elapsed + ((total % duration) * elapsed) / duration;
}

export function vestingReleaseNullifier(input: {
  scheduleId: string;
  nextSequence: number;
  releaseAt: bigint | string;
  newStateCommitment: string;
  runNullifier: string;
}): `0x${string}` {
  if (!Number.isInteger(input.nextSequence) || input.nextSequence < 1 || input.nextSequence > 0xffff_ffff) {
    throw new Error("Vesting release sequence must be a positive u32.");
  }
  return hashFixed(
    "PAYO_VESTING_RELEASE_V1",
    commitmentBytes(input.scheduleId),
    encodeU32(input.nextSequence),
    encodeUint(BigInt(input.releaseAt), 8),
    commitmentBytes(input.newStateCommitment),
    commitmentBytes(input.runNullifier),
  );
}

export function assertVestingTransition(input: VestingTransition): {
  scheduleId: `0x${string}`;
  previousStateCommitment: `0x${string}`;
  nextStateCommitment: `0x${string}`;
  releaseNullifier: `0x${string}`;
} {
  const transition = vestingTransitionSchema.parse(input);
  const scheduleId = vestingScheduleId(transition.schedule);
  if (BigInt(transition.previous.scheduleId) !== BigInt(scheduleId)
    || BigInt(transition.next.scheduleId) !== BigInt(scheduleId)) {
    throw new Error("Vesting state is bound to a different immutable schedule.");
  }
  const releaseAt = BigInt(transition.releaseAt);
  if (releaseAt < BigInt(transition.schedule.cliffAt)) throw new Error("Vesting release precedes its cliff.");
  if (releaseAt > BigInt(transition.schedule.endsAt)) throw new Error("Vesting release exceeds its end.");
  if (transition.next.releaseSequence !== transition.previous.releaseSequence + 1) {
    throw new Error("Vesting release sequence must increment exactly once.");
  }
  const earned = vestedAt(transition.schedule, releaseAt);
  const released = BigInt(transition.previous.releasedAtomic);
  const payable = BigInt(transition.payableAtomic);
  if (earned <= released) throw new Error("Vesting schedule has no unreleased value.");
  if (payable !== earned - released) throw new Error("Vesting payment is not the exact unpaid vested delta.");
  if (BigInt(transition.next.releasedAtomic) !== earned) {
    throw new Error("Next vesting state does not record the cumulative earned amount.");
  }
  const previousStateCommitment = transition.previous.releaseSequence === 0 && released === 0n
    ? ZERO_COMMITMENT
    : vestingStateCommitment(transition.previous);
  const nextStateCommitment = vestingStateCommitment(transition.next);
  return {
    scheduleId,
    previousStateCommitment,
    nextStateCommitment,
    releaseNullifier: vestingReleaseNullifier({
      scheduleId,
      nextSequence: transition.next.releaseSequence,
      releaseAt,
      newStateCommitment: nextStateCommitment,
      runNullifier: transition.runNullifier,
    }),
  };
}

export function payrollBookEntryCommitment(input: PayrollBookEntry): `0x${string}` {
  const entry = payrollBookEntrySchema.parse(input);
  return hashFixed(
    "PAYO_PAYROLL_BOOK_ENTRY_V1",
    addressBytes(entry.chainId),
    addressBytes(entry.sealAddress),
    addressBytes(entry.ownerAddress),
    encodeUint(BigInt(entry.periodStart), 8),
    encodeUint(BigInt(entry.periodEnd), 8),
    commitmentBytes(entry.agreementRoot),
    commitmentBytes(entry.manifestRoot),
    commitmentBytes(entry.runNullifier),
    encodeU32(entry.payrollProofVersion),
    commitmentBytes(entry.vestingScheduleId),
    commitmentBytes(entry.vestingStateCommitment),
  );
}

export function initialPayrollBookRoot(input: {
  chainId: string;
  sealAddress: string;
  ownerAddress: string;
  periodStart: bigint | string;
  periodEnd: bigint | string;
}): `0x${string}` {
  const chainId = BigInt(starknetAddressSchema.parse(input.chainId));
  const sealAddress = BigInt(starknetAddressSchema.parse(input.sealAddress));
  const owner = BigInt(starknetAddressSchema.parse(input.ownerAddress));
  const start = BigInt(input.periodStart);
  const end = BigInt(input.periodEnd);
  if (end <= start) throw new Error("Book period end must follow its start.");
  return feltCommitment(poseidon([
    BigInt(shortString.encodeShortString("PAYO_BOOK_V1")),
    chainId,
    sealAddress,
    owner,
    start,
    end,
  ]));
}

export function appendPayrollBookRoot(input: {
  previousRoot: string;
  entryCommitment: string;
  index: number;
}): `0x${string}` {
  if (!Number.isInteger(input.index) || input.index < 0 || input.index > 0xffff_ffff) {
    throw new Error("Payroll-book index must fit in u32.");
  }
  const previous = BigInt(commitmentSchema.parse(input.previousRoot));
  if (previous >= STARK_FIELD_PRIME) throw new Error("Payroll-book root is outside the Starknet field.");
  const [high, low] = commitmentLimbs(input.entryCommitment);
  return feltCommitment(poseidon([
    BigInt(shortString.encodeShortString("PAYO_BOOK_ADD_V1")),
    previous,
    high,
    low,
    BigInt(input.index),
  ]));
}

export function verifyCompletePayrollBook(input: CompletePayrollBook): {
  verified: true;
  entryCount: number;
  accumulatorRoot: `0x${string}`;
  totals: Record<"STRK" | "USDC", { grossAtomic: string; deductionsAtomic: string; netAtomic: string }>;
} {
  const book = completePayrollBookSchema.parse(input);
  const checkpoint = book.checkpoint;
  if (book.entries.length !== checkpoint.entryCount) {
    throw new Error("Payroll book is incomplete: disclosed entry count differs from the on-chain checkpoint.");
  }
  let root = initialPayrollBookRoot(checkpoint);
  const runNullifiers = new Set<string>();
  const totals = {
    STRK: { grossAtomic: 0n, deductionsAtomic: 0n, netAtomic: 0n },
    USDC: { grossAtomic: 0n, deductionsAtomic: 0n, netAtomic: 0n },
  };
  for (const [index, disclosure] of book.entries.entries()) {
    if (disclosure.index !== index) throw new Error("Payroll book has an omitted, duplicated, or reordered entry index.");
    const entry = disclosure.entry;
    if (BigInt(entry.chainId) !== BigInt(checkpoint.chainId)
      || BigInt(entry.sealAddress) !== BigInt(checkpoint.sealAddress)
      || BigInt(entry.ownerAddress) !== BigInt(checkpoint.ownerAddress)
      || entry.periodStart !== checkpoint.periodStart
      || entry.periodEnd !== checkpoint.periodEnd) {
      throw new Error("Payroll-book entry belongs to a different owner or reporting period.");
    }
    const runKey = entry.runNullifier.toLowerCase();
    if (runNullifiers.has(runKey)) throw new Error("Payroll book duplicates a finalized payroll run.");
    runNullifiers.add(runKey);
    const expectedCommitment = payrollBookEntryCommitment(entry);
    if (BigInt(expectedCommitment) !== BigInt(disclosure.entryCommitment)) {
      throw new Error("Payroll-book entry commitment does not match its disclosed fields.");
    }
    for (const rawLine of disclosure.lines) {
      const line = payrollBookDisclosureLineSchema.parse(rawLine);
      const tokenTotals = totals[line.token];
      tokenTotals.grossAtomic += BigInt(line.grossAtomic);
      tokenTotals.deductionsAtomic += BigInt(line.deductionsAtomic);
      tokenTotals.netAtomic += BigInt(line.netAtomic);
    }
    root = appendPayrollBookRoot({ previousRoot: root, entryCommitment: expectedCommitment, index });
  }
  if (BigInt(root) !== BigInt(checkpoint.accumulatorRoot)) {
    throw new Error("Payroll book does not reconstruct the on-chain period accumulator.");
  }
  return {
    verified: true,
    entryCount: book.entries.length,
    accumulatorRoot: root,
    totals: {
      STRK: Object.fromEntries(Object.entries(totals.STRK).map(([key, value]) => [key, value.toString()])) as never,
      USDC: Object.fromEntries(Object.entries(totals.USDC).map(([key, value]) => [key, value.toString()])) as never,
    },
  };
}

export { ZERO_COMMITMENT as PAYO_ZERO_COMMITMENT };
