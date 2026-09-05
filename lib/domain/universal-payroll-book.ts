import { keccak_256 } from "@noble/hashes/sha3.js";
import { z } from "zod";
import {
  concatBytes,
  encodeU32,
  encodeUint,
  normalizedHexBytes,
  toHex,
  utf8,
} from "@/lib/crypto/encoding";
import { atomicAmountSchema } from "./payroll";
import { commitmentSchema, starknetAddressSchema } from "./records";

export const UNIVERSAL_PAYROLL_BOOK_ENTRY_VERSION =
  "payo-payroll-book-entry-v2" as const;

export const payrollBookEntryKindSchema = z.enum([
  "ordinary",
  "vesting",
  "agent",
  "claim",
  "remediation",
]);
export type PayrollBookEntryKind = z.infer<typeof payrollBookEntryKindSchema>;

export const PAYROLL_BOOK_ENTRY_KIND_CODE = {
  ordinary: 0,
  vesting: 1,
  agent: 2,
  claim: 3,
  remediation: 4,
} as const satisfies Record<PayrollBookEntryKind, number>;

const unixSecondsSchema = z
  .string()
  .regex(/^(0|[1-9]\d*)$/)
  .refine((value) => BigInt(value) <= 0xffff_ffff_ffff_ffffn, "Timestamp must fit in u64.");

export const payrollBookTokenTotalsSchema = z.object({
  grossAtomic: atomicAmountSchema,
  deductionsAtomic: atomicAmountSchema,
  netAtomic: atomicAmountSchema,
}).strict().superRefine((totals, context) => {
  if (BigInt(totals.grossAtomic) - BigInt(totals.deductionsAtomic) !== BigInt(totals.netAtomic)) {
    context.addIssue({
      code: "custom",
      path: ["netAtomic"],
      message: "Book totals do not balance.",
    });
  }
});
export type PayrollBookTokenTotals = z.infer<typeof payrollBookTokenTotalsSchema>;

const zeroTotals = () => ({ grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" });

export const universalPayrollBookEntrySchema = z.object({
  entryVersion: z.literal(UNIVERSAL_PAYROLL_BOOK_ENTRY_VERSION),
  entryKind: payrollBookEntryKindSchema,
  chainId: starknetAddressSchema,
  sealAddress: starknetAddressSchema,
  sourceSealAddress: starknetAddressSchema,
  ownerAddress: starknetAddressSchema,
  periodStart: unixSecondsSchema,
  periodEnd: unixSecondsSchema,
  agreementRoot: commitmentSchema,
  manifestRoot: commitmentSchema,
  policyRoot: commitmentSchema,
  fxRoot: commitmentSchema,
  runNullifier: commitmentSchema,
  subjectNullifier: commitmentSchema,
  parentFactCommitment: commitmentSchema,
  factCommitment: commitmentSchema,
  sourceProofVersion: z.number().int().positive().max(0xffff_ffff),
  attestationRoot: commitmentSchema,
  contributorCount: z.number().int().positive().max(50),
  totalsDisclosure: z.enum(["hidden", "public"]),
  totalsCommitment: commitmentSchema,
  totals: z.object({
    STRK: payrollBookTokenTotalsSchema,
    USDC: payrollBookTokenTotalsSchema,
  }).strict(),
  vestingScheduleId: commitmentSchema,
  vestingStateCommitment: commitmentSchema,
}).strict().superRefine((entry, context) => {
  const zero = (value: string) => BigInt(value) === 0n;
  if (BigInt(entry.periodEnd) <= BigInt(entry.periodStart)) {
    context.addIssue({ code: "custom", path: ["periodEnd"], message: "Book period end must follow its start." });
  }
  for (const [field, value] of [
    ["chainId", entry.chainId],
    ["sealAddress", entry.sealAddress],
    ["sourceSealAddress", entry.sourceSealAddress],
    ["ownerAddress", entry.ownerAddress],
    ["agreementRoot", entry.agreementRoot],
    ["runNullifier", entry.runNullifier],
    ["subjectNullifier", entry.subjectNullifier],
    ["totalsCommitment", entry.totalsCommitment],
  ] as const) {
    if (zero(value)) context.addIssue({ code: "custom", path: [field], message: `${field} must be non-zero.` });
  }

  const payrollEntry = entry.entryKind === "ordinary"
    || entry.entryKind === "vesting"
    || entry.entryKind === "agent";
  if (entry.entryKind !== "claim" && zero(entry.manifestRoot)) {
    context.addIssue({ code: "custom", path: ["manifestRoot"], message: "A settled entry requires a non-zero manifest or action root." });
  }
  if (zero(entry.policyRoot)) {
    context.addIssue({ code: "custom", path: ["policyRoot"], message: "A book entry requires its approved policy root." });
  }
  if (payrollEntry && entry.sourceProofVersion !== 2) {
    context.addIssue({ code: "custom", path: ["sourceProofVersion"], message: "Payroll book entries require PayrollIntegrity v2." });
  }
  if (entry.entryKind === "claim" && entry.sourceProofVersion !== 6) {
    context.addIssue({ code: "custom", path: ["sourceProofVersion"], message: "Claim book entries require wage-claim v6." });
  }
  if (entry.entryKind === "remediation" && entry.sourceProofVersion !== 7) {
    context.addIssue({ code: "custom", path: ["sourceProofVersion"], message: "Remediation book entries require wage-remediation v7." });
  }

  const hasSchedule = !zero(entry.vestingScheduleId);
  const hasState = !zero(entry.vestingStateCommitment);
  if (entry.entryKind === "vesting") {
    if (!hasSchedule || !hasState) {
      context.addIssue({ code: "custom", path: ["vestingScheduleId"], message: "A vesting entry must bind its schedule and next state." });
    }
  } else if (hasSchedule || hasState) {
    context.addIssue({ code: "custom", path: ["vestingScheduleId"], message: "Only vesting entries may carry vesting state." });
  }

  if (payrollEntry) {
    if (BigInt(entry.subjectNullifier) !== BigInt(entry.runNullifier)) {
      context.addIssue({ code: "custom", path: ["subjectNullifier"], message: "A payroll entry subject must be its run nullifier." });
    }
    if (!zero(entry.parentFactCommitment) || !zero(entry.factCommitment)) {
      context.addIssue({ code: "custom", path: ["factCommitment"], message: "A payroll entry cannot impersonate an exception fact." });
    }
  } else if (zero(entry.parentFactCommitment) || zero(entry.factCommitment)) {
    context.addIssue({ code: "custom", path: ["factCommitment"], message: "An exception entry must bind its parent and proved fact." });
  }

  const amounts = Object.values(entry.totals).flatMap((totals) => [
    totals.grossAtomic,
    totals.deductionsAtomic,
    totals.netAtomic,
  ]);
  if (entry.totalsDisclosure === "hidden" && amounts.some((value) => BigInt(value) !== 0n)) {
    context.addIssue({ code: "custom", path: ["totals"], message: "Hidden public totals must be canonical zeros." });
  }
  if (entry.entryKind === "claim" && amounts.some((value) => BigInt(value) !== 0n)) {
    context.addIssue({ code: "custom", path: ["totals"], message: "A wage claim records no payment value." });
  }
  if (entry.entryKind === "claim" && entry.totalsDisclosure !== "hidden") {
    context.addIssue({ code: "custom", path: ["totalsDisclosure"], message: "A wage claim has no public payment totals." });
  }
  if (entry.entryKind !== "claim" && entry.totalsDisclosure === "public"
    && BigInt(entry.totals.STRK.netAtomic) + BigInt(entry.totals.USDC.netAtomic) === 0n) {
    context.addIssue({ code: "custom", path: ["totals"], message: "A public settlement entry must contain non-zero net value." });
  }
});
export type UniversalPayrollBookEntry = z.infer<typeof universalPayrollBookEntrySchema>;

export function derivePayrollBookTotalsSalt(input: {
  organizationSecret: string;
  runNullifier: string;
}): `0x${string}` {
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_PAYROLL_BOOK_TOTALS_SALT_V1"),
    normalizedHexBytes(commitmentSchema.parse(input.organizationSecret), 32),
    normalizedHexBytes(commitmentSchema.parse(input.runNullifier), 32),
  )));
}
export function utcAnnualPayrollBookPeriod(unixSeconds: string | bigint): {
  periodStart: bigint;
  periodEnd: bigint;
} {
  const seconds = BigInt(unixSeconds);
  if (seconds < 0n || seconds > BigInt(Math.floor(8.64e15 / 1_000))) {
    throw new Error("Payroll-book timestamp is outside the supported Date range.");
  }
  const instant = new Date(Number(seconds) * 1_000);
  if (Number.isNaN(instant.getTime())) throw new Error("Payroll-book timestamp is invalid.");
  const year = instant.getUTCFullYear();
  return {
    periodStart: BigInt(Math.floor(Date.UTC(year, 0, 1) / 1_000)),
    periodEnd: BigInt(Math.floor(Date.UTC(year + 1, 0, 1) / 1_000)),
  };
}

export function deriveExceptionBookTotalsSalt(input: {
  privateSecret: string;
  subjectNullifier: string;
}): `0x${string}` {
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_EXCEPTION_BOOK_TOTALS_SALT_V1"),
    normalizedHexBytes(commitmentSchema.parse(input.privateSecret), 32),
    normalizedHexBytes(commitmentSchema.parse(input.subjectNullifier), 32),
  )));
}

export function payrollBookTotalsCommitment(input: {
  subjectNullifier: string;
  contributorCount: number;
  totals: UniversalPayrollBookEntry["totals"];
  salt: string;
}): `0x${string}` {
  const totals = z.object({
    STRK: payrollBookTokenTotalsSchema,
    USDC: payrollBookTokenTotalsSchema,
  }).strict().parse(input.totals);
  if (!Number.isInteger(input.contributorCount) || input.contributorCount < 1 || input.contributorCount > 50) {
    throw new Error("Payroll-book contributor count must be between 1 and 50.");
  }
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_PAYROLL_BOOK_TOTALS_V1"),
    normalizedHexBytes(commitmentSchema.parse(input.subjectNullifier), 32),
    encodeU32(input.contributorCount),
    encodeUint(BigInt(totals.STRK.grossAtomic), 16),
    encodeUint(BigInt(totals.STRK.deductionsAtomic), 16),
    encodeUint(BigInt(totals.STRK.netAtomic), 16),
    encodeUint(BigInt(totals.USDC.grossAtomic), 16),
    encodeUint(BigInt(totals.USDC.deductionsAtomic), 16),
    encodeUint(BigInt(totals.USDC.netAtomic), 16),
    normalizedHexBytes(commitmentSchema.parse(input.salt), 32),
  )));
}
function fixed32(value: string): Uint8Array {
  return normalizedHexBytes(commitmentSchema.parse(value), 32);
}

function address32(value: string): Uint8Array {
  const parsed = BigInt(starknetAddressSchema.parse(value));
  return encodeUint(parsed, 32);
}

/**
 * The exact fixed-width commitment re-created by the final v3/vNext Noir
 * statement. Any field mutation therefore changes the on-chain book leaf.
 */
export function universalPayrollBookEntryCommitment(
  input: UniversalPayrollBookEntry,
): `0x${string}` {
  const entry = universalPayrollBookEntrySchema.parse(input);
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_PAYROLL_BOOK_ENTRY_V2"),
    address32(entry.chainId),
    address32(entry.sealAddress),
    address32(entry.sourceSealAddress),
    address32(entry.ownerAddress),
    encodeUint(BigInt(entry.periodStart), 8),
    encodeUint(BigInt(entry.periodEnd), 8),
    encodeUint(BigInt(PAYROLL_BOOK_ENTRY_KIND_CODE[entry.entryKind]), 1),
    fixed32(entry.agreementRoot),
    fixed32(entry.manifestRoot),
    fixed32(entry.policyRoot),
    fixed32(entry.fxRoot),
    fixed32(entry.runNullifier),
    fixed32(entry.subjectNullifier),
    fixed32(entry.parentFactCommitment),
    fixed32(entry.factCommitment),
    encodeU32(entry.sourceProofVersion),
    fixed32(entry.attestationRoot),
    encodeU32(entry.contributorCount),
    encodeUint(entry.totalsDisclosure === "public" ? 1n : 0n, 1),
    fixed32(entry.totalsCommitment),
    encodeUint(BigInt(entry.totals.STRK.grossAtomic), 16),
    encodeUint(BigInt(entry.totals.STRK.deductionsAtomic), 16),
    encodeUint(BigInt(entry.totals.STRK.netAtomic), 16),
    encodeUint(BigInt(entry.totals.USDC.grossAtomic), 16),
    encodeUint(BigInt(entry.totals.USDC.deductionsAtomic), 16),
    encodeUint(BigInt(entry.totals.USDC.netAtomic), 16),
    fixed32(entry.vestingScheduleId),
    fixed32(entry.vestingStateCommitment),
  )));
}

export function hiddenPayrollBookTotals(): UniversalPayrollBookEntry["totals"] {
  return { STRK: zeroTotals(), USDC: zeroTotals() };
}
