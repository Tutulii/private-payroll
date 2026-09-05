import { splitHashToU128 } from "@/lib/crypto/commitments";
import {
  PAYROLL_BOOK_ENTRY_KIND_CODE,
  hiddenPayrollBookTotals,
  payrollBookTotalsCommitment,
  universalPayrollBookEntryCommitment,
  universalPayrollBookEntrySchema,
  type PayrollBookEntryKind,
  type UniversalPayrollBookEntry,
} from "@/lib/domain/universal-payroll-book";
import type { ExceptionPublicInputsV2 } from "@/lib/domain/exception-protocol";
import { PAYO_PROOF_EMPTY_LEAF } from "./commitments";
import type {
  PayrollAgreementCircuitWitness,
  PayrollIntegrityInputBuild,
  PayrollLineCircuitWitness,
} from "./input-builder";

const ZERO = `0x${"00".repeat(32)}` as const;

export type PayrollBookShardAggregate = {
  contributorCount: number;
  STRK: { grossAtomic: string; deductionsAtomic: string; netAtomic: string };
  USDC: { grossAtomic: string; deductionsAtomic: string; netAtomic: string };
};

export type UniversalPayrollBookWitnessShard = {
  agreementLeaves: string[];
  payrollLeaves: string[];
  agreements: PayrollAgreementCircuitWitness[];
  lines: PayrollLineCircuitWitness[];
  aggregate: PayrollBookShardAggregate;
};

export type UniversalPayrollBookInputBuild = {
  entry: UniversalPayrollBookEntry;
  entryCommitment: `0x${string}`;
  entryCommitmentLimbs: { high: string; low: string };
  entryKindCode: number;
  totalsOpening: { totals: UniversalPayrollBookEntry["totals"]; salt: `0x${string}` };
  shards: readonly [UniversalPayrollBookWitnessShard, UniversalPayrollBookWitnessShard];
};

function emptyAgreement(): PayrollAgreementCircuitWitness {
  return {
    enabled: false,
    id_commitment: Array(32).fill(0),
    recipient_commitment: Array(32).fill(0),
    earnings: Array(8).fill("0"),
    earnings_count: "0",
    token: "0",
    policy_commitment: Array(32).fill(0),
    schedule_commitment: Array(32).fill(0),
    due_at: "0",
    valid_until: "0",
    classification_declared: "0",
    classification_score: "0",
    classification_employee_threshold: "0",
    final_pay_mode: false,
    final_required_mask: "0",
    final_components: Array(5).fill("0"),
    fx_floor_atomic: "0",
    reference_currency: "0",
    salt: Array(32).fill(0),
  };
}

function emptyLine(): PayrollLineCircuitWitness {
  return {
    active: false,
    deductions: Array(8).fill("0"),
    deductions_count: "0",
    policy_slot: "0",
    fx_slot: "0",
    salt: Array(32).fill(0),
    classification_treatment: "0",
    final_included_mask: "0",
    reference_value_atomic: "0",
  };
}

function emptyAggregate(): PayrollBookShardAggregate {
  return {
    contributorCount: 0,
    STRK: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
    USDC: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
  };
}

function aggregateBindings(
  payroll: PayrollIntegrityInputBuild,
  start: number,
  end: number,
): PayrollBookShardAggregate {
  const aggregate = emptyAggregate();
  for (const binding of payroll.proofBindings.slice(start, end)) {
    aggregate.contributorCount += 1;
    const totals = aggregate[binding.calculated.token];
    totals.grossAtomic = (BigInt(totals.grossAtomic) + BigInt(binding.calculated.grossAtomic)).toString();
    totals.deductionsAtomic = (
      BigInt(totals.deductionsAtomic) + BigInt(binding.calculated.deductionsTotalAtomic)
    ).toString();
    totals.netAtomic = (BigInt(totals.netAtomic) + BigInt(binding.calculated.netAtomic)).toString();
  }
  return aggregate;
}

function sumAggregate(
  left: PayrollBookShardAggregate,
  right: PayrollBookShardAggregate,
): UniversalPayrollBookEntry["totals"] {
  return {
    STRK: {
      grossAtomic: (BigInt(left.STRK.grossAtomic) + BigInt(right.STRK.grossAtomic)).toString(),
      deductionsAtomic: (
        BigInt(left.STRK.deductionsAtomic) + BigInt(right.STRK.deductionsAtomic)
      ).toString(),
      netAtomic: (BigInt(left.STRK.netAtomic) + BigInt(right.STRK.netAtomic)).toString(),
    },
    USDC: {
      grossAtomic: (BigInt(left.USDC.grossAtomic) + BigInt(right.USDC.grossAtomic)).toString(),
      deductionsAtomic: (
        BigInt(left.USDC.deductionsAtomic) + BigInt(right.USDC.deductionsAtomic)
      ).toString(),
      netAtomic: (BigInt(left.USDC.netAtomic) + BigInt(right.USDC.netAtomic)).toString(),
    },
  };
}

function pad<T>(values: readonly T[], size: number, create: () => T): T[] {
  if (values.length > size) throw new Error(`Cannot fit ${values.length} values into ${size} slots.`);
  return [...values, ...Array.from({ length: size - values.length }, create)];
}

function assertCommonPayrollState(payroll: PayrollIntegrityInputBuild) {
  const [first, second] = payroll.publicInputs;
  if (first.shardIndex !== "0" || second.shardIndex !== "1") {
    throw new Error("Payroll proof shards are not canonically ordered.");
  }
  for (const key of Object.keys(first) as Array<keyof typeof first>) {
    if (key !== "shardIndex" && BigInt(first[key]) !== BigInt(second[key])) {
      throw new Error("Payroll proof shards do not expose one common statement.");
    }
  }
  return first;
}

/**
 * Prepares the exact half-witnesses used by the final v3 book circuit. Each
 * shard re-hashes 25 PayrollIntegrity leaves and proves its own count/totals;
 * the on-chain seal accepts the entry only after both halves verify.
 */
export function buildUniversalPayrollBookInput(input: {
  payroll: PayrollIntegrityInputBuild;
  entryKind: Extract<PayrollBookEntryKind, "ordinary" | "vesting" | "agent">;
  ownerAddress: string;
  bookSealAddress?: string;
  sourceSealAddress: string;
  periodStart: bigint;
  periodEnd: bigint;
  totalsDisclosure: "hidden" | "public";
  totalsSalt: string;
  attestationRoot?: string;
  vestingScheduleId?: string;
  vestingStateCommitment?: string;
}): UniversalPayrollBookInputBuild {
  const payrollState = assertCommonPayrollState(input.payroll);
  if (input.payroll.proofBindings.length < 1 || input.payroll.proofBindings.length > 50) {
    throw new Error("A universal payroll-book entry requires 1–50 proved contributors.");
  }
  if (
    input.periodStart < 0n
    || input.periodEnd <= input.periodStart
    || BigInt(payrollState.validityStart) < input.periodStart
    || BigInt(payrollState.validityStart) >= input.periodEnd
  ) throw new Error("The payroll validity time is outside the reporting period.");

  const leaves = {
    agreement: pad(
      input.payroll.proofBindings.map(({ agreementLeaf }) => BigInt(agreementLeaf).toString()),
      64,
      () => BigInt(PAYO_PROOF_EMPTY_LEAF).toString(),
    ),
    payroll: pad(
      input.payroll.proofBindings.map(({ payrollLeaf }) => BigInt(payrollLeaf).toString()),
      64,
      () => BigInt(PAYO_PROOF_EMPTY_LEAF).toString(),
    ),
  };
  const aggregateZero = aggregateBindings(input.payroll, 0, 25);
  const aggregateOne = aggregateBindings(input.payroll, 25, 50);
  const makeShard = (start: number, aggregate: PayrollBookShardAggregate): UniversalPayrollBookWitnessShard => ({
    agreementLeaves: [...leaves.agreement],
    payrollLeaves: [...leaves.payroll],
    agreements: pad(
      input.payroll.proofBindings.slice(start, start + 25).map(({ agreement }) => agreement),
      25,
      emptyAgreement,
    ),
    lines: pad(
      input.payroll.proofBindings.slice(start, start + 25).map(({ line }) => line),
      25,
      emptyLine,
    ),
    aggregate,
  });

  const vestingScheduleId = input.vestingScheduleId ?? ZERO;
  const vestingStateCommitment = input.vestingStateCommitment ?? ZERO;
  const actualTotals = sumAggregate(aggregateZero, aggregateOne);
  const totalsSalt = `0x${BigInt(input.totalsSalt).toString(16).padStart(64, "0")}` as `0x${string}`;
  const totalsCommitment = payrollBookTotalsCommitment({
    subjectNullifier: input.payroll.runNullifier,
    contributorCount: aggregateZero.contributorCount + aggregateOne.contributorCount,
    totals: actualTotals,
    salt: totalsSalt,
  });
  const entry = universalPayrollBookEntrySchema.parse({
    entryVersion: "payo-payroll-book-entry-v2",
    entryKind: input.entryKind,
    chainId: `0x${BigInt(payrollState.chainId).toString(16)}`,
    sealAddress: `0x${BigInt(input.bookSealAddress ?? payrollState.sealAddress).toString(16)}`,
    sourceSealAddress: `0x${BigInt(input.sourceSealAddress).toString(16)}`,
    ownerAddress: `0x${BigInt(input.ownerAddress).toString(16)}`,
    periodStart: input.periodStart.toString(),
    periodEnd: input.periodEnd.toString(),
    agreementRoot: input.payroll.agreementRoot,
    manifestRoot: input.payroll.manifestRoot,
    policyRoot: input.payroll.policyRoot,
    fxRoot: input.payroll.fxRoot,
    runNullifier: input.payroll.runNullifier,
    subjectNullifier: input.payroll.runNullifier,
    parentFactCommitment: ZERO,
    factCommitment: ZERO,
    sourceProofVersion: 2,
    attestationRoot: input.attestationRoot ?? ZERO,
    contributorCount: aggregateZero.contributorCount + aggregateOne.contributorCount,
    totalsDisclosure: input.totalsDisclosure,
    totalsCommitment,
    totals: input.totalsDisclosure === "public"
      ? actualTotals
      : hiddenPayrollBookTotals(),
    vestingScheduleId,
    vestingStateCommitment,
  });
  const entryCommitment = universalPayrollBookEntryCommitment(entry);
  const limbs = splitHashToU128(entryCommitment);
  return {
    entry,
    entryCommitment,
    entryCommitmentLimbs: { high: limbs.high.toString(), low: limbs.low.toString() },
    entryKindCode: PAYROLL_BOOK_ENTRY_KIND_CODE[input.entryKind],
    totalsOpening: { totals: actualTotals, salt: totalsSalt },
    shards: [makeShard(0, aggregateZero), makeShard(25, aggregateOne)],
  };
}


function commitmentFromLimbs(high: string, low: string): `0x${string}` {
  const highValue = BigInt(high);
  const lowValue = BigInt(low);
  if (highValue < 0n || highValue >= 1n << 128n || lowValue < 0n || lowValue >= 1n << 128n) {
    throw new Error("Commitment limbs must fit in u128.");
  }
  return `0x${highValue.toString(16).padStart(32, "0")}${lowValue.toString(16).padStart(32, "0")}`;
}

function emptyWitnessShard(aggregate: PayrollBookShardAggregate): UniversalPayrollBookWitnessShard {
  return {
    agreementLeaves: Array(64).fill(BigInt(PAYO_PROOF_EMPTY_LEAF).toString()),
    payrollLeaves: Array(64).fill(BigInt(PAYO_PROOF_EMPTY_LEAF).toString()),
    agreements: Array.from({ length: 25 }, emptyAgreement),
    lines: Array.from({ length: 25 }, emptyLine),
    aggregate,
  };
}

/** Builds a v6/v7-sourced claim or remediation entry for the universal book. */
export function buildUniversalExceptionPayrollBookInput(input: {
  source: ExceptionPublicInputsV2;
  entryKind: Extract<PayrollBookEntryKind, "claim" | "remediation">;
  bookSealAddress: string;
  sourceSealAddress: string;
  ownerAddress: string;
  runNullifier: string;
  periodStart: bigint;
  periodEnd: bigint;
  totalsSalt: string;
  totalsDisclosure?: "hidden" | "public";
  payment?: { token: "STRK" | "USDC"; amountAtomic: string };
}): UniversalPayrollBookInputBuild {
  const expectedVersion = input.entryKind === "claim" ? 6n : 7n;
  if (BigInt(input.source.proofVersion) !== expectedVersion || BigInt(input.source.schemaVersion) !== 2n) {
    throw new Error(`A ${input.entryKind} book entry requires its v${expectedVersion.toString()} source proof.`);
  }
  if (BigInt(input.source.sealAddress) !== BigInt(input.sourceSealAddress)) {
    throw new Error("Exception book source seal does not match its proof.");
  }
  if (
    input.periodStart < 0n
    || input.periodEnd <= input.periodStart
    || BigInt(input.source.validityStart) < input.periodStart
    || BigInt(input.source.validityStart) >= input.periodEnd
  ) throw new Error("The exception proof time is outside the reporting period.");
  if (input.entryKind === "claim" && input.payment) {
    throw new Error("A claim book entry cannot contain a payment.");
  }
  if (input.entryKind === "remediation" && (!input.payment || BigInt(input.payment.amountAtomic) <= 0n)) {
    throw new Error("A remediation book entry requires its positive private payment.");
  }
  if (input.entryKind === "claim"
    && BigInt(input.runNullifier) !== BigInt(commitmentFromLimbs(
      input.source.parentNullifierHigh, input.source.parentNullifierLow,
    ))) {
    throw new Error("Claim book run nullifier differs from its v6 parent.");
  }
  const actualTotals = hiddenPayrollBookTotals();
  if (input.payment) {
    actualTotals[input.payment.token] = {
      grossAtomic: BigInt(input.payment.amountAtomic).toString(),
      deductionsAtomic: "0",
      netAtomic: BigInt(input.payment.amountAtomic).toString(),
    };
  }
  const contributorCount = 1;
  const totalsSalt = `0x${BigInt(input.totalsSalt).toString(16).padStart(64, "0")}` as `0x${string}`;
  const subjectNullifier = commitmentFromLimbs(
    input.source.subjectNullifierHigh, input.source.subjectNullifierLow,
  );
  const totalsCommitment = payrollBookTotalsCommitment({
    subjectNullifier,
    contributorCount,
    totals: actualTotals,
    salt: totalsSalt,
  });
  const disclosure = input.entryKind === "claim" ? "hidden" : input.totalsDisclosure ?? "hidden";
  const entry = universalPayrollBookEntrySchema.parse({
    entryVersion: "payo-payroll-book-entry-v2",
    entryKind: input.entryKind,
    chainId: `0x${BigInt(input.source.chainId).toString(16)}`,
    sealAddress: `0x${BigInt(input.bookSealAddress).toString(16)}`,
    sourceSealAddress: `0x${BigInt(input.sourceSealAddress).toString(16)}`,
    ownerAddress: `0x${BigInt(input.ownerAddress).toString(16)}`,
    periodStart: input.periodStart.toString(),
    periodEnd: input.periodEnd.toString(),
    agreementRoot: commitmentFromLimbs(input.source.agreementRootHigh, input.source.agreementRootLow),
    manifestRoot: commitmentFromLimbs(input.source.manifestRootHigh, input.source.manifestRootLow),
    policyRoot: commitmentFromLimbs(input.source.policyRootHigh, input.source.policyRootLow),
    fxRoot: commitmentFromLimbs(input.source.fxRootHigh, input.source.fxRootLow),
    runNullifier: input.runNullifier,
    subjectNullifier,
    parentFactCommitment: commitmentFromLimbs(
      input.source.parentFactCommitmentHigh, input.source.parentFactCommitmentLow,
    ),
    factCommitment: commitmentFromLimbs(
      input.source.factCommitmentHigh, input.source.factCommitmentLow,
    ),
    sourceProofVersion: Number(expectedVersion),
    attestationRoot: ZERO,
    contributorCount,
    totalsDisclosure: disclosure,
    totalsCommitment,
    totals: disclosure === "public" ? actualTotals : hiddenPayrollBookTotals(),
    vestingScheduleId: ZERO,
    vestingStateCommitment: ZERO,
  });
  const entryCommitment = universalPayrollBookEntryCommitment(entry);
  const entryLimbs = splitHashToU128(entryCommitment);
  const firstAggregate: PayrollBookShardAggregate = {
    contributorCount,
    STRK: { ...actualTotals.STRK },
    USDC: { ...actualTotals.USDC },
  };
  return {
    entry,
    entryCommitment,
    entryCommitmentLimbs: { high: entryLimbs.high.toString(), low: entryLimbs.low.toString() },
    entryKindCode: PAYROLL_BOOK_ENTRY_KIND_CODE[input.entryKind],
    totalsOpening: { totals: actualTotals, salt: totalsSalt },
    shards: [emptyWitnessShard(firstAggregate), emptyWitnessShard(emptyAggregate())],
  };
}
