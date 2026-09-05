import type { ExceptionPublicInputsV2 } from "@/lib/domain/exception-protocol";
import {
  PAYROLL_BOOK_ENTRY_KIND_CODE,
  utcAnnualPayrollBookPeriod,
} from "@/lib/domain/universal-payroll-book";
import {
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
  type VestingBookProof,
} from "./protocol";
import {
  orderedVestingTransitionPublicInputs,
  hashProofCalldata,
} from "./starknet-calldata";
import {
  buildUniversalExceptionPayrollBookInput,
} from "./universal-payroll-book-input";
import type {
  VestingTransitionInputBuild,
  VestingTransitionPublicInputs,
} from "./vesting-transition-input";

const ZERO = `0x${"00".repeat(32)}` as const;
const TEST_SALT = `0x${"a7".repeat(32)}` as const;
const U128_MASK = (1n << 128n) - 1n;

function commitment(high: string, low: string): `0x${string}` {
  return `0x${BigInt(high).toString(16).padStart(32, "0")}${BigInt(low).toString(16).padStart(32, "0")}`;
}

function split(value: string): { high: string; low: string } {
  const parsed = BigInt(value);
  return {
    high: (parsed >> 128n).toString(),
    low: (parsed & U128_MASK).toString(),
  };
}

function directGaragaCalldata(publicInputs: VestingTransitionPublicInputs): string[] {
  const output = [`0x${orderedVestingTransitionPublicInputs(publicInputs).length.toString(16)}`];
  for (const value of orderedVestingTransitionPublicInputs(publicInputs)) {
    const parsed = BigInt(value);
    output.push(`0x${(parsed & U128_MASK).toString(16)}`);
    output.push(`0x${(parsed >> 128n).toString(16)}`);
  }
  return output;
}

/**
 * Produces structurally valid direct-Garaga calldata around already-built
 * public inputs. This is intentionally test-only: it does not manufacture a
 * cryptographic proof and must never be used as deployment evidence.
 */
export function mockVestingBookProof(
  build: VestingTransitionInputBuild,
): VestingBookProof {
  return {
    proofVersion: 3,
    entryKind: build.entryKind,
    circuitSha256: VESTING_TRANSITION_CIRCUIT_SHA256,
    verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
    provingTimeMs: 1,
    scheduleId: build.scheduleId,
    previousStateCommitment: build.previousStateCommitment,
    nextStateCommitment: build.nextStateCommitment,
    releaseNullifier: build.releaseNullifier,
    bookEntry: build.bookEntry,
    bookEntryCommitment: build.bookEntryCommitment,
    shards: build.publicInputs.map((publicInputs, shardIndex) => {
      const proofCalldata = directGaragaCalldata(publicInputs);
      return {
        shardIndex: shardIndex as 0 | 1,
        proof: Uint8Array.of(1),
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs,
      };
    }) as VestingBookProof["shards"],
  };
}

/** Persistence/relayer fixture for tests whose source proof bytes are fixed. */
export function mockExceptionBookProof(input: {
  source: ExceptionPublicInputsV2;
  entryKind: "claim" | "remediation";
  bookSealAddress: string;
  sourceSealAddress: string;
  ownerAddress: string;
  runNullifier?: string;
  payment?: { token: "STRK" | "USDC"; amountAtomic: string };
}): VestingBookProof {
  const period = utcAnnualPayrollBookPeriod(input.source.validityStart);
  const runNullifier = input.runNullifier
    ?? commitment(input.source.parentNullifierHigh, input.source.parentNullifierLow);
  const build = buildUniversalExceptionPayrollBookInput({
    source: input.source,
    entryKind: input.entryKind,
    bookSealAddress: input.bookSealAddress,
    sourceSealAddress: input.sourceSealAddress,
    ownerAddress: input.ownerAddress,
    runNullifier,
    periodStart: period.periodStart,
    periodEnd: period.periodEnd,
    totalsSalt: TEST_SALT,
    ...(input.entryKind === "remediation"
      ? { payment: input.payment ?? { token: "STRK", amountAtomic: "1" } }
      : {}),
  });
  const totals = build.entry.totals;
  const bookEntry = split(build.entryCommitment);
  const totalsCommitment = split(build.entry.totalsCommitment);
  const run = split(runNullifier);
  const common = {
    chainId: `0x${BigInt(input.source.chainId).toString(16)}`,
    sealAddress: `0x${BigInt(input.bookSealAddress).toString(16)}`,
    proofVersion: "3" as const,
    schemaVersion: "1" as const,
    entryKind: PAYROLL_BOOK_ENTRY_KIND_CODE[input.entryKind].toString() as "3" | "4",
    agreementRootHigh: input.source.agreementRootHigh,
    agreementRootLow: input.source.agreementRootLow,
    manifestRootHigh: input.source.manifestRootHigh,
    manifestRootLow: input.source.manifestRootLow,
    policyRootHigh: input.source.policyRootHigh,
    policyRootLow: input.source.policyRootLow,
    fxRootHigh: input.source.fxRootHigh,
    fxRootLow: input.source.fxRootLow,
    runNullifierHigh: run.high,
    runNullifierLow: run.low,
    subjectNullifierHigh: input.source.subjectNullifierHigh,
    subjectNullifierLow: input.source.subjectNullifierLow,
    parentFactHigh: input.source.parentFactCommitmentHigh,
    parentFactLow: input.source.parentFactCommitmentLow,
    factHigh: input.source.factCommitmentHigh,
    factLow: input.source.factCommitmentLow,
    ownerAddress: BigInt(input.ownerAddress).toString(),
    sourceSealAddress: BigInt(input.sourceSealAddress).toString(),
    sourceProofVersion: input.source.proofVersion,
    attestationRootHigh: "0",
    attestationRootLow: "0",
    shard0ContributorCount: "1",
    shard1ContributorCount: "0",
    totalsDisclosed: "0" as const,
    totalsCommitmentHigh: totalsCommitment.high,
    totalsCommitmentLow: totalsCommitment.low,
    shard0StrkGross: totals.STRK.grossAtomic,
    shard0StrkDeductions: totals.STRK.deductionsAtomic,
    shard0StrkNet: totals.STRK.netAtomic,
    shard0UsdcGross: totals.USDC.grossAtomic,
    shard0UsdcDeductions: totals.USDC.deductionsAtomic,
    shard0UsdcNet: totals.USDC.netAtomic,
    shard1StrkGross: "0",
    shard1StrkDeductions: "0",
    shard1StrkNet: "0",
    shard1UsdcGross: "0",
    shard1UsdcDeductions: "0",
    shard1UsdcNet: "0",
    scheduleIdHigh: "0",
    scheduleIdLow: "0",
    previousStateHigh: "0",
    previousStateLow: "0",
    nextStateHigh: "0",
    nextStateLow: "0",
    releaseNullifierHigh: "0",
    releaseNullifierLow: "0",
    bookEntryHigh: bookEntry.high,
    bookEntryLow: bookEntry.low,
    periodStart: period.periodStart.toString(),
    periodEnd: period.periodEnd.toString(),
    validityStart: input.source.validityStart,
    validityExpiry: input.source.validityExpiry,
  } satisfies Omit<VestingTransitionPublicInputs, "shardIndex">;
  return mockVestingBookProof({
    circuitInputs: [{} as never, {} as never],
    publicInputs: [
      { ...common, shardIndex: "0" },
      { ...common, shardIndex: "1" },
    ],
    scheduleId: ZERO,
    previousStateCommitment: ZERO,
    nextStateCommitment: ZERO,
    releaseNullifier: ZERO,
    bookEntry: build.entry,
    bookEntryCommitment: build.entryCommitment,
    totalsOpening: build.totalsOpening,
    entryKind: input.entryKind,
  });
}
