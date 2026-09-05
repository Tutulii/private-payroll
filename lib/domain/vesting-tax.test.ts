import { describe, expect, it } from "vitest";
import {
  appendPayrollBookRoot,
  assertVestingTransition,
  initialPayrollBookRoot,
  payrollBookEntryCommitment,
  verifyCompletePayrollBook,
  vestingScheduleId,
  vestingStateCommitment,
  type CompletePayrollBook,
  type PayrollBookEntry,
  type VestingScheduleTerms,
  type VestingState,
} from "./vesting-tax";

const hex = (byte: string) => `0x${byte.repeat(64)}`;
const address = (suffix: string) => `0x${suffix.padStart(64, "0")}`;

const schedule: VestingScheduleTerms = {
  scheduleVersion: "payo-private-vesting-v1",
  agreementIdCommitment: hex("1"),
  recipientCommitment: hex("2"),
  tokenAddress: address("3"),
  startsAt: "100",
  cliffAt: "200",
  endsAt: "1100",
  totalAtomic: "1000",
  planSalt: hex("4"),
};

function transition() {
  const scheduleId = vestingScheduleId(schedule);
  const previous: VestingState = {
    stateVersion: "payo-vesting-state-v1",
    scheduleId,
    releasedAtomic: "0",
    releaseSequence: 0,
    stateSalt: hex("5"),
  };
  const next: VestingState = {
    ...previous,
    releasedAtomic: "500",
    releaseSequence: 1,
    stateSalt: hex("6"),
  };
  return {
    transitionVersion: "payo-vesting-transition-v1" as const,
    schedule,
    previous,
    releaseAt: "600",
    payableAtomic: "500",
    next,
    runNullifier: hex("7"),
  };
}

describe("stateful private vesting", () => {
  it("accepts the exact first linear release and derives opaque public state", () => {
    const result = assertVestingTransition(transition());
    expect(result.previousStateCommitment).toBe(`0x${"00".repeat(32)}`);
    expect(result.nextStateCommitment).toBe(vestingStateCommitment(transition().next));
    expect(result.releaseNullifier).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("rejects an early release, changed amount, stale sequence, and changed schedule", () => {
    expect(() => assertVestingTransition({ ...transition(), releaseAt: "199", payableAtomic: "0" }))
      .toThrow("cliff");
    expect(() => assertVestingTransition({ ...transition(), payableAtomic: "499" }))
      .toThrow("exact unpaid vested delta");
    expect(() => assertVestingTransition({
      ...transition(),
      next: { ...transition().next, releaseSequence: 2 },
    })).toThrow("increment exactly once");
    expect(() => assertVestingTransition({
      ...transition(),
      schedule: { ...schedule, totalAtomic: "1001" },
    })).toThrow("different immutable schedule");
  });

  it("advances from the committed previous release without allowing double pay", () => {
    const first = transition();
    const firstResult = assertVestingTransition(first);
    const previous = { ...first.next };
    const next = {
      ...previous,
      releasedAtomic: "750",
      releaseSequence: 2,
      stateSalt: hex("8"),
    };
    const second = assertVestingTransition({
      ...first,
      previous,
      releaseAt: "850",
      payableAtomic: "250",
      next,
      runNullifier: hex("9"),
    });
    expect(second.previousStateCommitment).toBe(firstResult.nextStateCommitment);
    expect(() => assertVestingTransition({
      ...first,
      previous,
      releaseAt: "850",
      payableAtomic: "500",
      next,
      runNullifier: hex("9"),
    })).toThrow("exact unpaid vested delta");
  });
});

function bookEntry(runByte: string, manifestByte: string): PayrollBookEntry {
  return {
    entryVersion: "payo-payroll-book-entry-v1",
    chainId: address("534e5f4d41494e"),
    sealAddress: address("456"),
    ownerAddress: address("123"),
    periodStart: "1",
    periodEnd: "1000",
    agreementRoot: hex("a"),
    manifestRoot: hex(manifestByte),
    runNullifier: hex(runByte),
    payrollProofVersion: 3,
    vestingScheduleId: hex("c"),
    vestingStateCommitment: hex("d"),
  };
}

function completeBook(): CompletePayrollBook {
  const entries = [bookEntry("1", "2"), bookEntry("3", "4")];
  let accumulatorRoot = initialPayrollBookRoot(entries[0]);
  const disclosures = entries.map((entry, index) => {
    const entryCommitment = payrollBookEntryCommitment(entry);
    accumulatorRoot = appendPayrollBookRoot({ previousRoot: accumulatorRoot, entryCommitment, index });
    return {
      index,
      entry,
      entryCommitment,
      lines: [{
        recipientReference: `worker-${index}`,
        jurisdictionCode: "US-CA",
        token: index === 0 ? "STRK" as const : "USDC" as const,
        grossAtomic: "100",
        deductionsAtomic: "20",
        netAtomic: "80",
      }],
      integrityVerificationTransactionHash: address(`${index + 10}`),
      settlementTransactionHash: address(`${index + 20}`),
    };
  });
  return {
    packageVersion: "payo-complete-payroll-book-v1",
    scope: "tax_authority",
    checkpoint: {
      checkpointVersion: "payo-payroll-book-checkpoint-v1",
      chainId: entries[0].chainId,
      sealAddress: entries[0].sealAddress,
      ownerAddress: entries[0].ownerAddress,
      periodStart: entries[0].periodStart,
      periodEnd: entries[0].periodEnd,
      entryCount: disclosures.length,
      accumulatorRoot,
    },
    entries: disclosures,
    generatedAt: "2026-09-04T00:00:00.000Z",
  };
}

describe("complete private payroll books", () => {
  it("matches the Cairo Starknet Poseidon accumulator vector", () => {
    const initial = initialPayrollBookRoot({
      chainId: address("534e5f4d41494e"),
      sealAddress: address("456"),
      ownerAddress: address("123"),
      periodStart: 1n,
      periodEnd: 1000n,
    });
    expect(initial).toBe("0x07bea589f92bbffe2718c60e970c29da3160dc9f7b23519b6baeef7010644fd8");
    expect(appendPayrollBookRoot({
      previousRoot: initial,
      entryCommitment: "0x0000000000000000000000000000005100000000000000000000000000000034",
      index: 0,
    })).toBe("0x05e96f9d434f47d636570b6583ab6f49a3c524b51a80be259d77d24d16b96544");
  });

  it("reconstructs the exact on-chain accumulator and balanced totals", () => {
    expect(verifyCompletePayrollBook(completeBook())).toMatchObject({
      verified: true,
      entryCount: 2,
      totals: {
        STRK: { grossAtomic: "100", deductionsAtomic: "20", netAtomic: "80" },
        USDC: { grossAtomic: "100", deductionsAtomic: "20", netAtomic: "80" },
      },
    });
  });

  it("rejects omission, duplication, mutation, wrong period, and unbalanced tax facts", () => {
    const omitted = completeBook();
    omitted.entries.pop();
    expect(() => verifyCompletePayrollBook(omitted)).toThrow("incomplete");

    const duplicated = completeBook();
    duplicated.entries[1] = { ...duplicated.entries[1], entry: duplicated.entries[0].entry };
    expect(() => verifyCompletePayrollBook(duplicated)).toThrow(/duplicates|commitment/);

    const changed = completeBook();
    changed.entries[0] = {
      ...changed.entries[0],
      entry: { ...changed.entries[0].entry, manifestRoot: hex("e") },
    };
    expect(() => verifyCompletePayrollBook(changed)).toThrow("commitment");

    const wrongPeriod = completeBook();
    wrongPeriod.entries[0] = {
      ...wrongPeriod.entries[0],
      entry: { ...wrongPeriod.entries[0].entry, periodStart: "2" },
    };
    expect(() => verifyCompletePayrollBook(wrongPeriod)).toThrow(/different owner or reporting period/);

    const unbalanced = completeBook();
    unbalanced.entries[0].lines[0].netAtomic = "81";
    expect(() => verifyCompletePayrollBook(unbalanced)).toThrow("arithmetic");
  });
});
