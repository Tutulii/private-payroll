import { describe, expect, it } from "vitest";
import {
  hiddenPayrollBookTotals,
  payrollBookTotalsCommitment,
  universalPayrollBookEntryCommitment,
  universalPayrollBookEntrySchema,
  type UniversalPayrollBookEntry,
} from "./universal-payroll-book";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(64)}`;

function entry(kind: UniversalPayrollBookEntry["entryKind"] = "ordinary"): UniversalPayrollBookEntry {
  const payroll = kind === "ordinary" || kind === "vesting" || kind === "agent";
  const subjectNullifier = payroll ? hex("5") : hex("6");
  const totals = kind === "claim" ? hiddenPayrollBookTotals() : {
    STRK: { grossAtomic: "110", deductionsAtomic: "10", netAtomic: "100" },
    USDC: { grossAtomic: "220", deductionsAtomic: "20", netAtomic: "200" },
  };
  return {
    entryVersion: "payo-payroll-book-entry-v2",
    entryKind: kind,
    chainId: "0x534e5f4d41494e",
    sealAddress: "0x456",
    sourceSealAddress: payroll ? "0x456" : "0x789",
    ownerAddress: "0x123",
    periodStart: "1767225600",
    periodEnd: "1798761600",
    agreementRoot: hex("1"),
    manifestRoot: hex("2"),
    policyRoot: hex("3"),
    fxRoot: hex("4"),
    runNullifier: hex("5"),
    subjectNullifier,
    parentFactCommitment: payroll ? hex("0") : hex("7"),
    factCommitment: payroll ? hex("0") : hex("8"),
    sourceProofVersion: payroll ? 2 : kind === "claim" ? 6 : 7,
    attestationRoot: hex("9"),
    contributorCount: 2,
    totalsDisclosure: kind === "claim" ? "hidden" : "public",
    totalsCommitment: payrollBookTotalsCommitment({
      subjectNullifier, contributorCount: 2, totals, salt: hex("f"),
    }),
    totals,
    vestingScheduleId: kind === "vesting" ? hex("a") : hex("0"),
    vestingStateCommitment: kind === "vesting" ? hex("b") : hex("0"),
  };
}

describe("universal private payroll-book entry", () => {
  it("accepts each proof-bound workflow with one canonical commitment", () => {
    const commitments = (["ordinary", "vesting", "agent", "claim", "remediation"] as const)
      .map((kind) => universalPayrollBookEntryCommitment(entry(kind)));
    expect(new Set(commitments).size).toBe(5);
    expect(commitments.every((value) => /^0x[0-9a-f]{64}$/.test(value))).toBe(true);
  });

  it("changes the commitment for every accountability binding", () => {
    const original = entry();
    const expected = universalPayrollBookEntryCommitment(original);
    const mutations: Array<(value: UniversalPayrollBookEntry) => void> = [
      (value) => { value.entryKind = "agent"; },
      (value) => { value.ownerAddress = "0x124"; },
      (value) => { value.sourceSealAddress = "0x457"; },
      (value) => { value.policyRoot = hex("c"); },
      (value) => { value.fxRoot = hex("d"); },
      (value) => { value.attestationRoot = hex("e"); },
      (value) => { value.contributorCount = 3; },
      (value) => { value.totalsCommitment = hex("d"); },
      (value) => { value.totals.STRK.netAtomic = "99"; value.totals.STRK.deductionsAtomic = "11"; },
    ];
    for (const mutate of mutations) {
      const changed = structuredClone(original);
      mutate(changed);
      expect(universalPayrollBookEntryCommitment(changed)).not.toBe(expected);
    }
  });

  it("rejects wrong proof versions, unbalanced totals and exception impersonation", () => {
    expect(() => universalPayrollBookEntrySchema.parse({ ...entry("claim"), sourceProofVersion: 2 }))
      .toThrow(/wage-claim v6/);
    const unbalanced = entry();
    unbalanced.totals.STRK.netAtomic = "101";
    expect(() => universalPayrollBookEntrySchema.parse(unbalanced)).toThrow(/do not balance/);
    expect(() => universalPayrollBookEntrySchema.parse({ ...entry(), factCommitment: hex("f") }))
      .toThrow(/cannot impersonate/);
  });

  it("keeps hidden totals canonical and makes vesting state exclusive", () => {
    const hidden = entry();
    hidden.totalsDisclosure = "hidden";
    expect(() => universalPayrollBookEntrySchema.parse(hidden)).toThrow(/canonical zeros/);
    expect(() => universalPayrollBookEntrySchema.parse({
      ...entry(),
      vestingScheduleId: hex("a"),
      vestingStateCommitment: hex("b"),
    })).toThrow(/Only vesting/);
  });
});
