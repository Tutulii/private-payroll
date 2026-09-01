import { describe, expect, it } from "vitest";
import {
  MAX_POLICY_GAS_TARGET_FRI,
  hasFundingBalance,
  parsePolicyGasTargetFri,
  policyGasFundingDelta,
} from "./policy-gas-funding.mjs";

describe("Phase 5 policy-account gas funding", () => {
  it("accepts an exact reviewed target within the safety ceiling", () => {
    expect(parsePolicyGasTargetFri("500000000000000000")).toBe(
      500_000_000_000_000_000n,
    );
    expect(parsePolicyGasTargetFri(MAX_POLICY_GAS_TARGET_FRI.toString())).toBe(
      MAX_POLICY_GAS_TARGET_FRI,
    );
  });

  it.each([undefined, "", "0", "-1", "1.5", "0x1"])(
    "rejects an invalid target %s",
    (value) => {
      expect(() => parsePolicyGasTargetFri(value)).toThrow();
    },
  );

  it("rejects a target above the hard operational ceiling", () => {
    expect(() =>
      parsePolicyGasTargetFri((MAX_POLICY_GAS_TARGET_FRI + 1n).toString()),
    ).toThrow("20 STRK safety ceiling");
  });

  it("funds only the shortfall and never overfunds an existing balance", () => {
    expect(policyGasFundingDelta(100n, 500n)).toBe(400n);
    expect(policyGasFundingDelta(500n, 500n)).toBe(0n);
    expect(policyGasFundingDelta(700n, 500n)).toBe(0n);
  });

  it("requires transfer value and simulated fee together", () => {
    expect(hasFundingBalance(110n, 100n, 10n)).toBe(true);
    expect(hasFundingBalance(109n, 100n, 10n)).toBe(false);
  });
});
