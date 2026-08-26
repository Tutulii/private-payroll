import { describe, expect, it } from "vitest";
import { buildVerifierBackedProfiles } from "./advanced-proof-profile";

const id = (suffix: string) => `018f1000-0000-7000-8000-${suffix.padStart(12, "0")}`;
const hash = (byte: string) => `0x${byte.repeat(64)}`;

const base = {
  organizationId: id("1"),
  runId: id("2"),
  proofBundleId: id("3"),
  proofVersion: "1",
  circuitSha256: hash("1"),
  verificationKeySha256: hash("2"),
  publicInputsHash: hash("3"),
  agreementRoot: hash("4"),
  manifestRoot: hash("5"),
  policyRoot: hash("6"),
  fxRoot: hash("7"),
  runNullifier: hash("8"),
  verificationState: "onchain_verified" as const,
  verifiedAt: new Date("2026-08-26T00:00:00.000Z"),
};

describe("verifier-backed Phase 3 profiles", () => {
  it("derives only profiles actually activated by the encrypted lines", () => {
    const profiles = buildVerifierBackedProfiles({
      ...base,
      lines: [
        { fxFloorAtomic: "100", finalPay: { requiredMask: 7, includedMask: 7 } },
        { fxFloorAtomic: "0" },
      ],
    });
    expect(profiles.map(({ profile }) => profile)).toEqual([
      "statutory_correct",
      "classification_consistency",
      "fx_floor",
      "offboarding_correct",
    ]);
    expect(profiles.find(({ profile }) => profile === "fx_floor")?.coveredLineCount).toBe(1);
    expect(JSON.stringify(profiles)).not.toContain("salary");
  });

  it("refuses to issue verifier-backed claims from local or rejected evidence", () => {
    expect(() => buildVerifierBackedProfiles({
      ...base,
      verificationState: "locally_verified",
      lines: [{}],
    })).toThrow("on-chain verified");
    expect(() => buildVerifierBackedProfiles({
      ...base,
      verificationState: "rejected",
      lines: [{}],
    })).toThrow("on-chain verified");
  });

  it("rejects an offboarding profile whose committed masks are incomplete", () => {
    expect(() => buildVerifierBackedProfiles({
      ...base,
      lines: [{ finalPay: { requiredMask: 7, includedMask: 3 } }],
    })).toThrow("incomplete final-pay mask");
  });
});
