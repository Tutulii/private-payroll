import { describe, expect, it } from "vitest";
import {
  DEMO_PROGRESSIVE_POLICY,
  evaluatePolicyPack,
  policyPackCommitment,
} from "./engine";

describe("bounded policy engine", () => {
  it("evaluates progressive brackets using atomic integer arithmetic", () => {
    expect(evaluatePolicyPack(DEMO_PROGRESSIVE_POLICY, { taxable_gross: "6000" }))
      .toEqual({ statutoryWithholding: "1200" });
  });

  it("commits every instruction and policy version", () => {
    const original = policyPackCommitment(DEMO_PROGRESSIVE_POLICY);
    const changed = policyPackCommitment({ ...DEMO_PROGRESSIVE_POLICY, revision: 2 });
    expect(original).toMatch(/^0x[0-9a-f]{64}$/);
    expect(changed).not.toBe(original);
  });

  it("rejects an incomplete bracket table", () => {
    const incomplete = {
      ...DEMO_PROGRESSIVE_POLICY,
      instructions: [
        { op: "INPUT" as const, out: "taxable", key: "taxable_gross" },
        {
          op: "BRACKET" as const,
          out: "withholding",
          input: "taxable",
          brackets: [{ upperAtomic: "1000", rateBps: 1000 }],
        },
      ],
    };
    expect(() => evaluatePolicyPack(incomplete, { taxable_gross: "2000" })).toThrow("do not cover");
  });
});
