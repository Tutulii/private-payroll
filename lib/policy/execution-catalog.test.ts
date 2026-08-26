import { describe, expect, it } from "vitest";
import {
  calculatePolicyDeductions,
  resolveExecutionPolicy,
  resolvePayrollPolicyCohort,
} from "./execution-catalog";

const at = new Date("2026-08-26T00:00:00.000Z");

describe("payroll execution policy catalog", () => {
  it("derives the exact employee statutory deduction without browser-entered tax", () => {
    const policy = resolveExecutionPolicy({
      policyId: "us-irs-supplemental-flat-2026-v1",
      policyVersion: 1,
      jurisdictionCode: "US-CA",
      classification: "employee",
      settlementToken: "USDC",
      at,
    });
    expect(calculatePolicyDeductions(policy, ["1000000", "500000"])).toEqual(["330000"]);
  });

  it("fails closed on jurisdiction, classification, version, and mixed-policy cohorts", () => {
    expect(() => resolveExecutionPolicy({
      policyId: "us-irs-supplemental-flat-2026-v1",
      policyVersion: 1,
      jurisdictionCode: "GB",
      classification: "employee",
      settlementToken: "USDC",
      at,
    })).toThrow(/does not apply in/i);
    expect(() => resolveExecutionPolicy({
      policyId: "us-irs-supplemental-flat-2026-v1",
      policyVersion: 2,
      jurisdictionCode: "US",
      classification: "employee",
      settlementToken: "USDC",
      at,
    })).toThrow(/not installed/i);
    const base = {
      agreementVersion: "payo-agreement-v1" as const,
      id: "a",
      organizationId: "organization-1",
      principalKind: "human" as const,
      classification: "employee" as const,
      classificationFactsCommitment: `0x${"11".repeat(32)}`,
      jurisdictionCode: "US",
      settlementToken: "USDC" as const,
      earningsAtomic: ["100"],
      schedule: { kind: "recurring" as const, cadence: "monthly" as const, nextDueAt: at.toISOString() },
      statutoryPolicy: { catalogRoot: `0x${"12".repeat(32)}`, policyId: "us-irs-supplemental-flat-2026-v1", policyVersion: 1 },
    };
    expect(() => resolvePayrollPolicyCohort([
      base,
      {
        ...base,
        id: "b",
        classification: "contractor",
        statutoryPolicy: { ...base.statutoryPolicy, policyId: "payo-net-invoice-no-withholding-v1" },
      },
    ], at)).toThrow(/separate private payroll cohorts/i);
  });
});
