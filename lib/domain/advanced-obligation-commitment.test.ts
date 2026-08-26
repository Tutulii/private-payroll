import { describe, expect, it } from "vitest";
import { advancedObligationCommitment } from "./advanced-obligation-commitment";
import type { EmploymentAgreement } from "./obligations";

const agreement = {
  agreementVersion: "payo-agreement-v2",
  id: "agreement-0001",
  organizationId: "organization-0001",
  principalKind: "human",
  classification: "contractor",
  classificationFactsCommitment: `0x${"01".repeat(32)}`,
  jurisdictionCode: "US-CA",
  settlementToken: "USDC",
  earningsAtomic: ["500"],
  schedule: {
    kind: "stream",
    startsAt: "2026-01-01T00:00:00.000Z",
    endsAt: "2026-01-11T00:00:00.000Z",
    totalAtomic: "1000",
    claimedAtomic: "0",
  },
  paymentPlan: {
    planVersion: "payo-payment-plan-v1",
    kind: "checkpoint_stream",
    startsAt: "2026-01-01T00:00:00.000Z",
    endsAt: "2026-01-11T00:00:00.000Z",
    totalAtomic: "1000",
    settledAtomic: "0",
    minimumCheckpointSeconds: 300,
    checkpoint: {
      sequence: 1,
      checkpointAt: "2026-01-06T00:00:00.000Z",
      cumulativeEntitlementAtomic: "500",
      attestationCommitment: `0x${"02".repeat(32)}`,
    },
  },
  planSalt: `0x${"03".repeat(32)}`,
  statutoryPolicy: {
    catalogRoot: `0x${"04".repeat(32)}`,
    policyId: "payo-net-invoice-no-withholding-v1",
    policyVersion: 1,
  },
} satisfies EmploymentAgreement;

describe("advanced obligation commitment", () => {
  it("has a deterministic binary-encoding golden vector", () => {
    expect(advancedObligationCommitment(agreement)).toBe(
      "0x8755872ec73d646ac2dde2f957889d09ed6f1dc975f208380ccd02f23a148be7",
    );
  });

  it("binds schedule progress, approvals, final pay, adjustments, and salt", () => {
    const base = advancedObligationCommitment(agreement);
    expect(advancedObligationCommitment({
      ...agreement,
      paymentPlan: { ...agreement.paymentPlan, settledAtomic: "1" },
      schedule: { ...agreement.schedule, claimedAtomic: "1" },
    })).not.toBe(base);
    expect(advancedObligationCommitment({ ...agreement, planSalt: `0x${"05".repeat(32)}` })).not.toBe(base);
  });
});
