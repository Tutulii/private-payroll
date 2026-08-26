import { describe, expect, it } from "vitest";
import type { EmploymentAgreement } from "@/lib/domain/obligations";
import { advancedPlanProofCommitment } from "./advanced-plan-commitment";

const agreement: Extract<EmploymentAgreement, { agreementVersion: "payo-agreement-v2" }> = {
  agreementVersion: "payo-agreement-v2",
  id: "018f05d7-6af4-7c78-8f87-223fd7641b03",
  organizationId: "018f05d7-6af4-7c78-8f87-223fd7641b04",
  principalKind: "human",
  classification: "contractor",
  classificationFactsCommitment: `0x${"10".repeat(32)}`,
  jurisdictionCode: "US",
  settlementToken: "USDC",
  earningsAtomic: ["500"],
  schedule: {
    kind: "stream",
    startsAt: "2026-01-01T00:00:00.000Z",
    endsAt: "2026-01-11T00:00:00.000Z",
    totalAtomic: "1000",
    claimedAtomic: "0",
  },
  statutoryPolicy: { policyId: "policy", policyVersion: 1, catalogRoot: `0x${"11".repeat(32)}` },
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
};

describe("advanced plan proof commitment", () => {
  it("matches the proof-field shape and binds plan progress", async () => {
    const commitment = await advancedPlanProofCommitment(agreement);
    expect(commitment).toBe("0x0e5da91863700962d2aa384d9b58d5ee0c1e7b28a47255ad51d8392df44dde7c");
    expect(commitment).toMatch(/^0x[0-9a-f]{64}$/);
    if (agreement.schedule.kind !== "stream" || agreement.paymentPlan.kind !== "checkpoint_stream") {
      throw new Error("invalid checkpoint fixture");
    }
    const changed: Extract<EmploymentAgreement, { agreementVersion: "payo-agreement-v2" }> = {
      ...agreement,
      schedule: { ...agreement.schedule, claimedAtomic: "1" },
      paymentPlan: { ...agreement.paymentPlan, settledAtomic: "1" },
    };
    expect(await advancedPlanProofCommitment(changed)).not.toBe(commitment);
  });
});
