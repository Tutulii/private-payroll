import { describe, expect, it } from "vitest";
import { generatePhase3UiWorkflowFixture } from "./phase3-ui-workflow-fixture";

describe("Phase 3 UI-originated workflow fixture", () => {
  it("creates every advanced workflow through the production form command", async () => {
    const fixture = await generatePhase3UiWorkflowFixture();
    expect(fixture.entries.map(({ workflow }) => workflow)).toEqual([
      "recurring",
      "checkpoint",
      "milestone",
      "vesting",
      "final-pay",
      "approved-adjustment",
      "statutory-fx-classification",
    ]);
    expect(new Set(fixture.entries.map(({ agreementRecord }) => agreementRecord.agreement.id)).size).toBe(7);
    expect(fixture.entries.every(({ agreementRecord }) =>
      agreementRecord.agreement.agreementVersion === "payo-agreement-v2")).toBe(true);
    expect(fixture.entries.every(({ checks }) =>
      checks.productionCommand === "storeEncryptedAgreementFromForm"
      && checks.encryptedRoundTrip
      && checks.plaintextAbsentFromEnvelope)).toBe(true);

    const recurring = fixture.entries.find(({ workflow }) => workflow === "recurring")!;
    expect(recurring.agreementRecord.agreement).toMatchObject({
      agreementVersion: "payo-agreement-v2",
      paymentPlan: { kind: "recurring" },
    });
    const finalPay = fixture.entries.find(({ workflow }) => workflow === "final-pay")!;
    expect(finalPay.agreementRecord.agreement).toMatchObject({
      termination: {
        pay: {
          ordinaryPayAtomic: "100000",
          accruedLeaveAtomic: "20000",
          noticeAtomic: "30000",
          severanceAtomic: "40000",
          adjustmentsAtomic: "10000",
          deductionsAtomic: "0",
        },
      },
    });
    const protectedPay = fixture.entries.find(({ workflow }) =>
      workflow === "statutory-fx-classification")!;
    expect(protectedPay.agreementRecord.agreement).toMatchObject({
      classification: "employee",
      statutoryPolicy: { policyId: "us-irs-supplemental-flat-2026-v1" },
      fxProtection: {
        referenceCurrency: "USD",
        minimumReferenceAtomic: "7800000",
        maximumAgeSeconds: 300,
      },
    });
  });
});
