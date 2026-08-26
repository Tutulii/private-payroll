import { describe, expect, it, vi } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { prepareEncryptedPayee } from "./payee-directory";
import {
  storeEncryptedAgreementFromForm,
  type AgreementFormDraft,
  type AgreementPlanKind,
} from "./agreement-form-workflow";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const now = new Date("2026-08-24T12:00:00.000Z");
const commitment = (byte: string) => `0x${byte.repeat(64)}`;

function baseDraft(planKind: AgreementPlanKind): AgreementFormDraft {
  return {
    planKind,
    amount: "1",
    classification: "contractor",
    classificationAnswers: referenceClassificationAnswers("contractor"),
    cadence: "monthly",
    nextDueAt: now.toISOString(),
    planStartsAt: "2026-08-24T10:00:00.000Z",
    planEndsAt: "2026-08-24T14:00:00.000Z",
    planCheckpointAt: now.toISOString(),
    planCliffAt: "2026-08-24T11:00:00.000Z",
    planTotalAmount: "1",
    milestoneCommitment: commitment("1"),
    approverCommitment: commitment("2"),
    attestationCommitment: commitment("3"),
    adjustmentReasonCommitment: commitment("4"),
    terminationReasonCommitment: commitment("5"),
    finalOrdinaryAmount: "0.1",
    finalLeaveAmount: "0.02",
    finalNoticeAmount: "0.03",
    finalSeveranceAmount: "0.04",
    finalAdjustmentAmount: "0.01",
    finalDeductionsAmount: "0",
    requireLeave: true,
    requireNotice: true,
    requireSeverance: true,
    policyId: "payo-net-invoice-no-withholding-v1",
    policyVersion: 1,
    fxFloorAmount: "",
    fxMaximumAgeSeconds: 300,
  };
}

describe("Team agreement form production workflow", () => {
  it.each([
    ["recurring", "payo-agreement-v2", "recurring"],
    ["checkpoint_stream", "payo-agreement-v2", "checkpoint_stream"],
    ["milestone", "payo-agreement-v2", "milestone"],
    ["private_vesting", "payo-agreement-v2", "private_vesting"],
    ["approved_adjustment", "payo-agreement-v2", "milestone"],
    ["final_pay", "payo-agreement-v2", "milestone"],
  ] as const)("stores and encrypts the %s form", async (planKind, agreementVersion, storedPlanKind) => {
    const principal = generateVaultPrincipal("admin:ui-workflow");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Private worker",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      now,
    }).record;
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const record = await storeEncryptedAgreementFromForm({
      client: { storeEncryptedRecord } as never,
      organizationId,
      payee,
      principal,
      draft: baseDraft(planKind),
      now,
    });

    expect(record.agreement.agreementVersion).toBe(agreementVersion);
    if (record.agreement.agreementVersion === "payo-agreement-v2") {
      expect(record.agreement.paymentPlan.kind).toBe(storedPlanKind);
      if (planKind === "approved_adjustment") expect(record.agreement.adjustment).toBeDefined();
      if (planKind === "final_pay") expect(record.agreement.termination).toBeDefined();
    } else {
      expect(record.agreement.schedule.kind).toBe(storedPlanKind);
    }
    expect(storeEncryptedRecord).toHaveBeenCalledTimes(1);
    const request = storeEncryptedRecord.mock.calls[0][0];
    expect(request.recordType).toBe("pay-agreement");
    expect(JSON.stringify(request.envelope)).not.toContain("Private worker");
    expect(decryptVaultRecord(request.envelope, principal)).toEqual(record);
  });

  it("rejects an inconsistent classification before writing ciphertext", async () => {
    const principal = generateVaultPrincipal("admin:ui-negative");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Private worker",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      now,
    }).record;
    const storeEncryptedRecord = vi.fn();
    await expect(storeEncryptedAgreementFromForm({
      client: { storeEncryptedRecord } as never,
      organizationId,
      payee,
      principal,
      draft: {
        ...baseDraft("recurring"),
        classification: "employee",
      },
      now,
    })).rejects.toThrow(/classification fact rubric/i);
    expect(storeEncryptedRecord).not.toHaveBeenCalled();
  });
});
