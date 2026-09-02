import { describe, expect, it, vi } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { generateUuidV7 } from "@/lib/domain/records";
import { prepareEncryptedPayee } from "./payee-directory";
import {
  advanceEncryptedRecurringAgreement,
  agreementScheduleCommitment,
  lockedPayrollScheduleCommitments,
  storeEncryptedAdvancedAgreement,
  storeEncryptedRecurringAgreement,
  synchronizeConfirmedRecurringAgreements,
} from "./agreement-directory";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const now = new Date("2026-08-24T12:00:00.000Z");

describe("encrypted pay agreements", () => {
  it("stores exact atomic compensation and commitment salts only as ciphertext", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US-CA",
      principal,
      now,
    }).record;
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const agreement = await storeEncryptedRecurringAgreement({
      client: { storeEncryptedRecord } as never,
      organizationId,
      payee,
      amount: "1250.25",
      token: "USDC",
      classification: "contractor",
      classificationAnswers: referenceClassificationAnswers("contractor"),
      cadence: "monthly",
      nextDueAt: "2026-08-31T00:00:00.000Z",
      policyId: "payo-net-invoice-no-withholding-v1",
      policyVersion: 1,
      principal,
      now,
    });
    expect(agreement.agreement.earningsAtomic).toEqual(["1250250000"]);
    expect(agreement.recipientSalt).toMatch(/^0x[0-9a-f]{64}$/);
    expect(agreement.agreementSalt).toMatch(/^0x[0-9a-f]{64}$/);
    const request = storeEncryptedRecord.mock.calls[0][0];
    expect(request.recordType).toBe("pay-agreement");
    expect(JSON.stringify(request.envelope)).not.toContain("1250250000");
    expect(JSON.stringify(request.envelope)).not.toContain("Maya");
  });

  it("rejects token and contributor-kind mismatches before storage", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Scout",
      principalKind: "agent",
      recipientAddress: "0x123",
      tokenPreference: "STRK",
      jurisdictionCode: "US",
      principal,
      now,
    }).record;
    const base = {
      client: { storeEncryptedRecord: vi.fn() } as never,
      organizationId,
      payee,
      amount: "1",
      token: "STRK" as const,
      classification: "contractor" as const,
      classificationAnswers: referenceClassificationAnswers("contractor"),
      cadence: "monthly" as const,
      nextDueAt: "2026-08-31T00:00:00.000Z",
      policyId: "payo-net-invoice-no-withholding-v1",
      policyVersion: 1,
      principal,
      now,
    };
    await expect(storeEncryptedRecurringAgreement(base)).rejects.toThrow(/classification/i);
    await expect(storeEncryptedRecurringAgreement({
      ...base,
      token: "USDC",
      classification: "agent_service",
      classificationAnswers: referenceClassificationAnswers("agent_service"),
    })).rejects.toThrow(/token preference/i);
  });

  it("advances exactly the confirmed encrypted schedule revision", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Scout",
      principalKind: "agent",
      recipientAddress: "0x123",
      tokenPreference: "STRK",
      jurisdictionCode: "US",
      principal,
      now,
    }).record;
    const firstStore = vi.fn().mockResolvedValue({ record: {} });
    const agreement = await storeEncryptedRecurringAgreement({
      client: { storeEncryptedRecord: firstStore } as never,
      organizationId,
      payee,
      amount: "1",
      token: "STRK",
      classification: "agent_service",
      classificationAnswers: referenceClassificationAnswers("agent_service"),
      cadence: "monthly",
      nextDueAt: "2028-01-31T12:00:00.000Z",
      policyId: "payo-net-invoice-no-withholding-v1",
      policyVersion: 1,
      principal,
      now,
    });
    const expectedScheduleCommitment = agreementScheduleCommitment(agreement.agreement);
    const revisionStore = vi.fn().mockResolvedValue({ record: {} });
    const advanced = await advanceEncryptedRecurringAgreement({
      client: { storeEncryptedRecord: revisionStore } as never,
      record: agreement,
      expectedScheduleCommitment,
      principal,
      now: new Date("2028-02-01T12:00:00.000Z"),
    });
    expect(advanced.revision).toBe(2);
    expect(advanced.agreement.schedule).toMatchObject({ nextDueAt: "2028-02-29T12:00:00.000Z" });
    expect(advanced.agreementCommitment).not.toBe(agreement.agreementCommitment);
    const request = revisionStore.mock.calls[0][0];
    expect(request.revision).toBe(2);
    expect(decryptVaultRecord(request.envelope, principal)).toEqual(advanced);
    await expect(advanceEncryptedRecurringAgreement({
      client: { storeEncryptedRecord: vi.fn() } as never,
      record: advanced,
      expectedScheduleCommitment,
      principal,
    })).rejects.toThrow(/current schedule revision/i);
  });

  it("locks in-flight schedules and advances each confirmed schedule exactly once", async () => {
    const principal = generateVaultPrincipal("admin:test");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      now,
    }).record;
    const agreement = await storeEncryptedRecurringAgreement({
      client: { storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }) } as never,
      organizationId,
      payee,
      amount: "10",
      token: "USDC",
      classification: "contractor",
      classificationAnswers: referenceClassificationAnswers("contractor"),
      cadence: "weekly",
      nextDueAt: "2026-08-24T12:00:00.000Z",
      policyId: "payo-net-invoice-no-withholding-v1",
      policyVersion: 1,
      principal,
      now,
    });
    const scheduleCommitment = agreementScheduleCommitment(agreement.agreement);
    const submitted = [{
      state: "submitted",
      updatedAt: "2026-08-24T12:05:00.000Z",
      lines: [{ agreementId: agreement.agreement.id, scheduleCommitment }],
    }];
    expect(lockedPayrollScheduleCommitments(submitted)).toContain(
      `${agreement.agreement.id}:${scheduleCommitment}`,
    );
    expect(lockedPayrollScheduleCommitments([{ ...submitted[0], state: "failed" }])).toHaveLength(0);
    expect(lockedPayrollScheduleCommitments([{
      ...submitted[0],
      state: "proven",
      obligationSnapshotPlanId: generateUuidV7(),
    }]))
      .not.toContain(`${agreement.agreement.id}:${scheduleCommitment}`);
    expect(lockedPayrollScheduleCommitments([{ ...submitted[0], state: "proven" }])).toHaveLength(1);

    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const [advanced] = await synchronizeConfirmedRecurringAgreements({
      client: { storeEncryptedRecord } as never,
      agreements: [agreement],
      runs: [{ ...submitted[0], state: "confirmed" }],
      principal,
    });
    expect(advanced.agreement.schedule).toMatchObject({ nextDueAt: "2026-08-31T12:00:00.000Z" });
    expect(storeEncryptedRecord).toHaveBeenCalledTimes(1);
    await synchronizeConfirmedRecurringAgreements({
      client: { storeEncryptedRecord } as never,
      agreements: [advanced],
      runs: [{ ...submitted[0], state: "confirmed" }],
      principal,
    });
    expect(storeEncryptedRecord).toHaveBeenCalledTimes(1);
  });

  it("encrypts a checkpoint-stream agreement with its exact proof schedule projection", async () => {
    const principal = generateVaultPrincipal("admin:advanced");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US-CA",
      principal,
      now,
    }).record;
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const record = await storeEncryptedAdvancedAgreement({
      client: { storeEncryptedRecord } as never,
      organizationId,
      payee,
      token: "USDC",
      classification: "contractor",
      classificationAnswers: referenceClassificationAnswers("contractor"),
      paymentPlan: {
        planVersion: "payo-payment-plan-v1",
        kind: "checkpoint_stream",
        startsAt: "2026-08-24T10:00:00.000Z",
        endsAt: "2026-08-24T14:00:00.000Z",
        totalAtomic: "1000000",
        settledAtomic: "0",
        minimumCheckpointSeconds: 900,
        checkpoint: {
          sequence: 1,
          checkpointAt: "2026-08-24T12:00:00.000Z",
          cumulativeEntitlementAtomic: "500000",
          attestationCommitment: `0x${"11".repeat(32)}`,
        },
      },
      principal,
      now,
    });
    expect(record.agreement).toMatchObject({
      agreementVersion: "payo-agreement-v2",
      schedule: { kind: "stream", totalAtomic: "1000000", claimedAtomic: "0" },
      paymentPlan: { kind: "checkpoint_stream" },
    });
    const request = storeEncryptedRecord.mock.calls[0][0];
    expect(JSON.stringify(request.envelope)).not.toContain("500000");
    expect(decryptVaultRecord(request.envelope, principal)).toEqual(record);
  });

  it("rejects incomplete final-pay components before encrypted storage", async () => {
    const principal = generateVaultPrincipal("admin:termination");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US-CA",
      principal,
      now,
    }).record;
    await expect(storeEncryptedAdvancedAgreement({
      client: { storeEncryptedRecord: vi.fn() } as never,
      organizationId,
      payee,
      token: "USDC",
      classification: "contractor",
      classificationAnswers: referenceClassificationAnswers("contractor"),
      paymentPlan: {
        planVersion: "payo-payment-plan-v1",
        kind: "milestone",
        dueAt: now.toISOString(),
        milestoneCommitment: `0x${"12".repeat(32)}`,
        approverCommitment: `0x${"13".repeat(32)}`,
        attestationCommitment: `0x${"14".repeat(32)}`,
        approvedAt: now.toISOString(),
      },
      termination: {
        terminatedAt: now.toISOString(),
        reasonCommitment: `0x${"15".repeat(32)}`,
        pay: {
          ordinaryPayAtomic: "100",
          accruedLeaveAtomic: "20",
          noticeAtomic: "0",
          severanceAtomic: "0",
          adjustmentsAtomic: "0",
          deductionsAtomic: "0",
          requiredComponents: { accruedLeave: true, notice: true, severance: false },
          includedComponents: { accruedLeave: true, notice: false, severance: false },
        },
      },
      principal,
      now,
    })).rejects.toThrow(/Required final-pay component is missing|included/i);
  });

  it("encrypts an approved adjustment as the exact proof-paid earnings component", async () => {
    const principal = generateVaultPrincipal("admin:adjustment");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US-CA",
      principal,
      now,
    }).record;
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const record = await storeEncryptedAdvancedAgreement({
      client: { storeEncryptedRecord } as never,
      organizationId,
      payee,
      token: "USDC",
      classification: "contractor",
      classificationAnswers: referenceClassificationAnswers("contractor"),
      paymentPlan: {
        planVersion: "payo-payment-plan-v1",
        kind: "milestone",
        dueAt: now.toISOString(),
        milestoneCommitment: `0x${"21".repeat(32)}`,
        approverCommitment: `0x${"22".repeat(32)}`,
        attestationCommitment: `0x${"23".repeat(32)}`,
        approvedAt: now.toISOString(),
      },
      fixedAmount: "25.5",
      adjustment: {
        amount: "25.5",
        reasonCommitment: `0x${"24".repeat(32)}`,
        approverCommitment: `0x${"22".repeat(32)}`,
      },
      principal,
      now,
    });
    expect(record.agreement.earningsAtomic).toEqual(["25500000"]);
    expect(record.agreement).toMatchObject({
      agreementVersion: "payo-agreement-v2",
      adjustment: { amountAtomic: "25500000" },
    });
    const request = storeEncryptedRecord.mock.calls[0][0];
    expect(JSON.stringify(request.envelope)).not.toContain("25500000");
    expect(decryptVaultRecord(request.envelope, principal)).toEqual(record);
  });

  it("binds an advanced US employee obligation to the executable statutory policy", async () => {
    const principal = generateVaultPrincipal("admin:advanced-employee");
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US-CA",
      principal,
      now,
    }).record;
    const record = await storeEncryptedAdvancedAgreement({
      client: { storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }) } as never,
      organizationId,
      payee,
      token: "USDC",
      classification: "employee",
      classificationAnswers: referenceClassificationAnswers("employee"),
      policyId: "us-irs-supplemental-flat-2026-v1",
      policyVersion: 1,
      paymentPlan: {
        planVersion: "payo-payment-plan-v1",
        kind: "recurring",
        cadence: "monthly",
        anchorAt: now.toISOString(),
        nextDueAt: now.toISOString(),
        occurrence: 0,
      },
      fixedAmount: "10",
      principal,
      now,
    });
    expect(record.agreement).toMatchObject({
      agreementVersion: "payo-agreement-v2",
      classification: "employee",
      statutoryPolicy: { policyId: "us-irs-supplemental-flat-2026-v1", policyVersion: 1 },
    });
  });
});
