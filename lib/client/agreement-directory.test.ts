import { describe, expect, it, vi } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { prepareEncryptedPayee } from "./payee-directory";
import {
  advanceEncryptedRecurringAgreement,
  agreementScheduleCommitment,
  lockedPayrollScheduleCommitments,
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
});
