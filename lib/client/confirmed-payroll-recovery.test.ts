import { describe, expect, it, vi } from "vitest";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import type { PayoClient } from "./payo-client";
import type { PendingPayrollSubmission } from "./payroll-execution";
import { recoverConfirmedPayrollFromBrowser } from "./confirmed-payroll-recovery";

const organizationId = "0198ddf0-9c00-7000-8000-000000000001";
const runId = "0198ddf0-9c00-7000-8000-000000000002";
const proofBundleId = "0198ddf0-9c00-7000-8000-000000000003";
const settlementId = "0198ddf0-9c00-7000-8000-000000000004";
const walletRequestId = "0198ddf0-9c00-7000-8000-000000000005";
const principal = generateVaultPrincipal("ready:owner");

function pending(): PendingPayrollSubmission {
  return {
    version: 3,
    organizationId,
    runId,
    proofBundleId,
    settlementId,
    walletRequestId,
    idempotencyKey: `payroll:${runId}:${walletRequestId}`,
    tokenTotalsCommitment: `0x${"11".repeat(32)}`,
    settlementEnvelope: encryptVaultRecord(
      { state: "approval_pending" },
      {
        schemaVersion: 1,
        organizationId,
        recordType: "settlement",
        recordId: settlementId,
        revision: 1,
      },
      [principal],
    ),
    proofShards: [["0x1", "0x2"], ["0x3", "0x4"]],
    createdAt: "2026-08-27T12:00:00.000Z",
  };
}

describe("confirmed payroll browser recovery", () => {
  it("uses the durable local approval when Ready submitted but never returned a hash", async () => {
    const client = {
      createSettlementIntent: vi.fn().mockResolvedValue({ settlement: { id: settlementId } }),
      recordSettlementSubmission: vi.fn().mockResolvedValue({ settlement: { id: settlementId } }),
      enqueueProofVerification: vi.fn().mockResolvedValue({ proofVerification: {} }),
      getSealedPayrollRecovery: vi.fn(),
      getEncryptedRecord: vi.fn(),
    };
    const persist = vi.fn();

    await expect(recoverConfirmedPayrollFromBrowser({
      client: client as unknown as PayoClient,
      organizationId,
      runId,
      indexedTransactionHash: "0xfeed",
      principal,
      pendingSubmission: pending(),
      persistPendingSubmission: persist,
    })).resolves.toMatchObject({
      runId,
      settlementId,
      transactionHash: "0xfeed",
      verificationQueued: true,
    });

    expect(client.recordSettlementSubmission).toHaveBeenCalledWith(settlementId, "0xfeed");
    expect(client.enqueueProofVerification).toHaveBeenCalledWith({
      settlementId,
      proofBundleId,
      shards: [["0x1", "0x2"], ["0x3", "0x4"]],
    });
    expect(client.getSealedPayrollRecovery).not.toHaveBeenCalled();
    expect(persist).toHaveBeenLastCalledWith(null);
  });

  it("fails closed when local and indexed transaction hashes disagree", async () => {
    const local = { ...pending(), transactionHash: "0xabc" };
    await expect(recoverConfirmedPayrollFromBrowser({
      client: {} as PayoClient,
      organizationId,
      runId,
      indexedTransactionHash: "0xdef",
      principal,
      pendingSubmission: local,
      persistPendingSubmission: vi.fn(),
    })).rejects.toThrow("does not match");
  });
});
