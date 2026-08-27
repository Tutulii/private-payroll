import type { VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import type { PayoClient } from "./payo-client";
import {
  recoverConfirmedPayrollVerification,
  resumePendingPayrollSubmission,
  type PendingPayrollSubmission,
} from "./payroll-execution";
import { payrollSubmissionRecoveryHash } from "./payroll-recovery-state";

export type ConfirmedPayrollRecoveryResult = {
  runId: string;
  settlementId: string;
  proofBundleId: string;
  transactionHash: string;
  verificationQueued: boolean;
  proofDeliveryWarning?: string;
};

/**
 * Repairs the browser half of a Ready transaction whose Wallet API promise
 * never resolved. The locally persisted approval is preferred because it
 * already contains the encrypted run's proof calldata and idempotency keys.
 * The encrypted-vault path remains as a fallback after a browser restart.
 */
export async function recoverConfirmedPayrollFromBrowser(input: {
  client: PayoClient;
  organizationId: string;
  runId: string;
  indexedTransactionHash: string;
  principal: VaultPrincipalKeyPair;
  pendingSubmission: PendingPayrollSubmission | null;
  persistPendingSubmission: (submission: PendingPayrollSubmission | null) => void;
}): Promise<ConfirmedPayrollRecoveryResult> {
  const pending = input.pendingSubmission;
  if (pending?.runId === input.runId) {
    if (pending.organizationId !== input.organizationId) {
      throw new Error("The local payroll recovery record belongs to another organization.");
    }
    const transactionHash = payrollSubmissionRecoveryHash({
      pendingTransactionHash: pending.transactionHash,
      indexedTransactionHash: input.indexedTransactionHash,
    });
    if (!transactionHash) throw new Error("The confirmed payroll is missing its indexed transaction hash.");
    return resumePendingPayrollSubmission({
      client: input.client,
      pending,
      transactionHash,
      persistPendingSubmission: input.persistPendingSubmission,
    });
  }

  return recoverConfirmedPayrollVerification({
    client: input.client,
    organizationId: input.organizationId,
    runId: input.runId,
    principal: input.principal,
  });
}
