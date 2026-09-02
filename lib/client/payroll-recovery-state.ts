import type { PayrollExecutionStage } from "./payroll-execution";

export type PayrollRecoveryMode =
  | "hidden"
  | "approval_in_progress"
  | "action_required"
  | "recording_required";

type WalletTransactionStage = "wallet" | "confirming" | "confirmed" | "failed" | null;

const STARKNET_TRANSACTION_HASH = /^0x[0-9a-fA-F]{1,64}$/;

/**
 * Returns the canonical hash that can safely resume browser-side settlement
 * recording. PAYO waits until its finalized-chain indexer has independently
 * observed the transaction, so a stale local recovery record can never make
 * the browser attach an unrelated Ready transaction to a payroll.
 */
export function payrollSubmissionRecoveryHash(input: {
  pendingTransactionHash?: string | null;
  indexedTransactionHash?: string | null;
}): string | null {
  const indexed = input.indexedTransactionHash?.trim();
  if (!indexed) return null;
  if (!STARKNET_TRANSACTION_HASH.test(indexed)) {
    throw new Error("PAYO returned an invalid indexed payroll transaction hash.");
  }

  const pending = input.pendingTransactionHash?.trim();
  if (!pending) return indexed;
  if (!STARKNET_TRANSACTION_HASH.test(pending)) {
    throw new Error("The local payroll recovery record contains an invalid transaction hash.");
  }
  if (BigInt(pending) !== BigInt(indexed)) {
    throw new Error("The Ready transaction does not match PAYO's finalized payroll event.");
  }
  return indexed;
}

/**
 * Keeps emergency settlement recovery separate from the normal Ready prompt.
 * The recovery payload is deliberately persisted before Ready opens, but that
 * durability detail must not be presented as a failure while approval is live.
 */
export function payrollRecoveryMode(input: {
  hasPendingSubmission: boolean;
  hasTransactionHash: boolean;
  executionStage: PayrollExecutionStage | null;
  walletStage: WalletTransactionStage;
}): PayrollRecoveryMode {
  if (!input.hasPendingSubmission) return "hidden";
  if (input.hasTransactionHash) return "recording_required";

  if (
    (input.executionStage === "recording"
      || input.executionStage === "wallet"
      || input.executionStage === "wallet_recovery")
    && (input.walletStage === null
      || input.walletStage === "wallet"
      || input.walletStage === "confirming")
  ) return "approval_in_progress";

  return "action_required";
}
