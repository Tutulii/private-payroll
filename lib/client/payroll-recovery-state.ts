import type { PayrollExecutionStage } from "./payroll-execution";

export type PayrollRecoveryMode =
  | "hidden"
  | "approval_in_progress"
  | "action_required"
  | "recording_required";

type WalletTransactionStage = "wallet" | "confirming" | "confirmed" | "failed" | null;

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
    (input.executionStage === "recording" || input.executionStage === "wallet")
    && (input.walletStage === null
      || input.walletStage === "wallet"
      || input.walletStage === "confirming")
  ) return "approval_in_progress";

  return "action_required";
}
