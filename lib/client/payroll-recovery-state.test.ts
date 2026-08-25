import { describe, expect, it } from "vitest";
import { payrollRecoveryMode } from "./payroll-recovery-state";

describe("payrollRecoveryMode", () => {
  it("does not expose emergency controls without a recovery payload", () => {
    expect(payrollRecoveryMode({
      hasPendingSubmission: false,
      hasTransactionHash: false,
      executionStage: null,
      walletStage: null,
    })).toBe("hidden");
  });

  it.each([
    ["recording", null],
    ["wallet", "wallet"],
    ["wallet", "confirming"],
  ] as const)("keeps recovery controls hidden during %s/%s", (executionStage, walletStage) => {
    expect(payrollRecoveryMode({
      hasPendingSubmission: true,
      hasTransactionHash: false,
      executionStage,
      walletStage,
    })).toBe("approval_in_progress");
  });

  it("requires attention after Ready fails without returning a hash", () => {
    expect(payrollRecoveryMode({
      hasPendingSubmission: true,
      hasTransactionHash: false,
      executionStage: null,
      walletStage: "failed",
    })).toBe("action_required");
  });

  it("requires attention after a page reload with an unresolved approval", () => {
    expect(payrollRecoveryMode({
      hasPendingSubmission: true,
      hasTransactionHash: false,
      executionStage: null,
      walletStage: null,
    })).toBe("action_required");
  });

  it("offers idempotent recording when a submitted hash is already durable locally", () => {
    expect(payrollRecoveryMode({
      hasPendingSubmission: true,
      hasTransactionHash: true,
      executionStage: null,
      walletStage: "failed",
    })).toBe("recording_required");
  });
});
