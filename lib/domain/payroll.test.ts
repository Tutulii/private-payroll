import { describe, expect, it } from "vitest";
import {
  assertPayrollTransition,
  calculatePayrollLine,
  calculatePayrollManifest,
  type PrivatePayrollLine,
} from "./payroll";

const line = (overrides: Partial<PrivatePayrollLine> = {}): PrivatePayrollLine => ({
  agreementId: "agreement-0001",
  recipientAddress: "0x123",
  token: "USDC",
  earningsAtomic: ["1000000", "250000"],
  deductionsAtomic: ["100000"],
  committedPolicyId: "us-reference-2026",
  scheduleCommitment: `0x${"11".repeat(32)}`,
  salt: `0x${"22".repeat(32)}`,
  ...overrides,
});

describe("payroll domain", () => {
  it("calculates using atomic integers only", () => {
    expect(calculatePayrollLine(line())).toMatchObject({
      grossAtomic: "1250000",
      deductionsTotalAtomic: "100000",
      netAtomic: "1150000",
    });
  });

  it("rejects deductions above gross", () => {
    expect(() => calculatePayrollLine(line({ deductionsAtomic: ["1300000"] }))).toThrow(
      "Deductions cannot exceed gross pay",
    );
  });

  it("rejects duplicate obligations", () => {
    expect(() => calculatePayrollManifest([line(), line()])).toThrow("Duplicate agreement");
  });

  it("enforces explicit workflow transitions", () => {
    expect(() => assertPayrollTransition("calculated", "confirmed")).toThrow("Invalid payroll transition");
    expect(() => assertPayrollTransition("calculated", "proven")).not.toThrow();
  });
});
