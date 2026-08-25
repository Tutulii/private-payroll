import { describe, expect, it } from "vitest";
import { describeWalletError } from "./wallet-error";

describe("describeWalletError", () => {
  it("keeps nested Ready Wallet API diagnostics", () => {
    expect(describeWalletError({
      code: "UNKNOWN_ERROR",
      message: "An error occurred",
      data: {
        origin: "paymaster",
        error: { code: 41, message: "execution reverted" },
      },
    })).toBe(
      "An error occurred (UNKNOWN_ERROR): {origin: paymaster, error: {code: 41, message: execution reverted}}",
    );
  });

  it("uses a nested error when the outer object has no diagnostic", () => {
    expect(describeWalletError({
      error: { code: 118, message: "An error occurred", data: "NOT_REGISTERED" },
    })).toBe("An error occurred (118): NOT_REGISTERED");
  });

  it("handles causes, bigint values, and circular objects without throwing", () => {
    const detail: Record<string, unknown> = { fee: 5n };
    detail.self = detail;
    const error = new Error("Ready failed", { cause: detail }) as Error & { code: string };
    error.code = "UNKNOWN_ERROR";
    expect(describeWalletError(error)).toContain(
      "Ready failed (UNKNOWN_ERROR): {fee: 5, self: [circular]}",
    );
  });

  it("does not include Error stacks", () => {
    const nested = new Error("private invoke rejected");
    const message = describeWalletError({ message: "An error occurred", data: nested });
    expect(message).toBe("An error occurred: private invoke rejected");
    expect(message).not.toContain("wallet-error.test.ts");
  });
});
