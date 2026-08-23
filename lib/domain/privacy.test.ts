import { describe, expect, it } from "vitest";
import { PAYO_DATA_CLASSIFICATION, assertOperationalMetadataSafe } from "./privacy";

describe("privacy classification", () => {
  it("classifies keys and recovery material as never-store data", () => {
    expect(PAYO_DATA_CLASSIFICATION.walletPrivateKey).toBe("never_store");
    expect(PAYO_DATA_CLASSIFICATION.recoveryPhrase).toBe("never_store");
    expect(PAYO_DATA_CLASSIFICATION.salary).toBe("encrypted");
    expect("manifestRoot" in PAYO_DATA_CLASSIFICATION).toBe(false);
    expect(PAYO_DATA_CLASSIFICATION.commitmentRoots).toBe("public");
  });

  it("accepts redacted workflow metadata", () => {
    expect(() => assertOperationalMetadataSafe({
      revision: 2,
      from: "submitted",
      to: "confirmed",
      receipt: { finality: "ACCEPTED_ON_L2" },
    })).not.toThrow();
  });

  it.each([
    { salary: "100000" },
    { nested: { recipientAddress: "0x123" } },
    { deductions: ["100"] },
    { wallet_private_key: "secret" },
  ])("rejects sensitive metadata: %o", (metadata) => {
    expect(() => assertOperationalMetadataSafe(metadata)).toThrow("Sensitive field");
  });
});
