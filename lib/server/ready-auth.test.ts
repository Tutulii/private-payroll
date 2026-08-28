import { describe, expect, it, vi } from "vitest";
import { verifyReadySignatureWithProviders } from "./ready-auth";

const verificationInput = {
  typedData: {} as Parameters<typeof verifyReadySignatureWithProviders>[0]["typedData"],
  signature: ["0x1", "0x2"],
  walletAddress: "0x1",
};

function provider(result: boolean | Error) {
  return {
    verifyMessageInStarknet: vi.fn(async () => {
      if (result instanceof Error) throw result;
      return result;
    }),
  };
}

describe("Ready signature RPC fallback", () => {
  it("falls back when the primary RPC is unavailable", async () => {
    const primary = provider(new Error("primary unavailable"));
    const fallback = provider(true);

    await expect(verifyReadySignatureWithProviders(
      verificationInput,
      [primary, fallback],
    )).resolves.toBe(true);
    expect(primary.verifyMessageInStarknet).toHaveBeenCalledOnce();
    expect(fallback.verifyMessageInStarknet).toHaveBeenCalledOnce();
  });

  it("fails closed without retrying a definitively invalid signature", async () => {
    const primary = provider(false);
    const fallback = provider(true);

    await expect(verifyReadySignatureWithProviders(
      verificationInput,
      [primary, fallback],
    )).resolves.toBe(false);
    expect(fallback.verifyMessageInStarknet).not.toHaveBeenCalled();
  });

  it("surfaces an outage when every RPC provider fails", async () => {
    await expect(verifyReadySignatureWithProviders(
      verificationInput,
      [provider(new Error("primary unavailable")), provider(new Error("fallback unavailable"))],
    )).rejects.toThrow("fallback unavailable");
  });
});
