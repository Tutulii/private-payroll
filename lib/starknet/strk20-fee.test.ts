import { describe, expect, it } from "vitest";
import { hash } from "starknet";
import {
  convertStrkPoolFeeToToken,
  decodeStrk20WalletFeeQuote,
  PAYMASTER_NON_STRK_QUOTE_BUFFER_BPS,
  PAYMASTER_PRICE_SCALE,
} from "./strk20-fee";

const USDC = "0x33068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb";

function simulatedCall(overrides: Partial<{ entrypoint: string; calldata: string[] }> = {}) {
  return {
    contract_address: "0x1270",
    entry_point: overrides.entrypoint ?? "execute_private_sponsored",
    calldata: overrides.calldata ?? [
      "0x2",
      "0x38c", "0x111", "0x2", "0xaa", "0xbb",
      "0x403", "0x222", "0x1", "0xcc",
      USDC, "0x31184", "0x0",
      "0x1", "0x1234",
    ],
  };
}

describe("decodeStrk20WalletFeeQuote", () => {
  it("extracts the exact native-USDC reserve from a sponsored wallet preview", () => {
    expect(decodeStrk20WalletFeeQuote(simulatedCall())).toEqual({
      tokenAddress: USDC,
      amount: 201_092n,
      source: "wallet-simulation",
    });
  });

  it("accepts the selector form and a non-sponsored forwarder call", () => {
    const result = decodeStrk20WalletFeeQuote(simulatedCall({
      entrypoint: hash.getSelectorFromName("execute_private"),
      calldata: ["0x0", USDC, "0x5", "0x1"],
    }));
    expect(result.amount).toBe((1n << 128n) + 5n);
  });

  it("fails closed for unknown call shapes", () => {
    expect(() => decodeStrk20WalletFeeQuote(simulatedCall({ entrypoint: "transfer" })))
      .toThrow(/cannot quote this fee safely/);
    expect(() => decodeStrk20WalletFeeQuote(simulatedCall({
      calldata: ["0x1", "0x38c", "0x111", "0x4", "0xaa"],
    }))).toThrow(/truncated/);
  });

  it("rejects zero fees and malformed sponsor metadata", () => {
    expect(() => decodeStrk20WalletFeeQuote(simulatedCall({
      calldata: ["0x0", USDC, "0x0", "0x0", "0x0"],
    }))).toThrow(/zero fee reserve/);
    expect(() => decodeStrk20WalletFeeQuote(simulatedCall({
      calldata: ["0x0", USDC, "0x1", "0x0", "0x2", "0x1234"],
    }))).toThrow(/metadata boundary/);
  });
});

describe("convertStrkPoolFeeToToken", () => {
  const poolFee = 6n * 10n ** 18n;

  it("preserves the exact atomic fee when STRK is the fee token", () => {
    expect(convertStrkPoolFeeToToken({
      poolFeeStrkAtomic: poolFee,
      tokenDecimals: 18,
      tokenPriceInStrk: PAYMASTER_PRICE_SCALE,
    })).toBe(poolFee);
  });

  it("rounds a buffered native-USDC reserve upward", () => {
    const priceInStrk = 36_142_090_427_137_511_424n;
    const quote = convertStrkPoolFeeToToken({
      poolFeeStrkAtomic: poolFee,
      tokenDecimals: 6,
      tokenPriceInStrk: priceInStrk,
      bufferBps: PAYMASTER_NON_STRK_QUOTE_BUFFER_BPS,
    });
    expect(quote).toBe(199_214n);
    expect(quote).toBeGreaterThan(
      convertStrkPoolFeeToToken({
        poolFeeStrkAtomic: poolFee,
        tokenDecimals: 6,
        tokenPriceInStrk: priceInStrk,
      }),
    );
  });

  it("rejects invalid external price data", () => {
    expect(() => convertStrkPoolFeeToToken({
      poolFeeStrkAtomic: poolFee,
      tokenDecimals: 6,
      tokenPriceInStrk: 0n,
    })).toThrow(/invalid token price/);
  });
});
