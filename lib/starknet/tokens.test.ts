import { describe, expect, it } from "vitest";
import {
  STRK_TOKEN_ADDRESS,
  USDC_TOKEN_ADDRESS,
  tokenByAddress,
} from "./tokens";

describe("tokenByAddress", () => {
  it("normalizes canonical, shortened hexadecimal, and decimal addresses", () => {
    expect(tokenByAddress(STRK_TOKEN_ADDRESS)?.symbol).toBe("STRK");
    expect(tokenByAddress(
      "0x" + BigInt(USDC_TOKEN_ADDRESS).toString(16),
    )?.symbol).toBe("USDC");
    expect(tokenByAddress(
      BigInt(STRK_TOKEN_ADDRESS).toString(10),
    )?.symbol).toBe("STRK");
  });

  it("rejects malformed and unsupported token addresses", () => {
    expect(tokenByAddress("not-an-address")).toBeUndefined();
    expect(tokenByAddress("0x1")).toBeUndefined();
  });
});
