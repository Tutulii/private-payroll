import { describe, expect, it } from "vitest";
import { num, type STRK20_INVOKE_ACTION } from "starknet";
import { PAYROLL_TOKENS } from "./tokens";
import {
  buildPrivatePayrollActions,
  requiredPayrollReserves,
  requiredPayrollReservesForQuotes,
} from "./private-payroll";

const SEAL = "0x1234";
const PAYO_ACTION: STRK20_INVOKE_ACTION = {
  type: "invoke",
  contract: SEAL,
  calldata: ["0x1", "0x2"],
};

describe("buildPrivatePayrollActions", () => {
  it("builds a mixed batch with exact token decimals and the seal last", () => {
    const result = buildPrivatePayrollActions([
      { address: "0x111", token: "STRK", amount: "1.25" },
      { address: "0x111", token: "USDC", amount: "2.123456" },
    ], PAYO_ACTION, SEAL);
    expect(result.totals).toEqual({ STRK: 1_250_000_000_000_000_000n, USDC: 2_123_456n });
    expect(result.actions).toHaveLength(3);
    expect(result.actions[0]).toMatchObject({
      type: "transfer",
      token: PAYROLL_TOKENS.STRK.address,
      amount: num.toHex(1_250_000_000_000_000_000n),
    });
    expect(result.actions.at(-1)).toBe(PAYO_ACTION);
  });

  it("rejects duplicate canonical address/token pairs but permits two tokens", () => {
    expect(() => buildPrivatePayrollActions([
      { address: "0x0111", token: "STRK", amount: "1" },
      { address: "0x111", token: "STRK", amount: "1" },
    ], PAYO_ACTION, SEAL)).toThrow(/duplicates/);
    expect(() => buildPrivatePayrollActions([
      { address: "0x0111", token: "STRK", amount: "1" },
      { address: "0x111", token: "USDC", amount: "1" },
    ], PAYO_ACTION, SEAL)).not.toThrow();
  });

  it("rejects bad amounts, addresses, batch sizes, and foreign seal actions", () => {
    expect(() => buildPrivatePayrollActions([
      { address: "not-an-address", token: "STRK", amount: "1" },
    ], PAYO_ACTION, SEAL)).toThrow(/invalid Starknet address/);
    expect(() => buildPrivatePayrollActions([
      { address: "0x111", token: "USDC", amount: "1.0000001" },
    ], PAYO_ACTION, SEAL)).toThrow(/no more than 6 decimals/);
    expect(() => buildPrivatePayrollActions([], PAYO_ACTION, SEAL)).toThrow(/at least one/);
    expect(() => buildPrivatePayrollActions(
      Array.from({ length: 51 }, (_, index) => ({ address: num.toHex(index + 1), token: "STRK" as const, amount: "1" })),
      PAYO_ACTION,
      SEAL,
    )).toThrow(/up to 50/);
    expect(() => buildPrivatePayrollActions(
      [{ address: "0x111", token: "STRK", amount: "1" }],
      { ...PAYO_ACTION, contract: "0x9999" },
      SEAL,
    )).toThrow(/unapproved PAYO seal/);
  });
});

describe("requiredPayrollReserves", () => {
  it("keeps STRK and USDC reserves separate", () => {
    const totals = { STRK: 100n, USDC: 200n };
    expect(requiredPayrollReserves(totals, "STRK", 6n)).toEqual({ STRK: 106n, USDC: 200n });
    expect(requiredPayrollReserves(totals, "USDC", 3n)).toEqual({ STRK: 100n, USDC: 203n });
  });

  it("reserves passive fees for both legs of a mixed-token payroll", () => {
    expect(requiredPayrollReservesForQuotes(
      { STRK: 100n, USDC: 200n },
      { STRK: 6n, USDC: 3n },
    )).toEqual({ STRK: 106n, USDC: 203n });
  });

  it("fails closed when an active token has no quote", () => {
    expect(() => requiredPayrollReservesForQuotes(
      { STRK: 100n, USDC: 0n },
      { STRK: 0n, USDC: 0n },
    )).toThrow(/missing a private fee reserve/);
  });
});
