import { describe, expect, it } from "vitest";
import { num, type STRK20_INVOKE_ACTION } from "starknet";
import { PAYROLL_TOKENS } from "./tokens";
import {
  buildPrivateExceptionActions,
  buildPrivatePayrollActions,
  requiredPayrollReserves,
  requiredPayrollReservesForQuotes,
} from "./private-payroll";

const SEAL = "0x1234";
const BOOK_SEAL = "0x4567";

function remediationBookAction(source: STRK20_INVOKE_ACTION): STRK20_INVOKE_ACTION {
  return {
    type: "invoke",
    contract: BOOK_SEAL,
    calldata: [source.calldata[1]!, source.calldata[2]!, "0x0", "0x0", "0x31", "0x32"],
  };
}
const PAYO_ACTION: STRK20_INVOKE_ACTION = {
  type: "invoke",
  contract: SEAL,
  calldata: Array.from({ length: 19 }, (_, index) => num.toHex(index)),
};

describe("buildPrivatePayrollActions", () => {
  it("builds a mixed batch with exact token decimals and the seal last", () => {
    const result = buildPrivatePayrollActions([
      { address: "0x111", token: "STRK", amount: "1.25" },
      { address: "0x111", token: "USDC", amount: "2.123456" },
    ], PAYO_ACTION, SEAL);
    expect(result.totals).toEqual({ STRK: 1_250_000_000_000_000_000n, USDC: 2_123_456n });
    expect(result.operationalReserves).toEqual({ STRK: 0n, USDC: 0n });
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

  it("anchors claims to the connected wallet and requires one private remediation transfer", () => {
    const claimAction = { ...PAYO_ACTION, calldata: ["0x2", ...PAYO_ACTION.calldata.slice(1)] };
    expect(buildPrivateExceptionActions("wage_claim", [], claimAction, SEAL, "0x111")).toEqual({
      actions: [
        {
          type: "transfer",
          token: PAYROLL_TOKENS.STRK.address,
          amount: "0x1",
          recipient: expect.any(String),
        },
        claimAction,
      ],
      totals: { STRK: 0n, USDC: 0n },
      operationalReserves: { STRK: 1n, USDC: 0n },
    });
    expect(() => buildPrivateExceptionActions(
      "wage_claim",
      [{ address: "0x111", token: "STRK", amount: "1" }],
      claimAction,
      SEAL,
      "0x111",
    )).toThrow(/cannot transfer/i);
    expect(() => buildPrivateExceptionActions("wage_claim", [], claimAction, SEAL))
      .toThrow(/connected Starknet address/i);

    const remediationAction = { ...PAYO_ACTION, calldata: ["0x3", ...PAYO_ACTION.calldata.slice(1)] };
    const bookAction = remediationBookAction(remediationAction);
    const remediation = buildPrivateExceptionActions(
      "wage_remediation",
      [{ address: "0x111", token: "USDC", amount: "2.5" }],
      [remediationAction, bookAction],
      SEAL,
      undefined,
      BOOK_SEAL,
    );
    expect(remediation.totals).toEqual({ STRK: 0n, USDC: 2_500_000n });
    expect(remediation.operationalReserves).toEqual({ STRK: 0n, USDC: 0n });
    expect(remediation.actions.at(-2)).toBe(remediationAction);
    expect(remediation.actions.at(-1)).toBe(bookAction);
    expect(() => buildPrivateExceptionActions(
      "wage_remediation", [], [remediationAction, bookAction], SEAL, undefined, BOOK_SEAL,
    )).toThrow(/exactly one/i);
  });

  it("accepts the vNext seven-field payroll and remediation consumption ABI", () => {
    const payrollAction = {
      ...PAYO_ACTION,
      calldata: ["0x0", "0x11", "0x12", "0x13", "0x14", "0x15", "0x16"],
    };
    expect(buildPrivatePayrollActions(
      [{ address: "0x111", token: "STRK", amount: "1" }],
      payrollAction,
      SEAL,
    ).actions.at(-1)).toBe(payrollAction);

    const remediationAction = {
      ...PAYO_ACTION,
      calldata: ["0x3", "0x21", "0x22", "0x23", "0x24", "0x25", "0x26"],
    };
    const bookAction = remediationBookAction(remediationAction);
    const actions = buildPrivateExceptionActions(
      "wage_remediation",
      [{ address: "0x111", token: "USDC", amount: "2.5" }],
      [remediationAction, bookAction],
      SEAL,
      undefined,
      BOOK_SEAL,
    ).actions;
    expect(actions.at(-2)).toBe(remediationAction);
    expect(actions.at(-1)).toBe(bookAction);
  });

  it("rejects a proof action whose mode or ABI does not match its workflow", () => {
    expect(() => buildPrivatePayrollActions(
      [{ address: "0x111", token: "STRK", amount: "1" }],
      { ...PAYO_ACTION, calldata: ["0x2", ...PAYO_ACTION.calldata.slice(1)] },
      SEAL,
    )).toThrow(/proof mode 0/i);
    expect(() => buildPrivateExceptionActions("wage_claim", [], PAYO_ACTION, SEAL))
      .toThrow(/proof mode 2/i);
    expect(() => buildPrivateExceptionActions(
      "wage_claim",
      [],
      { ...PAYO_ACTION, calldata: ["0x2", "0x1", "0x2", "0x3", "0x4", "0x5", "0x6"] },
      SEAL,
      "0x111",
    )).toThrow(/ABI/i);
    expect(() => buildPrivateExceptionActions(
      "wage_remediation",
      [{ address: "0x111", token: "USDC", amount: "1" }],
      { ...PAYO_ACTION, calldata: ["0x3", "bad", "0x2", "0x3", "0x4", "0x5", "0x6"] },
      SEAL,
    )).toThrow(/canonical/i);
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
