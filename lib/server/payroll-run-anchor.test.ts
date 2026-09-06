import { describe, expect, it, vi } from "vitest";
import {
  assertInvokedPayrollBookFxAnchor,
  assertInvokedPayrollFxAnchor,
  readPayrollRunAnchor,
} from "./payroll-run-anchor";

const sealAddress = "0x12345";
const blockNumber = 321;
const fxRoot = `0x${"ab".repeat(32)}`;
const fx = BigInt(fxRoot);
const fxHigh = (fx >> 128n).toString();
const fxLow = (fx & ((1n << 128n) - 1n)).toString();

function anchorFelts(overrides: Partial<Record<number, string>> = {}) {
  const values = [
    "1", "1", "3", "4", "5", "6", "7", "8",
    fxHigh, fxLow, "11", "12", "100", "101",
  ];
  for (const [index, value] of Object.entries(overrides)) {
    if (value !== undefined) values[Number(index)] = value;
  }
  return values;
}

const runNullifier = `0x${"cd".repeat(32)}`;
const run = BigInt(runNullifier);
const runHigh = (run >> 128n).toString();
const runLow = (run & ((1n << 128n) - 1n)).toString();

function bookAnchor(overrides: {
  exists?: boolean;
  status?: number;
  verifiedMask?: number;
  payrollState?: string[];
  transitionState?: string[];
} = {}) {
  const payrollState = Array<string>(14).fill("0");
  payrollState[0] = "2";
  payrollState[1] = "1";
  payrollState[8] = fxHigh;
  payrollState[9] = fxLow;
  payrollState[10] = runHigh;
  payrollState[11] = runLow;
  const transitionState = Array<string>(55).fill("0");
  transitionState[0] = "3";
  transitionState[1] = "1";
  transitionState[2] = "0";
  transitionState[9] = fxHigh;
  transitionState[10] = fxLow;
  transitionState[11] = runHigh;
  transitionState[12] = runLow;
  return { exists: true, status: 3, verifiedMask: 15, payrollState, transitionState, ...overrides };
}

describe("PAYO vNext payroll run anchor", () => {
  it("reads the exact 14-felt anchor at the pinned block and verifies its FX binding", async () => {
    const callContract = vi.fn().mockResolvedValue({ result: anchorFelts() });
    const anchor = await readPayrollRunAnchor({ callContract }, {
      sealAddress,
      runNullifierHigh: "11",
      runNullifierLow: "12",
      blockNumber,
    });

    expect(callContract).toHaveBeenCalledWith({
      contractAddress: sealAddress,
      entrypoint: "get_run_anchor",
      calldata: ["0xb", "0xc"],
    }, blockNumber);
    expect(anchor).toMatchObject({
      exists: true,
      invoked: true,
      fxRootHigh: fxHigh,
      fxRootLow: fxLow,
      blockNumber,
    });
    expect(() => assertInvokedPayrollFxAnchor(anchor, fxRoot)).not.toThrow();
  });

  it.each([
    [{ 0: "0" }, "not finalized"],
    [{ 1: "0" }, "not finalized"],
  ])("rejects an unfinalized payroll anchor", async (overrides, message) => {
    const anchor = await readPayrollRunAnchor({
      callContract: vi.fn().mockResolvedValue(anchorFelts(overrides)),
    }, { sealAddress, runNullifierHigh: "11", runNullifierLow: "12", blockNumber });
    expect(() => assertInvokedPayrollFxAnchor(anchor, fxRoot)).toThrow(message);
  });

  it("rejects an anchor committed to another FX root", async () => {
    const anchor = await readPayrollRunAnchor({
      callContract: vi.fn().mockResolvedValue(anchorFelts()),
    }, { sealAddress, runNullifierHigh: "11", runNullifierLow: "12", blockNumber });
    expect(() => assertInvokedPayrollFxAnchor(anchor, `0x${"cd".repeat(32)}`))
      .toThrow("different FX root");
  });

  it.each([
    [["1"], "expected 14"],
    [anchorFelts({ 1: "2" }), "Cairo boolean"],
    [anchorFelts({ 8: (1n << 128n).toString() }), "outside u128"],
    [anchorFelts({ 12: (1n << 64n).toString() }), "outside u64"],
  ])("fails closed for malformed anchor responses", async (response, message) => {
    await expect(readPayrollRunAnchor({
      callContract: vi.fn().mockResolvedValue(response),
    }, { sealAddress, runNullifierHigh: "11", runNullifierLow: "12", blockNumber }))
      .rejects.toThrow(message);
  });

  it("accepts a fully verified invoked universal payroll-book authorization", () => {
    expect(() => assertInvokedPayrollBookFxAnchor(bookAnchor(), fxRoot, runNullifier))
      .not.toThrow();
  });

  it("fails closed when universal payroll-book evidence is incomplete or mismatched", () => {
    const reject = (
      anchor: ReturnType<typeof bookAnchor>,
      message: string,
      root = fxRoot,
      nullifier = runNullifier,
    ) => expect(() => assertInvokedPayrollBookFxAnchor(anchor, root, nullifier)).toThrow(message);

    reject(bookAnchor({ exists: false }), "not invoked");
    reject(bookAnchor({ status: 2 }), "not invoked");
    reject(bookAnchor({ verifiedMask: 7 }), "missing proof shards");
    reject(bookAnchor({ payrollState: ["2"] }), "malformed state");
    reject(bookAnchor({ transitionState: Array<string>(54).fill("0") }), "malformed state");
    reject(bookAnchor({
      payrollState: bookAnchor().payrollState.map((value, index) => index === 0 ? "invalid" : value),
    }), "not a non-negative integer");
    reject(bookAnchor({
      transitionState: bookAnchor().transitionState.map((value, index) => index === 2 ? "3" : value),
    }), "not a payroll finalization");
    reject(bookAnchor({
      payrollState: bookAnchor().payrollState.map((value, index) => index === 8 ? "0" : value),
    }), "different FX root");
    reject(bookAnchor({
      transitionState: bookAnchor().transitionState.map((value, index) => index === 10 ? "0" : value),
    }), "different FX root");
    reject(bookAnchor({
      payrollState: bookAnchor().payrollState.map((value, index) => index === 10 ? "0" : value),
    }), "different payroll run");
    reject(bookAnchor({
      transitionState: bookAnchor().transitionState.map((value, index) => index === 12 ? "0" : value),
    }), "different payroll run");
    reject(bookAnchor(), "outside bytes32", "not-a-root");
    reject(bookAnchor(), "outside bytes32", fxRoot, "not-a-run");
  });
});
