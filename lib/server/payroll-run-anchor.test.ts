import { describe, expect, it, vi } from "vitest";
import {
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
});
