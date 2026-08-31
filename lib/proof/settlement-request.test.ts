import { describe, expect, it } from "vitest";
import { settlementMatchWitnessSchema } from "./settlement-request";

function witness() {
  return {
    version: "payo-settlement-match-witness-v1",
    executionId: "execution-0001",
    chainId: "0x1",
    policyAccountAddress: "0x2",
    poolAddress: "0x3",
    poolCalldata: ["0x1", "0x2"],
    viewingKey: "0x4",
    payrollNotes: [{
      position: 0,
      recipientAddress: "0x5",
      recipientPublicKey: "0x6",
      tokenAddress: "0x7",
      amountAtomic: "10",
      noteIndex: 1,
      salt: "11",
      noteId: "0x" + "11".repeat(32),
      packedValue: "0x" + "22".repeat(32),
    }],
    emittedNotes: [{
      noteId: "0x" + "11".repeat(32),
      packedValue: "0x" + "22".repeat(32),
    }],
  };
}

describe("SettlementMatch encrypted request", () => {
  it("accepts one manifest-ordered note and its exact output", () => {
    expect(settlementMatchWitnessSchema.parse(witness()).payrollNotes).toHaveLength(1);
  });

  it("rejects output substitution, reordering and unbounded calldata", () => {
    expect(() => settlementMatchWitnessSchema.parse({
      ...witness(),
      emittedNotes: [{ ...witness().emittedNotes[0], packedValue: "0x" + "33".repeat(32) }],
    })).toThrow("corresponding emitted note");
    expect(() => settlementMatchWitnessSchema.parse({
      ...witness(),
      payrollNotes: [{ ...witness().payrollNotes[0], position: 1 }],
    })).toThrow("manifest order");
    expect(() => settlementMatchWitnessSchema.parse({
      ...witness(),
      poolCalldata: Array(12_001).fill("0x1"),
    })).toThrow();
  });
});
