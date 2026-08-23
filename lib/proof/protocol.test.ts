import { describe, expect, it } from "vitest";
import { mapPayrollPublicInputs, safeProofFailure } from "./protocol";

describe("proof-worker privacy protocol", () => {
  it("returns only the 16 deployment-bound public inputs", () => {
    const values = Array.from({ length: 16 }, (_, index) => `0x${index.toString(16)}`);
    const mapped = mapPayrollPublicInputs(values);
    expect(mapped).toEqual({
      chainId: "0x0", sealAddress: "0x1", proofVersion: "0x2", schemaVersion: "0x3",
      agreementRootHigh: "0x4", agreementRootLow: "0x5",
      manifestRootHigh: "0x6", manifestRootLow: "0x7",
      policyRootHigh: "0x8", policyRootLow: "0x9", fxRootHigh: "0xa", fxRootLow: "0xb",
      runNullifierHigh: "0xc", runNullifierLow: "0xd", validityStart: "0xe", validityExpiry: "0xf",
    });
    expect(Object.keys(mapped)).toHaveLength(16);
  });

  it("rejects unexpected public-input shapes", () => {
    expect(() => mapPayrollPublicInputs(["0x1"])).toThrow("Expected 16");
  });

  it("never reflects prover errors or witness values to the main thread", () => {
    const privateSalary = "salary=987654321";
    const failure = safeProofFailure("request-1", "WITNESS_INVALID");
    expect(JSON.stringify(failure)).not.toContain(privateSalary);
    expect(failure.message).toBe("The encrypted payroll witness did not satisfy PayrollIntegrity.");
  });
});
