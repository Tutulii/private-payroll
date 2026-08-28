import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  classifyProofFailure,
  mapPayrollPublicInputs,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  PAYROLL_MOBILE_WASM_MAXIMUM_PAGES,
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  PAYO_PROOF_SUBMISSION_OVERHEAD_FELTS,
  STARKNET_MAX_INVOKE_CALLDATA_FELTS,
  payrollProverBackendOptions,
  safeProofFailure,
} from "./protocol";
import { decodeVerificationKeyHex } from "./starknet-calldata";

describe("proof-worker privacy protocol", () => {
  it("returns only the 16 deployment-bound inputs plus the shard index", () => {
    const values = Array.from({ length: 17 }, (_, index) => `0x${index.toString(16)}`);
    const mapped = mapPayrollPublicInputs(values);
    expect(mapped).toEqual({
      chainId: "0x0", sealAddress: "0x1", proofVersion: "0x2", schemaVersion: "0x3",
      agreementRootHigh: "0x4", agreementRootLow: "0x5",
      manifestRootHigh: "0x6", manifestRootLow: "0x7",
      policyRootHigh: "0x8", policyRootLow: "0x9", fxRootHigh: "0xa", fxRootLow: "0xb",
      runNullifierHigh: "0xc", runNullifierLow: "0xd", validityStart: "0xe", validityExpiry: "0xf",
      shardIndex: "0x10",
    });
    expect(Object.keys(mapped)).toHaveLength(17);
  });

  it("rejects unexpected public-input shapes", () => {
    expect(() => mapPayrollPublicInputs(["0x1"])).toThrow("Expected 17");
  });

  it("pins the exact deployment-bound browser circuit", () => {
    const circuit = readFileSync(new URL("../../public/circuits/payroll_integrity-v1.json", import.meta.url));
    const digest = `0x${createHash("sha256").update(circuit).digest("hex")}`;
    expect(PAYROLL_INTEGRITY_CIRCUIT_SHA256).toBe(digest);
  });

  it("pins the proof-bound verification key served to the browser worker", () => {
    const document = readFileSync(
      new URL("../../public/circuits/payroll_integrity-v1.vk.hex", import.meta.url),
      "utf8",
    );
    const verificationKey = decodeVerificationKeyHex(document);
    const digest = `0x${createHash("sha256").update(verificationKey).digest("hex")}`;
    expect(verificationKey).toHaveLength(1_888);
    expect(PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256).toBe(digest);
  });

  it("pins the merged v2 circuit and its proof-bound verification key", () => {
    const circuit = readFileSync(new URL("../../public/circuits/advanced_obligation-v2.json", import.meta.url));
    const verificationKey = decodeVerificationKeyHex(readFileSync(
      new URL("../../public/circuits/advanced_obligation-v2.vk.hex", import.meta.url),
      "utf8",
    ));
    expect(`0x${createHash("sha256").update(circuit).digest("hex")}`)
      .toBe(ADVANCED_OBLIGATION_CIRCUIT_SHA256);
    expect(`0x${createHash("sha256").update(verificationKey).digest("hex")}`)
      .toBe(ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256);
    expect(verificationKey).toHaveLength(1_888);
  });

  it("reserves account and PayrollSeal overhead below Starknet's invoke limit", () => {
    expect(PAYO_MAX_PROOF_CALLDATA_FELTS + PAYO_PROOF_SUBMISSION_OVERHEAD_FELTS)
      .toBe(STARKNET_MAX_INVOKE_CALLDATA_FELTS);
    expect(3_223).toBeLessThanOrEqual(PAYO_MAX_PROOF_CALLDATA_FELTS);
  });

  it("never reflects prover errors or witness values to the main thread", () => {
    const privateSalary = "salary=987654321";
    const failure = safeProofFailure("request-1", "WITNESS_INVALID");
    expect(JSON.stringify(failure)).not.toContain(privateSalary);
    expect(failure.message).toBe("The encrypted payroll witness did not satisfy PayrollIntegrity.");
  });

  it("uses a measured one-thread WASM ceiling on mobile without weakening desktop isolation", () => {
    expect(payrollProverBackendOptions({
      userAgent: "Mozilla/5.0 (Linux; Android 16; Mobile)",
      crossOriginIsolated: false,
      hardwareConcurrency: 8,
    })).toEqual({ threads: 1, memory: { maximum: PAYROLL_MOBILE_WASM_MAXIMUM_PAGES } });
    expect(payrollProverBackendOptions({
      userAgent: "Mozilla/5.0 (X11; Linux x86_64)",
      crossOriginIsolated: true,
      hardwareConcurrency: 16,
    })).toEqual({ threads: 4 });
  });

  it("maps memory exhaustion to an actionable error without reflecting backend details", () => {
    const code = classifyProofFailure(new Error("bad alloc salary=987654321"), "PROVING_FAILED");
    const failure = safeProofFailure("request-2", code);
    expect(failure.code).toBe("PROVING_RESOURCE_EXHAUSTED");
    expect(JSON.stringify(failure)).not.toContain("987654321");
    expect(classifyProofFailure(new Error("ordinary prover failure"), "PROVING_FAILED"))
      .toBe("PROVING_FAILED");
  });
});
