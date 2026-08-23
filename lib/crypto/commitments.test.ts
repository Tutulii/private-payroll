import { describe, expect, it } from "vitest";
import vector from "@/vectors/commitments-v1.json";
import { calculatePayrollLine, type PrivatePayrollLine } from "@/lib/domain/payroll";
import {
  buildFixedMerkleRoot,
  deriveRunNullifier,
  hashAgreementTerms,
  hashPayrollLeaf,
  splitHashToU128,
} from "./commitments";
import { compiledPolicyProgramCommitment } from "@/lib/policy/engine";

describe("PAYO canonical commitments", () => {
  it("matches the authoritative agreement-terms Noir vector", () => {
    const zeroes = Array(16).fill("0");
    const policyCommitment = compiledPolicyProgramCommitment({
      metadataCommitment: `0x${"07".repeat(32)}`,
      instructionCount: 2,
      opcodes: [2, 6, ...Array(14).fill(0)],
      left: Array(16).fill(0),
      right: Array(16).fill(0),
      immediate: zeroes,
      numerator: ["0", "1", ...Array(14).fill("0")],
      denominator: ["0", "10", ...Array(14).fill("0")],
      outputRegister: 1,
    });
    expect(hashAgreementTerms({
      agreementIdCommitment: `0x${"01".repeat(32)}`,
      recipientCommitment: `0x${"02".repeat(32)}`,
      earningsAtomic: ["100"],
      token: "STRK",
      policyCommitment,
      scheduleCommitment: `0x${"04".repeat(32)}`,
      dueAt: 100n,
      validUntil: 200n,
      classificationDeclared: 1,
      classificationScore: 10,
      classificationEmployeeThreshold: 5,
      finalPayMode: false,
      finalRequiredMask: 0,
      finalComponentsAtomic: [],
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
      salt: `0x${"06".repeat(32)}`,
    })).toBe("0xe42ba9589267d776623d6b4791668cbce16d586e12e499a37058fcd07f49e278");
  });
  it("matches the v1 cross-language golden vector", () => {
    const line = calculatePayrollLine(vector.input as PrivatePayrollLine);
    const leaf = hashPayrollLeaf(line);
    const root = buildFixedMerkleRoot([leaf]);
    const nullifier = deriveRunNullifier({
      organizationSecret: vector.organizationSecret,
      cycleId: vector.cycleId,
      revision: vector.revision,
    });
    const limbs = splitHashToU128(root);

    expect(leaf).toBe(vector.expected.leaf);
    expect(root).toBe(vector.expected.root);
    expect(nullifier).toBe(vector.expected.nullifier);
    expect(limbs.high.toString()).toBe(vector.expected.rootHighU128);
    expect(limbs.low.toString()).toBe(vector.expected.rootLowU128);
  });

  it("rejects payroll trees above the private circuit bound", () => {
    expect(() => buildFixedMerkleRoot(Array(51).fill(vector.expected.leaf))).toThrow("at most 50");
  });
});
