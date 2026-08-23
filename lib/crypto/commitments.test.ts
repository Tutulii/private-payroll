import { describe, expect, it } from "vitest";
import vector from "@/vectors/commitments-v1.json";
import { calculatePayrollLine, type PrivatePayrollLine } from "@/lib/domain/payroll";
import {
  buildFixedMerkleRoot,
  deriveRunNullifier,
  hashPayrollLeaf,
  splitHashToU128,
} from "./commitments";

describe("PAYO canonical commitments", () => {
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
