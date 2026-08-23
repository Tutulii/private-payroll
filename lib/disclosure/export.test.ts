import { strFromU8 } from "fflate";
import { describe, expect, it } from "vitest";
import { createComplianceExportZip, inspectComplianceExportZip, type ComplianceExport } from "./export";

const fixture: ComplianceExport = {
  exportVersion: "payo-compliance-export-v1",
  scope: "auditor",
  organizationId: "organization-001",
  runId: "payroll-run-001",
  journal: [
    { date: "2026-08-23", accountCode: "PAYROLL", debitAtomic: "100", creditAtomic: "0", token: "STRK", memo: "Private payroll aggregate" },
    { date: "2026-08-23", accountCode: "TREASURY", debitAtomic: "0", creditAtomic: "100", token: "STRK", memo: "Settlement" },
  ],
  proofPackage: {
    packageVersion: "payo-proof-package-v1",
    runId: "payroll-run-001",
    organizationId: "organization-001",
    proofType: "payroll_integrity",
    proofVersion: "1",
    verifier: { chainId: "SN_MAIN", contractAddress: "0x123" },
    publicInputs: { manifestRoot: "0xabc" },
    proof: "0xproof",
    createdAt: "2026-08-23T10:00:00.000Z",
  },
  verification: {
    verified: true,
    verifierAddress: "0x123",
    proofVersion: "1",
    checkedAt: "2026-08-23T10:01:00.000Z",
  },
  starknetReceipt: { transactionHash: "0x456", finality: "ACCEPTED_ON_L2" },
};

describe("compliance export", () => {
  it("creates a self-describing archive without adding payroll plaintext", () => {
    const files = inspectComplianceExportZip(createComplianceExportZip(fixture));
    expect(Object.keys(files).sort()).toEqual([
      "journal.csv",
      "manifest.json",
      "proof.json",
      "starknet-receipt.json",
      "verification.json",
    ]);
    const manifest = JSON.parse(strFromU8(files["manifest.json"]));
    expect(manifest.content).toHaveLength(4);
    expect(strFromU8(files["journal.csv"])).toContain("Private payroll aggregate");
  });

  it("rejects unbalanced accounting journals", () => {
    expect(() => createComplianceExportZip({
      ...fixture,
      journal: [fixture.journal[0], { ...fixture.journal[1], creditAtomic: "99" }],
    })).toThrow("journal is not balanced");
  });
});
