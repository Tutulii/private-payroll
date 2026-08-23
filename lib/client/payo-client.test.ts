import { describe, expect, it } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { prepareEncryptedPayrollRun } from "./payo-client";

describe("client-encrypted payroll preparation", () => {
  it("commits and encrypts salary data before API transport", () => {
    const principal = generateVaultPrincipal("owner");
    const prepared = prepareEncryptedPayrollRun({
      id: "payroll-run-001",
      organizationId: "organization-001",
      cycleId: "2026-08",
      revision: 1,
      dueAt: "2026-08-27T00:00:00.000Z",
      organizationSecret: `0x${"44".repeat(32)}`,
      principals: [principal],
      lines: [{
        agreementId: "maya-2026",
        recipientAddress: "0x123",
        token: "STRK",
        earningsAtomic: ["1000000000000000000"],
        deductionsAtomic: ["100000000000000000"],
        committedPolicyId: "policy-us-reference-v1",
        scheduleCommitment: `0x${"11".repeat(32)}`,
        salt: `0x${"22".repeat(32)}`,
      }],
    });
    const wire = JSON.stringify(prepared);
    expect(wire).not.toContain("maya-2026");
    expect(wire).not.toContain("1000000000000000000");

    const decrypted = decryptVaultRecord<{ manifest: { lines: Array<{ agreementId: string }> } }>(
      prepared.envelope,
      principal,
    );
    expect(decrypted.manifest.lines[0].agreementId).toBe("maya-2026");
    expect(prepared.agreementRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(prepared.manifestRoot).toMatch(/^0x[0-9a-f]{64}$/);
  });
});
