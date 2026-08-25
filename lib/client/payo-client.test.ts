import { describe, expect, it } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { deriveRunNullifier } from "@/lib/crypto/commitments";
import { prepareEncryptedPayrollRun } from "./payo-client";

describe("client-encrypted payroll preparation", () => {
  it("commits and encrypts salary data before API transport", () => {
    const principal = generateVaultPrincipal("owner");
    const organizationSecret = `0x${"44".repeat(32)}`;
    const runNullifier = deriveRunNullifier({ organizationSecret, cycleId: "2026-08", revision: 1 });
    const runId = "0198ddf0-9c00-7000-8000-000000000001";
    const organizationId = "0198ddf0-9c00-7000-8000-000000000002";
    const agreementId = "0198ddf0-9c00-7000-8000-000000000003";
    const payeeId = "0198ddf0-9c00-7000-8000-000000000004";
    const prepared = prepareEncryptedPayrollRun({
      id: runId,
      organizationId,
      cycleId: "2026-08",
      revision: 1,
      dueAt: "2026-08-27T00:00:00.000Z",
      organizationSecret,
      principals: [principal],
      proofBinding: {
        agreementRoot: `0x${"aa".repeat(32)}`,
        manifestRoot: `0x${"bb".repeat(32)}`,
        policyRoot: `0x${"cc".repeat(32)}`,
        fxRoot: `0x${"dd".repeat(32)}`,
        runNullifier,
      },
      lineRecordMetadata: [{
        agreementId,
        payeeId,
        recipientCommitment: `0x${"33".repeat(32)}`,
        policyCommitment: `0x${"55".repeat(32)}`,
      }],
      lines: [{
        agreementId,
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
    expect(wire).not.toContain(agreementId);
    expect(wire).not.toContain("1000000000000000000");

    const decrypted = decryptVaultRecord<{ manifest: { lines: Array<{ agreementId: string }> } }>(
      prepared.envelope,
      principal,
    );
    expect(decrypted.manifest.lines[0].agreementId).toBe(agreementId);
    expect(prepared.lineRecords).toHaveLength(1);
    const privateLine = decryptVaultRecord<{ agreementId: string; payeeId: string; netAtomic: string }>(
      prepared.lineRecords[0].envelope,
      principal,
    );
    expect(privateLine).toMatchObject({ agreementId, payeeId, netAtomic: "900000000000000000" });
    expect(prepared.agreementRoot).toBe(`0x${"aa".repeat(32)}`);
    expect(prepared.manifestRoot).toBe(`0x${"bb".repeat(32)}`);
  });
});
