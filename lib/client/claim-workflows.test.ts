import { describe, expect, it, vi } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  createEncryptedRemediationDraft,
  createEncryptedWageClaimDraft,
} from "./claim-workflows";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const agreementId = "018f1000-0000-7000-8000-000000000002";
const runId = "018f1000-0000-7000-8000-000000000003";

describe("encrypted claim and remediation drafts", () => {
  it("stores salted claim facts only as ciphertext", async () => {
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const claim = await createEncryptedWageClaimDraft({
      client: { storeEncryptedRecord } as never,
      organizationId,
      agreementId,
      runId,
      claimKind: "below_committed_floor",
      principal: generateVaultPrincipal("worker:test"),
      now: new Date("2026-08-24T12:00:00.000Z"),
    });
    expect(claim).toMatchObject({ state: "draft", claimKind: "below_committed_floor" });
    expect(claim.proofBundleId).toBeUndefined();
    expect(JSON.stringify(storeEncryptedRecord.mock.calls[0][0].envelope)).not.toContain("below_committed_floor");
  });

  it("creates remediation as an explicitly unproved draft", async () => {
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const remediation = await createEncryptedRemediationDraft({
      client: { storeEncryptedRecord } as never,
      organizationId,
      claimId: agreementId,
      principal: generateVaultPrincipal("admin:test"),
      now: new Date("2026-08-24T12:00:00.000Z"),
    });
    expect(remediation).toMatchObject({ state: "draft" });
    expect(remediation.settlementId).toBeUndefined();
    expect(remediation.proofBundleId).toBeUndefined();
  });
});
