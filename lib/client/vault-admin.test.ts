import { describe, expect, it, vi } from "vitest";
import {
  createSecondAdminEnrollment,
  decryptVaultRecord,
  encryptVaultRecord,
  generateVaultPrincipal,
  recoverVaultRecoveryPackage,
} from "@/lib/crypto/vault";
import type { PayoClient } from "./payo-client";
import { finishSecondAdminRecovery, prepareSecondAdminGrant } from "./vault-admin";

const organizationId = "0198ddf0-9c00-7000-8000-000000000001";

describe("second-admin recovery lifecycle", () => {
  it("grants the organization key without sending plaintext to the API", async () => {
    const firstAdmin = generateVaultPrincipal("did:privy:first");
    const enrollment = await createSecondAdminEnrollment({
      organizationId,
      principalId: "did:privy:second",
      password: "second administrator password",
    });
    const encryptedProfile = encryptVaultRecord(
      { id: organizationId, name: "Private company" },
      { schemaVersion: 1, organizationId, recordType: "organization-profile", recordId: organizationId, revision: 1 },
      [firstAdmin],
    );
    const organizationSecret = `0x${"55".repeat(32)}`;
    const grant = prepareSecondAdminGrant({
      organizationId,
      organizationSecret,
      authorizingPrincipal: firstAdmin,
      encryptedProfile,
      enrollment,
      keyVersion: 1,
    });
    expect(JSON.stringify(grant)).not.toContain(organizationSecret);
    expect(grant.encryptedProfile.ciphertext).toBe(encryptedProfile.ciphertext);

    const client = {
      getVaultKeyGrant: vi.fn().mockResolvedValue({
        grant: { id: grant.grantId, keyVersion: 1, envelope: grant.envelope, createdAt: new Date().toISOString() },
      }),
    } as unknown as PayoClient;
    const recovered = await finishSecondAdminRecovery({
      client,
      enrollment,
      password: "second administrator password",
    });
    expect(recovered.organizationSecret).toBe(organizationSecret);
    expect(decryptVaultRecord(grant.encryptedProfile, recovered.principal)).toMatchObject({ name: "Private company" });
    await expect(recoverVaultRecoveryPackage(
      recovered.recoveryPackage,
      "second administrator password",
    )).resolves.toMatchObject({ organizationSecret });
  }, 30_000);
});
