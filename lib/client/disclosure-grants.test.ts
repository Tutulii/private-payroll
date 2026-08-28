import { describe, expect, it, vi } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import { createEncryptedDisclosureGrant } from "./disclosure-grants";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const runId = "018f1000-0000-7000-8000-000000000002";
const granteePrincipalId = "550e8400-e29b-41d4-a716-446655440000";

describe("encrypted disclosure grants", () => {
  it("wraps the grant to issuer and recipient without uploading the recipient key in plaintext", async () => {
    const issuer = generateVaultPrincipal("admin:test");
    const grantee = generateVaultPrincipal(granteePrincipalId);
    const createDisclosureGrant = vi.fn().mockResolvedValue({ grant: {} });
    const result = await createEncryptedDisclosureGrant({
      client: { createDisclosureGrant } as never,
      organizationId,
      runId,
      granteePrincipalId,
      granteePublicKey: grantee.publicKey,
      issuerPrincipal: issuer,
      expiresAt: "2026-08-25T12:00:00.000Z",
      now: new Date("2026-08-24T12:00:00.000Z"),
    });
    expect(result.record.fieldScope).toEqual(["aggregate", "token", "settlement"]);
    expect(result.envelope.wrappedKeys.map(({ principalId }) => principalId).sort())
      .toEqual([issuer.principalId, granteePrincipalId].sort());
    const request = createDisclosureGrant.mock.calls[0][0];
    expect(JSON.stringify(request.envelope)).not.toContain(grantee.publicKey);
  });

  it("rejects an invalid recipient X25519 key before the API call", async () => {
    const createDisclosureGrant = vi.fn();
    await expect(createEncryptedDisclosureGrant({
      client: { createDisclosureGrant } as never,
      organizationId,
      runId,
      granteePrincipalId,
      granteePublicKey: "not-a-valid-key",
      issuerPrincipal: generateVaultPrincipal("admin:test"),
      expiresAt: "2026-08-25T12:00:00.000Z",
      now: new Date("2026-08-24T12:00:00.000Z"),
    })).rejects.toThrow();
    expect(createDisclosureGrant).not.toHaveBeenCalled();
  });
});
