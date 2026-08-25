import { describe, expect, it } from "vitest";
import { decryptVaultRecord } from "@/lib/crypto/vault";
import { createVaultWorkspace, unlockVaultWorkspace } from "./vault-workspace";

describe("vault workspace onboarding", () => {
  it("creates an encrypted organization and recoverable client-only keys", async () => {
    const workspace = await createVaultWorkspace({
      principalId: "did:privy:owner",
      organizationName: "Acorn Labs",
      recoveryPassword: "a production strength recovery phrase",
      now: new Date("2026-08-24T00:00:00.000Z"),
    });
    const wire = JSON.stringify({
      organizationId: workspace.organizationId,
      encryptedProfile: workspace.encryptedProfile,
      initialPrincipal: workspace.initialPrincipal,
      vaultPublicKey: workspace.principal.publicKey,
      recoveryPackageHash: workspace.recoveryPackageHash,
    });
    expect(wire).not.toContain("Acorn Labs");
    expect(wire).not.toContain(workspace.organizationSecret);
    expect(wire).not.toContain(workspace.principal.secretKey);
    expect(decryptVaultRecord(workspace.encryptedProfile, workspace.principal)).toMatchObject({
      name: "Acorn Labs",
      enabledTokens: ["STRK", "USDC"],
    });
    expect(decryptVaultRecord(workspace.initialPrincipal.envelope, workspace.principal)).toMatchObject({
      kind: "admin",
      accessState: "vault_grantee",
      vaultPrincipalId: "did:privy:owner",
    });
    await expect(unlockVaultWorkspace(
      workspace.recoveryPackage,
      "a production strength recovery phrase",
    )).resolves.toMatchObject({
      organizationId: workspace.organizationId,
      organizationSecret: workspace.organizationSecret,
      principal: workspace.principal,
    });
  }, 30_000);

  it("rejects empty names and weak recovery passwords", async () => {
    await expect(createVaultWorkspace({
      principalId: "did:privy:owner",
      organizationName: "",
      recoveryPassword: "a production strength recovery phrase",
    })).rejects.toThrow();
    await expect(createVaultWorkspace({
      principalId: "did:privy:owner",
      organizationName: "Acorn Labs",
      recoveryPassword: "weak",
    })).rejects.toThrow(/12/);
  });
});
