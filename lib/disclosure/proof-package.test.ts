import { describe, expect, it } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import { createProofCommitter } from "@/lib/proof/commitments";
import {
  createRecipientEncryptedProofPackage,
  verifyRecipientProofPackageOffline,
  type ProofPackageGrant,
  type RecipientProofPackagePayload,
} from "./proof-package";

const activeAt = new Date("2026-08-26T12:00:00.000Z");

async function fixture(scope: ProofPackageGrant["scope"] = "worker") {
  const recipient = generateVaultPrincipal(`${scope}-principal`);
  const committer = await createProofCommitter();
  const leaves = [committer.proofHash(9n, [11n]), committer.proofHash(9n, [22n])];
  const opening = committer.buildProofFixedMerkleMembership(leaves, 1);
  const grant: ProofPackageGrant = {
    grantVersion: "payo-proof-package-grant-v1",
    id: `grant-${scope}-0001`,
    organizationId: "organization-0001",
    runId: "payroll-run-0001",
    scope,
    granteePrincipalId: recipient.principalId,
    fieldScope: scope === "worker" ? ["net", "token", "settlement"] : ["aggregate", "settlement"],
    recipientEncryptionKey: recipient.publicKey,
    validAfter: "2026-08-26T11:00:00.000Z",
    expiresAt: "2026-08-27T11:00:00.000Z",
  };
  const payload: RecipientProofPackagePayload = {
    packageVersion: "payo-recipient-proof-package-v1",
    grant,
    journal: [
      { date: "2026-08-26", accountCode: "PAYROLL", debitAtomic: "25", creditAtomic: "0", token: "USDC", memo: "Scoped private payroll" },
      { date: "2026-08-26", accountCode: "TREASURY", debitAtomic: "0", creditAtomic: "25", token: "USDC", memo: "Private settlement" },
    ],
    proofPackage: {
      packageVersion: "payo-proof-package-v1",
      runId: grant.runId,
      organizationId: grant.organizationId,
      proofType: "payroll_integrity",
      proofVersion: "2",
      verifier: { chainId: "SN_SEPOLIA", contractAddress: "0x123" },
      publicInputs: { manifestRoot: opening.root },
      proof: "0xproof",
      createdAt: "2026-08-26T11:55:00.000Z",
    },
    verification: {
      verified: true,
      verificationState: "onchain_verified",
      verifierAddress: "0x123",
      proofVersion: "2",
      publicInputsHash: `0x${"11".repeat(32)}`,
      verificationTransactionHash: "0x456",
      checkedAt: "2026-08-26T11:59:00.000Z",
    },
    starknetReceipt: { transactionHash: "0x789", finality: "ACCEPTED_ON_L2" },
    disclosedFields: scope === "worker"
      ? { net: "25", token: "USDC", settlement: "confirmed" }
      : { aggregate: "25", settlement: "confirmed" },
    ...(scope === "worker" ? {
      lineOpening: {
        manifestRoot: opening.root,
        lineCommitment: opening.leaf,
        lineIndex: 1,
        siblings: opening.siblings,
        pathBits: opening.pathBits,
      },
    } : {}),
  };
  return { recipient, grant, payload };
}

describe("recipient-encrypted proof packages", () => {
  it("encrypts a worker-scoped package and verifies its proof line opening offline", async () => {
    const { recipient, grant, payload } = await fixture();
    const encrypted = createRecipientEncryptedProofPackage({ payload, recipient, at: activeAt });
    expect(JSON.stringify(encrypted)).not.toContain("Scoped private payroll");
    expect(JSON.stringify(encrypted)).not.toContain('"net":"25"');
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: encrypted,
      recipient,
      currentGrant: grant,
      at: activeAt,
    })).resolves.toMatchObject({
      scope: "worker",
      fieldScope: ["net", "token", "settlement"],
      fileNames: expect.arrayContaining(["manifest.json", "line-opening.json", "journal.csv"]),
    });
  });

  it("fails closed for the wrong recipient, expiry, and current revocation", async () => {
    const { recipient, grant, payload } = await fixture();
    const encrypted = createRecipientEncryptedProofPackage({ payload, recipient, at: activeAt });
    const stranger = generateVaultPrincipal("stranger-principal");
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: encrypted, recipient: stranger, currentGrant: grant, at: activeAt,
    })).rejects.toThrow(/recipient|authorized/);
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: encrypted,
      recipient,
      currentGrant: grant,
      at: new Date("2026-08-28T00:00:00.000Z"),
    })).rejects.toThrow(/not active/);
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: encrypted,
      recipient,
      currentGrant: { ...grant, revokedAt: "2026-08-26T11:59:30.000Z" },
      at: activeAt,
    })).rejects.toThrow(/revoked/);
  });

  it("rejects out-of-scope fields and unbalanced journals before encryption", async () => {
    const { recipient, payload } = await fixture("auditor");
    expect(() => createRecipientEncryptedProofPackage({
      payload: { ...payload, disclosedFields: { ...payload.disclosedFields, gross: "secret" } },
      recipient,
      at: activeAt,
    })).toThrow(/outside its grant/);
    expect(() => createRecipientEncryptedProofPackage({
      payload: {
        ...payload,
        journal: [payload.journal[0], { ...payload.journal[1], creditAtomic: "24" }],
      },
      recipient,
      at: activeAt,
    })).toThrow(/not balanced/);
  });
});
