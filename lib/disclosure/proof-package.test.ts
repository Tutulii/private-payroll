import { describe, expect, it } from "vitest";
import { zipSync } from "fflate";
import { sha256 } from "@noble/hashes/sha2.js";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { toBase64, toHex } from "@/lib/crypto/encoding";
import { createProofCommitter } from "@/lib/proof/commitments";
import {
  createRecipientEncryptedProofPackage,
  inspectRecipientProofPackageOffline,
  proofPackagePublicInputsHash,
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

function encryptedArchiveFixture(input: {
  archive: Uint8Array;
  grant: ProofPackageGrant;
  recipient: ReturnType<typeof generateVaultPrincipal>;
}) {
  const packageCommitment = toHex(sha256(input.archive));
  return {
    packageVersion: "payo-encrypted-proof-package-v1" as const,
    grantId: input.grant.id,
    packageCommitment,
    envelope: encryptVaultRecord({
      archiveBase64: toBase64(input.archive),
      packageCommitment,
    }, {
      schemaVersion: 1,
      organizationId: input.grant.organizationId,
      recordType: "proof-package",
      recordId: input.grant.id,
      revision: 1,
    }, [input.recipient]),
  };
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

  it("binds current packages to canonical public inputs and rejects a changed digest", async () => {
    const { recipient, grant, payload } = await fixture();
    const publicInputs = {
      ...payload.proofPackage.publicInputs,
      chainId: "0x1",
      sealAddress: "0x123",
      proofVersion: "2",
      schemaVersion: "1",
      agreementRootHigh: "1",
      agreementRootLow: "2",
      manifestRootHigh: "3",
      manifestRootLow: "4",
      policyRootHigh: "5",
      policyRootLow: "6",
      fxRootHigh: "7",
      fxRootLow: "8",
      runNullifierHigh: "9",
      runNullifierLow: "10",
      validityStart: "11",
      validityExpiry: "12",
    };
    const publicInputsHash = proofPackagePublicInputsHash(publicInputs);
    expect(publicInputsHash).toMatch(/^0x[0-9a-f]{64}$/);
    const boundPayload: RecipientProofPackagePayload = {
      ...payload,
      proofPackage: {
        ...payload.proofPackage,
        verifier: { ...payload.proofPackage.verifier, chainId: "0x1" },
        publicInputs,
      },
      verification: { ...payload.verification, publicInputsHash: publicInputsHash! },
    };
    const encrypted = createRecipientEncryptedProofPackage({ payload: boundPayload, recipient, at: activeAt });
    await expect(inspectRecipientProofPackageOffline({
      encryptedPackage: encrypted,
      recipient,
      currentGrant: grant,
      at: activeAt,
    })).resolves.toMatchObject({ publicInputsBinding: "verified" });
    expect(() => createRecipientEncryptedProofPackage({
      payload: {
        ...boundPayload,
        verification: { ...boundPayload.verification, publicInputsHash: `0x${"ff".repeat(32)}` },
      },
      recipient,
      at: activeAt,
    })).toThrow(/not bound to the packaged proof public inputs/i);
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
    })).rejects.toThrow(/expired/);
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: encrypted,
      recipient,
      currentGrant: { ...grant, revokedAt: "2026-08-26T11:59:30.000Z" },
      at: activeAt,
    })).rejects.toThrow(/revoked/);

    const wrongKey = generateVaultPrincipal(recipient.principalId);
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: encrypted,
      recipient: wrongKey,
      currentGrant: grant,
      at: activeAt,
    })).rejects.toThrow(/public key/);
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

  it("rejects mismatched envelope metadata and unsafe ZIP contents before extraction", async () => {
    const { recipient, grant, payload } = await fixture();
    const encrypted = createRecipientEncryptedProofPackage({ payload, recipient, at: activeAt });
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: {
        ...encrypted,
        envelope: { ...encrypted.envelope, aad: { ...encrypted.envelope.aad, organizationId: "another-organization" } },
      },
      recipient,
      currentGrant: grant,
      at: activeAt,
    })).rejects.toThrow(/does not match/);

    const unsupportedArchive = zipSync({ "unexpected.txt": new Uint8Array([1, 2, 3]) });
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: encryptedArchiveFixture({ archive: unsupportedArchive, grant, recipient }),
      recipient,
      currentGrant: grant,
      at: activeAt,
    })).rejects.toThrow(/archive.*unsupported/i);

    const oversizedArchive = zipSync({ "proof.json": new Uint8Array(8 * 1024 * 1024 + 1) });
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: encryptedArchiveFixture({ archive: oversizedArchive, grant, recipient }),
      recipient,
      currentGrant: grant,
      at: activeAt,
    })).rejects.toThrow(/safe size limit/i);
  });
});
