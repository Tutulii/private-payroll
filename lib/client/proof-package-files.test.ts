import { describe, expect, it } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  createRecipientEncryptedProofPackage,
  type ProofPackageGrant,
  type RecipientProofPackagePayload,
} from "@/lib/disclosure/proof-package";
import {
  classifyProofPackageOpenFailure,
  createPayoPublicIdentity,
  openPayoProofPackage,
  parsePayoProofPackageExport,
  parsePayoPublicIdentity,
  parsePayoJsonText,
  proofPackageFilename,
  proofPackageIdentityFingerprint,
  publicIdentityFilename,
} from "./proof-package-files";

const now = new Date("2026-08-28T06:30:00.000Z");

function fixture() {
  const recipient = generateVaultPrincipal("recipient-proof-principal");
  const grant: ProofPackageGrant = {
    grantVersion: "payo-proof-package-grant-v1",
    id: "grant-remediation-0001",
    organizationId: "organization-0001",
    runId: "payroll-run-0001",
    scope: "employer",
    granteePrincipalId: recipient.principalId,
    fieldScope: ["exception", "settlement"],
    recipientEncryptionKey: recipient.publicKey,
    validAfter: "2026-08-28T06:00:00.000Z",
    expiresAt: "2026-08-29T06:00:00.000Z",
  };
  const payload: RecipientProofPackagePayload = {
    packageVersion: "payo-recipient-proof-package-v1",
    grant,
    journal: [
      { date: "2026-08-28", accountCode: "WAGE_REMEDIATION_EXPENSE", debitAtomic: "2500000", creditAtomic: "0", token: "USDC", memo: "Proof-bound remediation" },
      { date: "2026-08-28", accountCode: "PRIVATE_TREASURY", debitAtomic: "0", creditAtomic: "2500000", token: "USDC", memo: "Private remediation settlement" },
    ],
    proofPackage: {
      packageVersion: "payo-proof-package-v1",
      runId: grant.runId,
      organizationId: grant.organizationId,
      proofType: "wage_remediation",
      proofVersion: "4",
      verifier: { chainId: "SN_MAIN", contractAddress: "0x123" },
      publicInputs: { manifestRoot: `0x${"11".repeat(32)}` },
      proof: "encrypted-proof-reference",
      transactionHash: "0x789",
      createdAt: "2026-08-28T06:20:00.000Z",
    },
    verification: {
      verified: true,
      verificationState: "onchain_verified",
      verifierAddress: "0x123",
      proofVersion: "4",
      publicInputsHash: `0x${"22".repeat(32)}`,
      verificationTransactionHash: "0x456",
      checkedAt: "2026-08-28T06:25:00.000Z",
    },
    starknetReceipt: { transactionHash: "0x789", state: "finalized", confirmationDepth: 9 },
    disclosedFields: {
      exception: {
        workflowType: "wage_remediation",
        subjectRecordId: "remediation-0001",
        claimId: "claim-missing-0001",
        claimKind: "missing_obligation",
        agreementId: "agreement-0001",
        amountAtomic: "2500000",
        token: "USDC",
      },
      settlement: { transactionHash: "0x789" },
    },
  };
  const encryptedPackage = createRecipientEncryptedProofPackage({ payload, recipient, at: now });
  const file = {
    format: "payo-encrypted-proof-package-v1" as const,
    organizationId: grant.organizationId,
    runId: grant.runId,
    scope: grant.scope,
    grant,
    encryptedPackage,
  };
  return { recipient, grant, file };
}

describe("PAYO proof package files", () => {
  it("opens a recipient package locally and produces readable linked claim context", async () => {
    const { recipient, grant, file } = fixture();
    const opened = await openPayoProofPackage({ value: file, recipient, currentGrant: grant, at: now });
    expect(opened.grantEvidence).toBe("current");
    expect(opened.report).toMatchObject({
      integrity: "verified",
      publicInputsBinding: "legacy",
      workflow: "wage_remediation",
      workflowLabel: "Private wage remediation",
      settlementState: "finalized",
      claim: {
        type: "missing_obligation",
        typeLabel: "Missing obligation",
        id: "claim-missing-0001",
        amountAtomic: "2500000",
        amountLabel: "2.5 USDC",
        token: "USDC",
        settlementState: "finalized",
      },
    });
    expect(proofPackageFilename(opened.report)).toBe("payo-wage-remediation-employer-20260828.json");
    expect(proofPackageFilename(opened.report)).not.toContain("missing-obligation");
  });

  it("rejects cross-field export tampering and revoked current grants", async () => {
    const { recipient, grant, file } = fixture();
    expect(() => parsePayoProofPackageExport({ ...file, runId: "another-payroll-run" })).toThrow(/not a valid PAYO/i);
    await expect(openPayoProofPackage({
      value: file,
      recipient,
      currentGrant: { ...grant, revokedAt: "2026-08-28T06:29:00.000Z" },
      at: now,
    })).rejects.toThrow(/revoked/i);
  });

  it("rejects malformed JSON, unsupported formats, and modified commitments", async () => {
    const { recipient, grant, file } = fixture();
    expect(() => parsePayoJsonText("{", "The proof package")).toThrow(/not valid JSON/i);
    expect(() => parsePayoProofPackageExport({ ...file, format: "payo-proof-package-v0" })).toThrow(/not a valid PAYO/i);
    await expect(openPayoProofPackage({
      value: {
        ...file,
        encryptedPackage: { ...file.encryptedPackage, packageCommitment: `0x${"ff".repeat(32)}` },
      },
      recipient,
      currentGrant: grant,
      at: now,
    })).rejects.toThrow(/commitment/i);
  });

  it("rejects ciphertext tampering instead of rendering partial data", async () => {
    const { recipient, grant, file } = fixture();
    const ciphertext = file.encryptedPackage.envelope.ciphertext;
    const tampered = {
      ...file,
      encryptedPackage: {
        ...file.encryptedPackage,
        envelope: {
          ...file.encryptedPackage.envelope,
          ciphertext: `${ciphertext[0] === "A" ? "B" : "A"}${ciphertext.slice(1)}`,
        },
      },
    };
    await expect(openPayoProofPackage({ value: tampered, recipient, currentGrant: grant, at: now })).rejects.toThrow();
  });
});

describe("PAYO public identities", () => {
  it("exports only public material and verifies its fingerprint on import", () => {
    const principal = generateVaultPrincipal("shared-identity-principal");
    const identity = createPayoPublicIdentity(principal, now);
    expect(JSON.stringify(identity)).not.toContain(principal.secretKey);
    expect(parsePayoPublicIdentity(identity)).toEqual(identity);
    expect(publicIdentityFilename(identity)).toMatch(/^payo-public-identity-[0-9a-f]{8}\.json$/);
    expect(() => parsePayoPublicIdentity({ ...identity, principalId: "changed-principal" })).toThrow(/fingerprint/i);
    expect(() => parsePayoPublicIdentity({ ...identity, secretKey: principal.secretKey })).toThrow(/not a valid PAYO/i);
    const invalidKeyIdentity = {
      ...identity,
      publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    };
    expect(() => parsePayoPublicIdentity({
      ...invalidKeyIdentity,
      fingerprint: proofPackageIdentityFingerprint(invalidKeyIdentity),
    })).toThrow(/invalid X25519/i);
  });
});

describe("proof package failure labels", () => {
  it.each([
    [new Error("The disclosure grant is expired."), "expired", "Expired"],
    [new Error("The disclosure grant is revoked."), "revoked", "Revoked"],
    [new Error("The recipient public key does not match."), "wrong_recipient", "Wrong recipient"],
    [new Error("The package commitment is invalid."), "tampered", "Tampered"],
    [new Error("Unsupported package"), "invalid", "Invalid"],
  ] as const)("maps a rejected package to a safe result", (error, code, title) => {
    expect(classifyProofPackageOpenFailure(error)).toMatchObject({ code, title });
  });
});
