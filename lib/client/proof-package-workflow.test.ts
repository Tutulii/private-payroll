import { describe, expect, it, vi } from "vitest";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  inspectRecipientProofPackageOffline,
  verifyRecipientProofPackageOffline,
} from "@/lib/disclosure/proof-package";
import {
  buildPayrollIntegrityInputsFromSerialized,
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";
import { buildWageClaimInputs, buildWageRemediationInputs } from "@/lib/proof/wage-claim-input";
import { prepareEncryptedPayrollRun } from "./payo-client";
import { createProofPackageForSettlement } from "./proof-package-workflow";

const organizationId = "0198ddf0-9c00-7000-8000-000000000101";
const runId = "0198ddf0-9c00-7000-8000-000000000102";
const settlementId = "0198ddf0-9c00-7000-8000-000000000103";
const proofBundleId = "0198ddf0-9c00-7000-8000-000000000104";
const agreementId = "0198ddf0-9c00-7000-8000-000000000105";
const payeeId = "0198ddf0-9c00-7000-8000-000000000106";
const granteeId = "0198ddf0-9c00-7000-8000-000000000107";
const claimId = "0198ddf0-9c00-7000-8000-000000000108";
const remediationId = "0198ddf0-9c00-7000-8000-000000000109";
const now = new Date("2026-08-26T12:00:00.000Z");

async function fixture(proofState = "complete") {
  const issuer = generateVaultPrincipal("issuer:proof-package");
  const grantee = generateVaultPrincipal(granteeId);
  const snapshot = buildFxSnapshot({
    baseToken: "USDC",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 60,
    minimumSources: 3,
    feedId: "pragma:USDC/USD:median",
    quotes: ["a", "b", "c"].map((source, index) => ({
      source,
      priceAtomic: "1000000",
      observedAt: `1970-01-01T00:16:${40 + index}.000Z`,
    })),
    now: new Date(1_010_000),
  });
  const buildInput = serializePayrollIntegrityBuildRequest({
    chainId: "0x1",
    sealAddress: "0x123",
    organizationSecret: `0x${"55".repeat(32)}`,
    cycleId: "worker-package",
    revision: 1,
    validityStart: 1_010n,
    validityExpiry: 2_000n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [snapshot],
    lines: [{
      agreementId,
      recipientAddress: "0x456",
      recipientSalt: `0x${"11".repeat(32)}`,
      agreementSalt: `0x${"22".repeat(32)}`,
      lineSalt: `0x${"33".repeat(32)}`,
      token: "USDC",
      earningsAtomic: ["250000"],
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment: `0x${"44".repeat(32)}`,
      dueAt: 1_000n,
      validUntil: 2_000n,
      classification: { declared: 2, score: 2, employeeThreshold: 5 },
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
    }],
  });
  const rebuilt = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  const preparedRun = prepareEncryptedPayrollRun({
    id: runId,
    organizationId,
    cycleId: buildInput.cycleId,
    revision: 1,
    dueAt: "2026-08-26T10:00:00.000Z",
    lines: [{
      agreementId,
      recipientAddress: "0x456",
      token: "USDC",
      earningsAtomic: ["250000"],
      deductionsAtomic: [],
      committedPolicyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment: `0x${"44".repeat(32)}`,
      salt: `0x${"33".repeat(32)}`,
    }],
    lineRecordMetadata: [{
      agreementId,
      payeeId,
      recipientCommitment: `0x${"66".repeat(32)}`,
      policyCommitment: `0x${"77".repeat(32)}`,
    }],
    organizationSecret: buildInput.organizationSecret,
    principals: [issuer],
    proofBinding: {
      agreementRoot: rebuilt.agreementRoot,
      manifestRoot: rebuilt.manifestRoot,
      policyRoot: rebuilt.policyRoot,
      fxRoot: rebuilt.fxRoot,
      runNullifier: rebuilt.runNullifier,
    },
    claimProofSource: { buildInput },
    now,
  });
  const proofEnvelope = encryptVaultRecord({
    schemaVersion: 1,
    scheme: "ultra_honk",
    circuitSha256: `0x${"88".repeat(32)}`,
    verificationKeySha256: `0x${"99".repeat(32)}`,
    provingTimeMs: 123,
    shards: rebuilt.publicInputs.map((publicInputs, shardIndex) => ({
      shardIndex,
      proofBase64: "AQ==",
      proofCalldata: ["0x1"],
      calldataHash: `0x${shardIndex + 1}`,
      publicInputs,
    })),
  }, {
    schemaVersion: 1,
    organizationId,
    recordType: "proof-bundle",
    recordId: proofBundleId,
    revision: 1,
  }, [issuer]);
  const createDisclosureGrant = vi.fn().mockResolvedValue({ grant: {} });
  const revokeDisclosureGrant = vi.fn().mockResolvedValue({ grant: {} });
  const client = {
    getSettlement: vi.fn().mockResolvedValue({ settlement: {
      id: settlementId,
      runId,
      organizationId,
      workflowType: "payroll",
      state: "confirmed",
      transactionHash: "0xabc",
      tokenTotalsCommitment: `0x${"aa".repeat(32)}`,
      blockNumber: "123",
      confirmationDepth: 8,
      confirmedAt: now.toISOString(),
    } }),
    getPayrollRun: vi.fn().mockResolvedValue({ run: { id: runId, organizationId, envelope: preparedRun.envelope } }),
    getProofVerification: vi.fn().mockResolvedValue({ proofVerification: {
      proofBundleId,
      state: proofState,
      shard0TransactionHash: "0xaaa",
      shard1TransactionHash: "0xbbb",
      updatedAt: now.toISOString(),
    } }),
    getEncryptedRecord: vi.fn().mockResolvedValue({ record: { envelope: proofEnvelope } }),
    createDisclosureGrant,
    revokeDisclosureGrant,
  };
  return { issuer, grantee, client, createDisclosureGrant, buildInput, rebuilt, preparedRun };
}

async function exceptionFixture(workflowType: "wage_claim" | "wage_remediation") {
  const base = await fixture();
  const validityStart = 1_010n;
  const validityExpiry = 2_000n;
  const claimBuild = await buildWageClaimInputs({
    payroll: base.rebuilt,
    agreementId,
    claimKind: "missing_obligation",
    claimSalt: `0x${"ab".repeat(32)}`,
    validityStart,
    validityExpiry,
  });
  const timestamp = now.toISOString();
  const claim = {
    schemaVersion: 1 as const,
    id: claimId,
    organizationId,
    revision: 3,
    createdAt: timestamp,
    updatedAt: timestamp,
    agreementId,
    runId,
    claimNullifier: claimBuild.claimNullifier,
    claimSalt: claimBuild.claimSalt,
    claimKind: "missing_obligation" as const,
    shortfallAtomic: claimBuild.shortfallAtomic,
    token: claimBuild.token,
    proofBundleId,
    settlementId,
    state: "submitted" as const,
  };
  const remediationBuild = workflowType === "wage_remediation"
    ? await buildWageRemediationInputs({
        claim: claimBuild,
        amountAtomic: claimBuild.shortfallAtomic,
        token: claimBuild.token,
        remediationSalt: `0x${"cd".repeat(32)}`,
        validityStart,
        validityExpiry,
      })
    : undefined;
  const remediation = remediationBuild ? {
    schemaVersion: 1 as const,
    id: remediationId,
    organizationId,
    revision: 3,
    createdAt: timestamp,
    updatedAt: timestamp,
    claimId,
    runId,
    agreementId,
    claimNullifier: claimBuild.claimNullifier,
    amountAtomic: claimBuild.shortfallAtomic,
    token: claimBuild.token,
    settlementId,
    proofBundleId,
    remediationSalt: `0x${"cd".repeat(32)}`,
    state: "submitted" as const,
  } : undefined;
  const subject = workflowType === "wage_claim" ? claim : remediation!;
  const publicInputs = workflowType === "wage_claim" ? claimBuild.publicInputs : remediationBuild!.publicInputs;
  const proofEnvelope = encryptVaultRecord({
    schemaVersion: 1,
    scheme: "ultra_honk",
    circuitSha256: `0x${"88".repeat(32)}`,
    verificationKeySha256: `0x${"99".repeat(32)}`,
    provingTimeMs: 123,
    shards: publicInputs.map((inputs, shardIndex) => ({
      shardIndex,
      proofBase64: "AQ==",
      proofCalldata: ["0x1"],
      calldataHash: `0x${shardIndex + 1}`,
      publicInputs: inputs,
    })),
  }, {
    schemaVersion: 1,
    organizationId,
    recordType: "proof-bundle",
    recordId: proofBundleId,
    revision: 1,
  }, [base.issuer]);
  const subjectEnvelope = encryptVaultRecord(subject, {
    schemaVersion: 1,
    organizationId,
    recordType: workflowType === "wage_claim" ? "wage-claim" : "remediation",
    recordId: subject.id,
    revision: subject.revision,
  }, [base.issuer]);
  const claimEnvelope = encryptVaultRecord(claim, {
    schemaVersion: 1,
    organizationId,
    recordType: "wage-claim",
    recordId: claim.id,
    revision: claim.revision,
  }, [base.issuer]);
  base.client.getSettlement.mockResolvedValue({ settlement: {
    id: settlementId,
    runId,
    organizationId,
    workflowType,
    subjectRecordId: subject.id,
    state: "finalized",
    transactionHash: "0xabc",
    tokenTotalsCommitment: `0x${"aa".repeat(32)}`,
    blockNumber: "123",
    confirmationDepth: 8,
    confirmedAt: timestamp,
  } });
  base.client.getEncryptedRecord.mockImplementation(async ({ recordId }: { recordId: string }) => ({
    record: { envelope: recordId === proofBundleId ? proofEnvelope : recordId === claimId ? claimEnvelope : subjectEnvelope },
  }));
  return base;
}

describe("proof package workflow", () => {
  it("rebuilds a proved line, creates a scoped Merkle opening, and encrypts it to the worker", async () => {
    const { issuer, grantee, client } = await fixture();
    const result = await createProofPackageForSettlement({
      client: client as never,
      organizationId,
      settlementId,
      issuerPrincipal: issuer,
      grantee,
      scope: "worker",
      workerAgreementId: agreementId,
      expiresAt: "2026-08-27T12:00:00.000Z",
      now,
    });
    expect(JSON.stringify(result.encryptedPackage)).not.toContain("250000");
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: result.encryptedPackage,
      recipient: grantee,
      currentGrant: result.grant,
      at: now,
    })).resolves.toMatchObject({
      scope: "worker",
      fileNames: expect.arrayContaining(["line-opening.json", "journal.csv", "verification.json"]),
    });
  });

  it("creates and decrypts an auditor package when the issuer is also the recipient", async () => {
    const { issuer, client, createDisclosureGrant } = await fixture();
    const result = await createProofPackageForSettlement({
      client: client as never,
      organizationId,
      settlementId,
      issuerPrincipal: issuer,
      grantee: issuer,
      scope: "auditor",
      expiresAt: "2026-08-27T12:00:00.000Z",
      now,
    });

    const grantRequest = createDisclosureGrant.mock.calls[0]?.[0];
    expect(grantRequest.envelope.wrappedKeys).toHaveLength(1);
    await expect(verifyRecipientProofPackageOffline({
      encryptedPackage: result.encryptedPackage,
      recipient: issuer,
      currentGrant: result.grant,
      at: now,
    })).resolves.toMatchObject({
      scope: "auditor",
      fileNames: expect.arrayContaining(["journal.csv", "verification.json"]),
    });
  });

  it("refuses to disclose before both on-chain verifier shards complete", async () => {
    const { issuer, grantee, client, createDisclosureGrant } = await fixture("pending");
    await expect(createProofPackageForSettlement({
      client: client as never,
      organizationId,
      settlementId,
      issuerPrincipal: issuer,
      grantee,
      scope: "worker",
      workerAgreementId: agreementId,
      expiresAt: "2026-08-27T12:00:00.000Z",
      now,
    })).rejects.toThrow(/not yet verified on-chain/i);
    expect(createDisclosureGrant).not.toHaveBeenCalled();
  });

  it.each(["wage_claim", "wage_remediation"] as const)(
    "reconstructs and recipient-encrypts a verified %s exception package",
    async (workflowType) => {
      const { issuer, grantee, client } = await exceptionFixture(workflowType);
      const result = await createProofPackageForSettlement({
        client: client as never,
        organizationId,
        settlementId,
        issuerPrincipal: issuer,
        grantee,
        scope: "worker",
        workerAgreementId: agreementId,
        expiresAt: "2026-08-27T12:00:00.000Z",
        now,
      });
      expect(result.grant.fieldScope).toContain("exception");
      expect(JSON.stringify(result.encryptedPackage)).not.toContain("250000");
      const inspection = await inspectRecipientProofPackageOffline({
        encryptedPackage: result.encryptedPackage,
        recipient: grantee,
        currentGrant: result.grant,
        at: now,
      });
      expect(inspection).toMatchObject({
        scope: "worker",
        publicInputsBinding: "verified",
        fieldScope: expect.arrayContaining(["exception", "settlement"]),
        fileNames: expect.arrayContaining(["line-opening.json", "journal.csv", "disclosure.json"]),
      });
      expect(inspection.disclosedFields.exception).toMatchObject({
        workflowType,
        claimKind: "missing_obligation",
        token: "USDC",
      });
    },
  );
});
