import { describe, expect, it, vi } from "vitest";
import { createPayoPublicIdentity } from "@/lib/client/proof-package-files";
import { decryptVaultRecord, encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  createReadyReportingIdentity,
  deriveDirectStrk20ReportingIdentity,
} from "@/lib/crypto/reporting-identity";
import { buildFxSnapshot } from "@/lib/domain/fx";
import { recipientReferenceResolutionSchema } from "@/lib/domain/records";
import {
  appendPayrollBookRoot,
  initialPayrollBookRoot,
  payrollBookEntryCommitment,
} from "@/lib/domain/vesting-tax";
import {
  derivePayrollBookTotalsSalt,
  payrollBookTotalsCommitment,
} from "@/lib/domain/universal-payroll-book";
import {
  buildPayrollIntegrityInputsFromSerialized,
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";
import {
  inspectEncryptedPayrollReport,
  verifyCompletePayrollBookReport,
  type TrustedPayrollBookSnapshot,
} from "@/lib/disclosure/payroll-book-report";
import {
  createEncryptedWorkerStatementSource,
  generateWorkerIncomeStatementFromSource,
  workerStatementSourceFilename,
} from "@/lib/disclosure/worker-statement-source";
import type { PayAgreementDirectoryRecord } from "./agreement-directory";
import type { PayeeDirectoryRecord } from "./payee-directory";
import {
  createEncryptedPayrollReportFromBook,
  createWorkerStatementSourceFromBook,
  generateWorkerStatementAgainstLiveBook,
  inspectPayrollReportAgainstLiveBook,
  payrollReportFilename,
} from "./payroll-report-workflow";
import { openWorkerPayrollEvidenceAgainstLiveBook } from "./worker-payroll-evidence";
import {
  createAuthorityReadinessEvidence,
  verifyAuthorityReadinessEvidence,
} from "@/lib/disclosure/authority-readiness";
import { verifyPublicAccountabilitySummary } from "@/lib/disclosure/public-accountability";
import { US_2026_SUPPLEMENTAL_FLAT } from "@/lib/policy/reference-packs";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(64)}`;
const ZERO = hex("0");
const ORGANIZATION_ID = "01991f00-1000-7000-8000-000000000001";
const RUN_ID = "01991f00-1001-7000-8000-000000000002";
const AGREEMENT_ID = "agreement-report-worker-1";
const PAYEE_ID = "01991f00-1002-7000-8000-000000000003";
const CONFLICTING_AGREEMENT_ID = "agreement-report-worker-legacy-alias";
const CONFLICTING_PAYEE_ID = "01991f00-1003-7000-8000-000000000004";
const CHAIN = "0x534e5f4d41494e";
const SEAL = "0x456";
const OWNER = "0x123";
const PERIOD_START = 1_767_225_600n;
const PERIOD_END = 1_798_761_600n;

async function fixture(input: {
  totalsDisclosure?: "public" | "hidden";
  conflictingRecipientReferences?: boolean;
} = {}) {
  const employer = generateVaultPrincipal("employer-report-principal");
  const worker = generateVaultPrincipal("worker-report-principal");
  const stranger = generateVaultPrincipal("stranger-report-principal");
  const validityStart = PERIOD_START + 100n;
  const fx = buildFxSnapshot({
    baseToken: "STRK",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    aggregatedSourceCount: 3,
    quotes: [{
      source: "pragma-strk",
      priceAtomic: "100000",
      observedAt: new Date(Number(validityStart - 10n) * 1_000).toISOString(),
    }],
    now: new Date(Number(validityStart) * 1_000),
  });
  const conflictingRecipientReferences = input.conflictingRecipientReferences ?? false;
  const policy = conflictingRecipientReferences
    ? US_2026_SUPPLEMENTAL_FLAT.pack
    : PAYO_NET_INVOICE_POLICY;
  const lines = conflictingRecipientReferences
    ? [{
        agreementId: AGREEMENT_ID,
        recipientAddress: "0x789",
        recipientSalt: hex("2"),
        agreementSalt: hex("3"),
        lineSalt: hex("4"),
        token: "STRK" as const,
        earningsAtomic: ["100"],
        deductionsAtomic: ["22"],
        policyId: policy.id,
        scheduleCommitment: hex("5"),
        dueAt: validityStart,
        validUntil: validityStart + 300n,
        classification: { declared: 1 as const, score: 5, employeeThreshold: 5 },
        fxFloorAtomic: "0",
        referenceCurrency: "USD" as const,
      }, {
        agreementId: CONFLICTING_AGREEMENT_ID,
        recipientAddress: "0x789",
        recipientSalt: hex("6"),
        agreementSalt: hex("7"),
        lineSalt: hex("8"),
        token: "STRK" as const,
        earningsAtomic: ["100"],
        deductionsAtomic: ["22"],
        policyId: policy.id,
        scheduleCommitment: hex("9"),
        dueAt: validityStart,
        validUntil: validityStart + 300n,
        classification: { declared: 1 as const, score: 5, employeeThreshold: 5 },
        fxFloorAtomic: "0",
        referenceCurrency: "USD" as const,
      }]
    : [{
        agreementId: AGREEMENT_ID,
        recipientAddress: "0x789",
        recipientSalt: hex("2"),
        agreementSalt: hex("3"),
        lineSalt: hex("4"),
        token: "STRK" as const,
        earningsAtomic: ["100"],
        deductionsAtomic: [],
        policyId: policy.id,
        scheduleCommitment: hex("5"),
        dueAt: validityStart,
        validUntil: validityStart + 300n,
        classification: { declared: 2 as const, score: 2, employeeThreshold: 5 },
        fxFloorAtomic: "0",
        referenceCurrency: "USD" as const,
      }];
  const buildInput = serializePayrollIntegrityBuildRequest({
    chainId: CHAIN,
    sealAddress: SEAL,
    organizationSecret: hex("1"),
    cycleId: "complete-book-run-1",
    revision: 1,
    validityStart,
    validityExpiry: validityStart + 300n,
    policies: [policy],
    fxSnapshots: [fx],
    lines,
  });
  const payroll = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  const totals = {
    STRK: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
    USDC: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
  };
  for (const line of payroll.calculatedLines) {
    const tokenTotals = totals[line.token];
    tokenTotals.grossAtomic = (BigInt(tokenTotals.grossAtomic) + BigInt(line.grossAtomic)).toString();
    tokenTotals.deductionsAtomic = (BigInt(tokenTotals.deductionsAtomic) + BigInt(line.deductionsTotalAtomic)).toString();
    tokenTotals.netAtomic = (BigInt(tokenTotals.netAtomic) + BigInt(line.netAtomic)).toString();
  }
  const totalsSalt = derivePayrollBookTotalsSalt({
    organizationSecret: hex("1"),
    runNullifier: payroll.runNullifier,
  });
  const totalsDisclosure = input.totalsDisclosure ?? "public";
  const publicTotals = totalsDisclosure === "public"
    ? totals
    : {
        STRK: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
        USDC: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
      };
  const bookEntry = {
    entryVersion: "payo-payroll-book-entry-v2" as const,
    entryKind: "ordinary" as const,
    chainId: CHAIN,
    sealAddress: SEAL,
    sourceSealAddress: SEAL,
    ownerAddress: OWNER,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    agreementRoot: payroll.agreementRoot,
    manifestRoot: payroll.manifestRoot,
    policyRoot: payroll.policyRoot,
    fxRoot: payroll.fxRoot,
    runNullifier: payroll.runNullifier,
    subjectNullifier: payroll.runNullifier,
    parentFactCommitment: ZERO,
    factCommitment: ZERO,
    sourceProofVersion: 2,
    attestationRoot: ZERO,
    contributorCount: lines.length,
    totalsDisclosure,
    totalsCommitment: payrollBookTotalsCommitment({
      subjectNullifier: payroll.runNullifier,
      contributorCount: lines.length,
      totals,
      salt: totalsSalt,
    }),
    totals: publicTotals,
    vestingScheduleId: ZERO,
    vestingStateCommitment: ZERO,
  };
  const entryCommitment = payrollBookEntryCommitment(bookEntry);
  const checkpoint = {
    checkpointVersion: "payo-payroll-book-checkpoint-v1" as const,
    chainId: CHAIN,
    sealAddress: SEAL,
    ownerAddress: OWNER,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    entryCount: 1,
    accumulatorRoot: appendPayrollBookRoot({
      previousRoot: initialPayrollBookRoot(bookEntry),
      entryCommitment,
      index: 0,
    }),
  };
  const snapshot: TrustedPayrollBookSnapshot = {
    snapshotVersion: "payo-trusted-payroll-book-snapshot-v1",
    checkpoint,
    entries: [{ index: 0, entryCommitment }],
    observedAt: "2026-09-04T00:01:00.000Z",
    blockNumber: "1234",
  };
  const runEnvelope = encryptVaultRecord({
    schemaVersion: 1,
    agreementRoot: payroll.agreementRoot,
    manifestRoot: payroll.manifestRoot,
    policyRoot: payroll.policyRoot,
    fxRoot: payroll.fxRoot,
    runNullifier: payroll.runNullifier,
    claimProofSource: { buildInput },
  }, {
    schemaVersion: 1,
    organizationId: ORGANIZATION_ID,
    recordType: "payroll-run",
    recordId: RUN_ID,
    revision: 1,
  }, [employer]);
  const source = {
    runId: RUN_ID,
    runRevision: 1,
    runEnvelope,
    entryKind: "ordinary" as const,
    bookEntry,
    bookEntryCommitment: entryCommitment,
    integrityVerificationTransactionHash: "0xabc",
    settlementTransactionHash: "0xdef",
  };
  const client = {
    getPayrollBookSnapshot: vi.fn().mockResolvedValue({ snapshot }),
    getPayrollBookSources: vi.fn().mockResolvedValue({ sources: [source] }),
  };
  const agreements = (conflictingRecipientReferences ? [{
    payeeId: PAYEE_ID,
    agreement: { id: AGREEMENT_ID, classification: "employee" },
  }, {
    payeeId: CONFLICTING_PAYEE_ID,
    agreement: { id: CONFLICTING_AGREEMENT_ID, classification: "employee" },
  }] : [{
    payeeId: PAYEE_ID,
    agreement: { id: AGREEMENT_ID, classification: "contractor" },
  }]) as unknown as PayAgreementDirectoryRecord[];
  const payees = (conflictingRecipientReferences ? [{
    id: PAYEE_ID,
    displayName: "Ada Worker",
    principalKind: "human",
    recipientAddress: "0x789",
  }, {
    id: CONFLICTING_PAYEE_ID,
    displayName: "Ada Former Reference",
    principalKind: "human",
    recipientAddress: "0x789",
  }] : [{
    id: PAYEE_ID,
    displayName: "Ada Worker",
    principalKind: "human",
    recipientAddress: "0x789",
  }]) as unknown as PayeeDirectoryRecord[];
  return { employer, worker, stranger, client, agreements, payees, source, snapshot };
}

describe("complete private payroll report workflow", () => {
  it("rebuilds every encrypted run and exports an employer book bound to the live accumulator", async () => {
    const data = await fixture();
    const result = await createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.employer,
      kind: "employer_book",
      agreements: data.agreements,
      payees: data.payees,
      now: new Date("2026-09-04T01:00:00.000Z"),
    });
    expect(result.verification).toMatchObject({ verified: true, entryCount: 1 });
    expect(result.verifiedIncomeEvidence).toMatchObject({
      evidenceVersion: "payo-verified-income-evidence-v1",
      taxYear: 2026,
      coverage: { completeBookEntryCount: 1, disclosedLineCount: 1, mode: "complete_book" },
    });
    expect(result.familiarTaxDocuments).toEqual([]);
    const accountability = result.publicAccountabilitySummary;
    if (!accountability) throw new Error("Expected public-accountability evidence.");
    expect(accountability).toMatchObject({
      packageVersion: "payo-public-payroll-accountability-v1",
      source: { entryCount: 1, accumulatorRoot: data.snapshot.checkpoint.accumulatorRoot },
      privacy: {
        recipientDetails: "omitted",
        contributorCountMeaning: "payment_slots_not_unique_people",
        fiatConversion: "not_included_without_verified_period_fx",
      },
      quarters: [{
        quarter: "2026-Q1",
        contributorPayments: { value: 1, coverage: "complete_public" },
        aggregateState: "complete_public",
        publicTotals: { STRK: { grossAtomic: "100", netAtomic: "100" } },
        smallCohortWarning: true,
      }],
    });
    expect(verifyPublicAccountabilitySummary(accountability)).toEqual(accountability);
    expect(JSON.stringify(accountability)).not.toContain("Ada Worker");
    expect(JSON.stringify(accountability)).not.toContain('"0x789"');
    const mutatedSummary = structuredClone(accountability);
    mutatedSummary.generatedAt = "2026-09-04T01:00:01.000Z";
    expect(() => verifyPublicAccountabilitySummary(mutatedSummary)).toThrow(/mutated after verification/i);
    await expect(inspectPayrollReportAgainstLiveBook({
      client: data.client as never,
      encryptedReport: result.encryptedReport,
      recipient: data.employer,
    })).resolves.toMatchObject({
      verification: { verified: true, totals: { STRK: { netAtomic: "100" } } },
    });
    expect(payrollReportFilename(result.encryptedReport, { year: 2026 }))
      .toMatch(/^payo-complete-payroll-book-2026-/);
  });

  it("never derives or guesses totals for a hidden on-chain aggregate", async () => {
    const data = await fixture({ totalsDisclosure: "hidden" });
    const result = await createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.employer,
      kind: "employer_book",
      agreements: data.agreements,
      payees: data.payees,
      now: new Date("2026-09-04T01:15:00.000Z"),
    });
    const accountability = result.publicAccountabilitySummary;
    if (!accountability) throw new Error("Expected hidden public-accountability evidence.");
    expect(accountability.quarters[0]).toMatchObject({
      contributorPayments: { value: 1, coverage: "complete_public" },
      aggregateState: "hidden",
      publicEntryCount: 0,
      hiddenEntryCount: 1,
    });
    expect(accountability.quarters[0]).not.toHaveProperty("publicTotals");
    expect(JSON.stringify(accountability)).not.toContain('"grossAtomic":"100"');
  });

  it("creates a committed government-integration-ready export only for the bound reviewer", async () => {
    const data = await fixture();
    const recipientIdentity = createPayoPublicIdentity(
      data.worker,
      new Date("2026-09-04T01:29:00.000Z"),
    );
    const recipientBinding = {
      principalId: recipientIdentity.principalId,
      identityFingerprint: recipientIdentity.fingerprint,
    };
    const result = await createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.worker,
      recipientIdentities: [recipientIdentity],
      kind: "tax_book",
      agreements: data.agreements,
      payees: data.payees,
      now: new Date("2026-09-04T01:30:00.000Z"),
    });
    if (!("authorityReadinessEvidence" in result) || !result.authorityReadinessEvidence) {
      throw new Error("Expected authority-readiness evidence.");
    }
    const evidence = result.authorityReadinessEvidence;
    expect(evidence).toMatchObject({
      packageVersion: "payo-authority-readiness-evidence-v1",
      readinessState: "verified_evidence",
      filingState: "exported_not_submitted",
      source: { recipients: [recipientBinding] },
      coverage: { mode: "complete_selected_onchain_book", entryCount: 1, lineCount: 1 },
      chainEvidence: { blockNumber: "1234" },
    });
    expect(verifyAuthorityReadinessEvidence(evidence)).toEqual(evidence);

    const mutated = structuredClone(evidence);
    mutated.coverage.lineCount += 1;
    expect(() => verifyAuthorityReadinessEvidence(mutated)).toThrow(/mutated after verification/i);

    if (result.payload.reportType !== "complete_payroll_book") throw new Error("Expected a complete report.");
    await expect(createAuthorityReadinessEvidence({
      report: result.payload,
      trustedSnapshot: data.snapshot,
      reportCommitment: result.encryptedReport.packageCommitment,
      recipients: [{ ...recipientBinding, identityFingerprint: hex("8") }],
    })).rejects.toThrow(/recipient identities differ/i);
  });

  it("delivers the complete reviewer book while withholding readiness evidence for conflicting references", async () => {
    const data = await fixture({ conflictingRecipientReferences: true });
    const recipientIdentity = createPayoPublicIdentity(
      data.worker,
      new Date("2026-09-04T01:34:00.000Z"),
    );
    const result = await createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.worker,
      recipientIdentities: [recipientIdentity],
      kind: "tax_book",
      agreements: data.agreements,
      payees: data.payees,
      now: new Date("2026-09-04T01:35:00.000Z"),
    });

    expect(result.verification).toMatchObject({ verified: true, entryCount: 1 });
    expect(result.encryptedReport.envelope.wrappedKeys).toEqual([
      expect.objectContaining({ principalId: data.worker.principalId }),
    ]);
    expect(result.familiarTaxDocuments).toEqual([]);
    expect(result.familiarTaxIssues).toEqual([expect.objectContaining({
      code: "conflicting_recipient_references",
      recipientAddress: "0x789",
      recipientReferences: ["Ada Former Reference", "Ada Worker"],
    })]);
    expect("authorityReadinessEvidence" in result).toBe(true);
    if (!("authorityReadinessEvidence" in result)) {
      throw new Error("Expected a complete reviewer-book result.");
    }
    expect(result.authorityReadinessEvidence).toBeUndefined();

    await expect(inspectPayrollReportAgainstLiveBook({
      client: data.client as never,
      encryptedReport: result.encryptedReport,
      recipient: data.worker,
    })).resolves.toMatchObject({
      verification: { verified: true, entryCount: 1 },
      authorityReadinessEvidence: undefined,
      familiarTaxIssues: [expect.objectContaining({
        code: "conflicting_recipient_references",
        recipientReferences: ["Ada Former Reference", "Ada Worker"],
      })],
    });
  });

  it("creates readable and readiness evidence after an audited historical reference resolution", async () => {
    const data = await fixture({ conflictingRecipientReferences: true });
    const recipientIdentity = createPayoPublicIdentity(
      data.worker,
      new Date("2026-09-04T01:36:00.000Z"),
    );
    const resolution = recipientReferenceResolutionSchema.parse({
      resolutionVersion: "payo-recipient-reference-resolution-v1",
      resolutionId: "01991f00-2000-7000-8000-000000000005",
      recipientAddress: "0x789",
      canonicalReference: "Ada Worker",
      historicalReferences: ["Ada Former Reference", "Ada Worker"],
      resolvedAt: "2026-09-04T01:35:30.000Z",
    });
    const payees = data.payees.map((payee) => ({
      ...payee,
      displayName: "Ada Worker",
      recipientReferenceResolution: resolution,
    }));
    const result = await createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.worker,
      recipientIdentities: [recipientIdentity],
      kind: "tax_book",
      agreements: data.agreements,
      payees,
      now: new Date("2026-09-04T01:37:00.000Z"),
    });

    expect(result.familiarTaxIssues).toEqual([]);
    expect(result.familiarTaxDocuments).toEqual([expect.objectContaining({
      recipientReference: "Ada Worker",
      sourceLineCount: 2,
      fields: expect.arrayContaining([
        expect.objectContaining({ code: "BOX_1", amountAtomic: "200" }),
        expect.objectContaining({ code: "BOX_2", amountAtomic: "44" }),
        expect.objectContaining({ code: "PAYO_NET", amountAtomic: "156" }),
      ]),
    })]);
    expect(result.payload).toMatchObject({
      entries: [{
        lines: [
          { recipientReference: "Ada Worker", recipientReferenceResolution: resolution },
          { recipientReference: "Ada Worker", recipientReferenceResolution: resolution },
        ],
      }],
    });
    expect("authorityReadinessEvidence" in result
      ? result.authorityReadinessEvidence
      : undefined).toMatchObject({
      readinessState: "verified_evidence",
      coverage: { familiarDocumentCount: 1, familiarDocumentIssueCount: 0 },
      recipientReferenceResolutions: [resolution],
    });
    await expect(inspectPayrollReportAgainstLiveBook({
      client: data.client as never,
      encryptedReport: result.encryptedReport,
      recipient: data.worker,
    })).resolves.toMatchObject({
      familiarTaxIssues: [],
      familiarTaxDocuments: [expect.objectContaining({ sourceLineCount: 2 })],
      authorityReadinessEvidence: expect.objectContaining({
        recipientReferenceResolutions: [resolution],
      }),
    });

    if (result.payload.reportType !== "complete_payroll_book") throw new Error("Expected complete book.");
    const inconsistent = structuredClone(result.payload);
    inconsistent.entries[0].lines[1].recipientReferenceResolution!.resolutionId =
      "01991f00-2001-7000-8000-000000000006";
    await expect(verifyCompletePayrollBookReport({
      report: inconsistent,
      trustedSnapshot: data.snapshot,
    })).rejects.toThrow(/inconsistent reference resolutions/i);
  });

  it("encrypts one complete book to multiple verified committee identities", async () => {
    const data = await fixture();
    const primaryIdentity = createPayoPublicIdentity(
      data.worker,
      new Date("2026-09-04T01:39:00.000Z"),
    );
    const committeeIdentity = createPayoPublicIdentity(
      data.stranger,
      new Date("2026-09-04T01:39:30.000Z"),
    );
    const input = {
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.worker,
      recipientIdentities: [primaryIdentity, committeeIdentity],
      kind: "tax_book" as const,
      agreements: data.agreements,
      payees: data.payees,
      now: new Date("2026-09-04T01:40:00.000Z"),
    };
    const result = await createEncryptedPayrollReportFromBook(input);
    expect(result.encryptedReport.envelope.wrappedKeys.map(({ principalId }) => principalId).sort())
      .toEqual([data.worker.principalId, data.stranger.principalId].sort());
    expect(result.payload).toMatchObject({
      scope: "tax_authority",
      recipientIdentities: [
        { principalId: primaryIdentity.principalId, identityFingerprint: primaryIdentity.fingerprint },
        { principalId: committeeIdentity.principalId, identityFingerprint: committeeIdentity.fingerprint },
      ],
    });
    if (!("authorityReadinessEvidence" in result) || !result.authorityReadinessEvidence) {
      throw new Error("Expected committee readiness evidence.");
    }
    expect(result.authorityReadinessEvidence).toMatchObject({
      source: { recipients: expect.arrayContaining([
        { principalId: primaryIdentity.principalId, identityFingerprint: primaryIdentity.fingerprint },
        { principalId: committeeIdentity.principalId, identityFingerprint: committeeIdentity.fingerprint },
      ]) },
      claimCoverage: { audience: "governance_committee" },
    });
    await expect(inspectEncryptedPayrollReport({
      encryptedReport: result.encryptedReport,
      recipient: data.worker,
      trustedSnapshot: data.snapshot,
    })).resolves.toMatchObject({ verification: { verified: true } });
    await expect(inspectEncryptedPayrollReport({
      encryptedReport: result.encryptedReport,
      recipient: data.stranger,
      trustedSnapshot: data.snapshot,
    })).resolves.toMatchObject({ verification: { verified: true } });

    await expect(createEncryptedPayrollReportFromBook({
      ...input,
      recipientIdentities: [primaryIdentity, primaryIdentity],
    })).rejects.toThrow(/unique principals, encryption keys and fingerprints/i);
    await expect(createEncryptedPayrollReportFromBook({
      ...input,
      recipientIdentities: [primaryIdentity, { ...committeeIdentity, fingerprint: hex("f") }],
    })).rejects.toThrow(/fingerprint is invalid/i);
    await expect(createEncryptedPayrollReportFromBook({
      ...input,
      recipientIdentities: [committeeIdentity, primaryIdentity],
    })).rejects.toThrow(/primary reviewer identity does not match/i);
  });

  it("lets a direct STRK20 holder independently generate the final worker statement", async () => {
    const data = await fixture();
    const direct = deriveDirectStrk20ReportingIdentity({
      viewingKey: "0x123456",
      context: { chainId: CHAIN, poolAddress: "0x987", recipientAddress: "0x789" },
      createdAt: new Date("2026-09-04T02:00:00.000Z"),
    });
    const source = await createWorkerStatementSourceFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipientIdentity: direct.identity,
      agreements: data.agreements,
      payees: data.payees,
      workerPayeeId: PAYEE_ID,
      now: new Date("2026-09-04T02:01:00.000Z"),
    });
    const encryptedSource = source.encryptedSource;
    expect(JSON.stringify(encryptedSource)).not.toContain("123456");
    const generated = await generateWorkerStatementAgainstLiveBook({
      client: data.client as never,
      encryptedSource,
      recipient: direct.principal,
      now: new Date("2026-09-04T03:00:00.000Z"),
    });
    expect(generated).toMatchObject({
      statement: {
        reportType: "worker_income_statement",
        recipientAddress: "0x789",
        recipientReference: "Ada Worker",
        generatedAt: "2026-09-04T03:00:00.000Z",
      },
      verification: { verified: true, lineCount: 1, netTotals: { STRK: "100" } },
      recipientIdentity: { mode: "direct_strk20_viewing_key" },
      verifiedIncomeEvidence: {
        taxYear: 2026,
        coverage: { completeBookEntryCount: 1, disclosedLineCount: 1, mode: "worker_lines_in_complete_book" },
      },
      familiarTaxDocuments: [],
    });
    await expect(inspectEncryptedPayrollReport({
      encryptedReport: generated.encryptedReport,
      recipient: direct.principal,
      trustedSnapshot: data.snapshot,
    })).resolves.toMatchObject({ verification: { verified: true, lineCount: 1 } });
    await expect(openWorkerPayrollEvidenceAgainstLiveBook({
      client: data.client as never,
      value: encryptedSource,
      sourceFilename: "worker-source.json",
      recipients: [
        { principal: data.stranger },
        { principal: direct.principal, identityFingerprint: direct.identity.fingerprint },
      ],
      now: new Date("2026-09-04T03:01:00.000Z"),
    })).resolves.toMatchObject({
      kind: "source",
      recipientPrincipalId: direct.principal.principalId,
      statement: { recipientReference: "Ada Worker" },
      verification: { verified: true, lineCount: 1 },
    });
    await expect(openWorkerPayrollEvidenceAgainstLiveBook({
      client: data.client as never,
      value: generated.encryptedReport,
      sourceFilename: "worker-report.json",
      recipients: [{ principal: direct.principal }],
    })).resolves.toMatchObject({
      kind: "report",
      statement: { reportType: "worker_income_statement" },
      verification: { verified: true, lineCount: 1 },
    });
    expect(workerStatementSourceFilename({ encryptedSource, recipientReference: "Ada Worker", year: 2026 }))
      .toMatch(/^payo-worker-statement-source-ada-worker-2026-/);

    const stranger = deriveDirectStrk20ReportingIdentity({
      viewingKey: "0x123457",
      context: direct.identity.context,
    });
    await expect(generateWorkerStatementAgainstLiveBook({
      client: data.client as never,
      encryptedSource,
      recipient: stranger.principal,
    })).rejects.toThrow(/unauthorized, tampered, or unreadable/i);
    await expect(openWorkerPayrollEvidenceAgainstLiveBook({
      client: data.client as never,
      value: encryptedSource,
      sourceFilename: "worker-source.json",
      recipients: [{ principal: stranger.principal }],
    })).rejects.toThrow(/belongs to another PAYO identity/i);
  });

  it("keeps Ready on an explicit PAYO-X25519 fallback and rejects recipient rebinding", async () => {
    const data = await fixture();
    const complete = await createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.employer,
      kind: "employer_book",
      agreements: data.agreements,
      payees: data.payees,
    });
    if (complete.payload.reportType !== "complete_payroll_book") throw new Error("Expected a complete book.");
    const ready = createReadyReportingIdentity({
      principal: data.worker,
      context: { chainId: CHAIN, poolAddress: "0x987", recipientAddress: "0x789" },
    });
    const encryptedSource = await createEncryptedWorkerStatementSource({
      completeReport: complete.payload,
      trustedSnapshot: data.snapshot,
      recipientAddress: "0x789",
      recipientReference: "Ada Worker",
      recipientIdentity: ready.identity,
    });
    await expect(generateWorkerIncomeStatementFromSource({
      encryptedSource,
      recipient: data.worker,
      trustedSnapshot: data.snapshot,
    })).resolves.toMatchObject({
      verification: { verified: true },
      recipientIdentity: {
        mode: "ready_payo_x25519",
        readyViewingKeyAccess: "not_available",
      },
    });
    await expect(createEncryptedWorkerStatementSource({
      completeReport: complete.payload,
      trustedSnapshot: data.snapshot,
      recipientAddress: "0x790",
      recipientReference: "Another Worker",
      recipientIdentity: ready.identity,
    })).rejects.toThrow(/another STRK20 recipient/i);

    const changed = { ...encryptedSource, sourceCommitment: hex("f") };
    await expect(generateWorkerIncomeStatementFromSource({
      encryptedSource: changed,
      recipient: data.worker,
      trustedSnapshot: data.snapshot,
    })).rejects.toThrow(/commitment or recipient binding/i);
  });

  it("creates a worker-only statement and encrypts it only to the worker identity", async () => {
    const data = await fixture();
    const result = await createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.worker,
      kind: "worker_statement",
      workerPayeeId: PAYEE_ID,
      agreements: data.agreements,
      payees: data.payees,
    });
    expect(result.payload).toMatchObject({
      reportType: "worker_income_statement",
      recipientReference: "Ada Worker",
    });
    await expect(inspectEncryptedPayrollReport({
      encryptedReport: result.encryptedReport,
      recipient: data.worker,
      trustedSnapshot: data.snapshot,
    })).resolves.toMatchObject({ verification: { verified: true, lineCount: 1 } });
    await expect(inspectEncryptedPayrollReport({
      encryptedReport: result.encryptedReport,
      recipient: data.stranger,
      trustedSnapshot: data.snapshot,
    })).rejects.toThrow("unauthorized, tampered, or unreadable");
  });

  it("keeps complete employer and reviewer books out of My Pay", async () => {
    const data = await fixture();
    for (const kind of ["employer_book", "tax_book"] as const) {
      const complete = await createEncryptedPayrollReportFromBook({
        client: data.client as never,
        organizationId: ORGANIZATION_ID,
        ownerAddress: OWNER,
        periodStart: PERIOD_START.toString(),
        periodEnd: PERIOD_END.toString(),
        principal: data.employer,
        recipient: data.worker,
        recipientIdentities: kind === "tax_book"
          ? [createPayoPublicIdentity(data.worker)]
          : undefined,
        kind,
        agreements: data.agreements,
        payees: data.payees,
      });
      await expect(openWorkerPayrollEvidenceAgainstLiveBook({
        client: data.client as never,
        value: complete.encryptedReport,
        sourceFilename: `${kind}.json`,
        recipients: [{ principal: data.worker }],
      })).rejects.toThrow(/My Pay opens worker evidence only/i);
    }
  });

  it("fails closed when an on-chain entry is omitted or its encrypted roots change", async () => {
    const data = await fixture();
    data.client.getPayrollBookSources.mockResolvedValueOnce({ sources: [] });
    await expect(createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.employer,
      kind: "tax_book",
      agreements: data.agreements,
      payees: data.payees,
    })).rejects.toThrow("entry 1");

    const changed = structuredClone(data.source);
    changed.runEnvelope = encryptVaultRecord({
      schemaVersion: 1,
      agreementRoot: hex("f"),
      manifestRoot: changed.bookEntry.manifestRoot,
      policyRoot: hex("e"),
      fxRoot: hex("d"),
      runNullifier: changed.bookEntry.runNullifier,
      claimProofSource: {
        buildInput: (decryptVaultRecord(
          data.source.runEnvelope,
          data.employer,
        ) as { claimProofSource: { buildInput: unknown } }).claimProofSource.buildInput,
      },
    }, changed.runEnvelope.aad, [data.employer]);
    data.client.getPayrollBookSources.mockResolvedValueOnce({ sources: [changed] });
    await expect(createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.employer,
      kind: "employer_book",
      agreements: data.agreements,
      payees: data.payees,
    })).rejects.toThrow("changed agreement commitment");
  });

  it("fails closed when universal v2 book bindings differ from the proved payroll", async () => {
    const data = await fixture();
    const changedPolicy = structuredClone(data.source);
    changedPolicy.bookEntry.policyRoot = hex("f");
    data.client.getPayrollBookSources.mockResolvedValueOnce({ sources: [changedPolicy] });
    await expect(createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.employer,
      kind: "employer_book",
      agreements: data.agreements,
      payees: data.payees,
    })).rejects.toThrow("differs from its proved payroll bindings");

    const changedTotals = structuredClone(data.source);
    changedTotals.bookEntry.totals.STRK.grossAtomic = "101";
    changedTotals.bookEntry.totals.STRK.netAtomic = "101";
    data.client.getPayrollBookSources.mockResolvedValueOnce({ sources: [changedTotals] });
    await expect(createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.employer,
      kind: "tax_book",
      agreements: data.agreements,
      payees: data.payees,
    })).rejects.toThrow("STRK totals differ from the proved payroll");

    const changedKind = {
      ...structuredClone(data.source),
      entryKind: "agent" as const,
    };
    data.client.getPayrollBookSources.mockResolvedValueOnce({ sources: [changedKind] });
    await expect(createEncryptedPayrollReportFromBook({
      client: data.client as never,
      organizationId: ORGANIZATION_ID,
      ownerAddress: OWNER,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      principal: data.employer,
      recipient: data.employer,
      kind: "worker_statement",
      workerPayeeId: PAYEE_ID,
      agreements: data.agreements,
      payees: data.payees,
    })).rejects.toThrow("differs from its universal payroll-book entry");
  });
});
