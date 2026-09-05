import { describe, expect, it, vi } from "vitest";
import { decryptVaultRecord, encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  createReadyReportingIdentity,
  deriveDirectStrk20ReportingIdentity,
} from "@/lib/crypto/reporting-identity";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  appendPayrollBookRoot,
  initialPayrollBookRoot,
  payrollBookEntryCommitment,
} from "@/lib/domain/vesting-tax";
import {
  buildPayrollIntegrityInputsFromSerialized,
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";
import {
  inspectEncryptedPayrollReport,
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

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(64)}`;
const ZERO = hex("0");
const ORGANIZATION_ID = "01991f00-1000-7000-8000-000000000001";
const RUN_ID = "01991f00-1001-7000-8000-000000000002";
const AGREEMENT_ID = "agreement-report-worker-1";
const PAYEE_ID = "01991f00-1002-7000-8000-000000000003";
const CHAIN = "0x534e5f4d41494e";
const SEAL = "0x456";
const OWNER = "0x123";
const PERIOD_START = 1_767_225_600n;
const PERIOD_END = 1_798_761_600n;

async function fixture() {
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
  const buildInput = serializePayrollIntegrityBuildRequest({
    chainId: CHAIN,
    sealAddress: SEAL,
    organizationSecret: hex("1"),
    cycleId: "complete-book-run-1",
    revision: 1,
    validityStart,
    validityExpiry: validityStart + 300n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [fx],
    lines: [{
      agreementId: AGREEMENT_ID,
      recipientAddress: "0x789",
      recipientSalt: hex("2"),
      agreementSalt: hex("3"),
      lineSalt: hex("4"),
      token: "STRK",
      earningsAtomic: ["100"],
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment: hex("5"),
      dueAt: validityStart,
      validUntil: validityStart + 300n,
      classification: { declared: 2, score: 2, employeeThreshold: 5 },
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
    }],
  });
  const payroll = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  const bookEntry = {
    entryVersion: "payo-payroll-book-entry-v1" as const,
    chainId: CHAIN,
    sealAddress: SEAL,
    ownerAddress: OWNER,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    agreementRoot: payroll.agreementRoot,
    manifestRoot: payroll.manifestRoot,
    runNullifier: payroll.runNullifier,
    payrollProofVersion: 2,
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
  const agreements = [{
    payeeId: PAYEE_ID,
    agreement: { id: AGREEMENT_ID, classification: "contractor" },
  }] as unknown as PayAgreementDirectoryRecord[];
  const payees = [{
    id: PAYEE_ID,
    displayName: "Ada Worker",
    principalKind: "human",
    recipientAddress: "0x789",
  }] as unknown as PayeeDirectoryRecord[];
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
});
