import { describe, expect, it } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  appendPayrollBookRoot,
  initialPayrollBookRoot,
  type PayrollBookEntry,
} from "@/lib/domain/vesting-tax";
import {
  buildPayrollIntegrityInputs,
  PAYO_NET_INVOICE_POLICY,
} from "@/lib/proof/input-builder";
import {
  buildPayrollBookReportEntry,
  createWorkerIncomeStatement,
  encryptPayrollReport,
  inspectEncryptedPayrollReport,
  verifyCompletePayrollBookReport,
  verifyWorkerIncomeStatement,
  type CompletePayrollBookReport,
  type TrustedPayrollBookSnapshot,
} from "./payroll-book-report";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(64)}`;
const ZERO = `0x${"00".repeat(32)}` as const;
const CHAIN = "0x534e5f4d41494e";
const SEAL = "0x456";
const OWNER = "0x123";
const PERIOD_START = 1_767_225_600n;
const PERIOD_END = 1_798_761_600n;
const ORGANIZATION_ID = "01991f00-0000-7000-8000-000000000001";
const TAX_REPORT_ID = "01991f00-0001-7000-8000-000000000002";
const WORKER_REPORT_ID = "01991f00-0002-7000-8000-000000000003";

async function payrollFixture(input: {
  cycleId: string;
  agreementId: string;
  recipientAddress: string;
  seed: string;
  grossAtomic: string;
  validityStart: bigint;
}) {
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
      observedAt: new Date(Number(input.validityStart - 10n) * 1_000).toISOString(),
    }],
    now: new Date(Number(input.validityStart) * 1_000),
  });
  return buildPayrollIntegrityInputs({
    chainId: CHAIN,
    sealAddress: SEAL,
    organizationSecret: hex(input.seed),
    cycleId: input.cycleId,
    revision: 1,
    validityStart: input.validityStart,
    validityExpiry: input.validityStart + 300n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [fx],
    lines: [{
      agreementId: input.agreementId,
      recipientAddress: input.recipientAddress,
      recipientSalt: hex("5"),
      agreementSalt: hex("6"),
      lineSalt: hex("7"),
      token: "STRK",
      earningsAtomic: [input.grossAtomic],
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment: hex("8"),
      dueAt: input.validityStart,
      validUntil: input.validityStart + 300n,
      classification: { declared: 2, score: 2, employeeThreshold: 5 },
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
    }],
  });
}

async function fixture() {
  const payrolls = [
    await payrollFixture({
      cycleId: "tax-book-run-1",
      agreementId: "worker-a-agreement-1",
      recipientAddress: "0x789",
      seed: "1",
      grossAtomic: "100",
      validityStart: PERIOD_START + 100n,
    }),
    await payrollFixture({
      cycleId: "tax-book-run-2",
      agreementId: "worker-b-agreement-1",
      recipientAddress: "0x987",
      seed: "2",
      grossAtomic: "250",
      validityStart: PERIOD_START + 200n,
    }),
  ];
  const bookEntries: PayrollBookEntry[] = payrolls.map((payroll) => ({
    entryVersion: "payo-payroll-book-entry-v1",
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
  }));
  const entries = [];
  for (const [index, payroll] of payrolls.entries()) {
    entries.push(await buildPayrollBookReportEntry({
      index,
      entry: bookEntries[index],
      payroll,
      policies: [PAYO_NET_INVOICE_POLICY],
      lineMetadata: {
        [payroll.proofBindings[0].agreementId]: {
          recipientReference: index === 0 ? "worker-a" : "worker-b",
          workerType: "contractor",
        },
      },
      integrityVerificationTransactionHash: `0x${(100 + index).toString(16)}`,
      settlementTransactionHash: `0x${(200 + index).toString(16)}`,
    }));
  }
  let accumulatorRoot = initialPayrollBookRoot(bookEntries[0]);
  for (const entry of entries) {
    accumulatorRoot = appendPayrollBookRoot({
      previousRoot: accumulatorRoot,
      entryCommitment: entry.entryCommitment,
      index: entry.index,
    });
  }
  const checkpoint = {
    checkpointVersion: "payo-payroll-book-checkpoint-v1" as const,
    chainId: CHAIN,
    sealAddress: SEAL,
    ownerAddress: OWNER,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    entryCount: entries.length,
    accumulatorRoot,
  };
  const report: CompletePayrollBookReport = {
    reportVersion: "payo-private-payroll-report-v1",
    reportType: "complete_payroll_book",
    reportId: TAX_REPORT_ID,
    organizationId: ORGANIZATION_ID,
    scope: "tax_authority",
    checkpoint,
    entries,
    generatedAt: "2026-09-04T00:00:00.000Z",
  };
  const trustedSnapshot: TrustedPayrollBookSnapshot = {
    snapshotVersion: "payo-trusted-payroll-book-snapshot-v1",
    checkpoint,
    entries: entries.map(({ index, entryCommitment }) => ({ index, entryCommitment })),
    observedAt: "2026-09-04T00:01:00.000Z",
    blockNumber: "1234567",
  };
  return { report, trustedSnapshot };
}

describe("private tax-authority payroll books", () => {
  it("reconstructs every private line and the independently observed on-chain book", async () => {
    const { report, trustedSnapshot } = await fixture();
    await expect(verifyCompletePayrollBookReport({ report, trustedSnapshot })).resolves.toMatchObject({
      verified: true,
      entryCount: 2,
      scope: "tax_authority",
      totals: {
        STRK: { grossAtomic: "350", deductionsAtomic: "0", netAtomic: "350" },
      },
    });
  });

  it("encrypts the full book to the authority and rejects another private key", async () => {
    const { report, trustedSnapshot } = await fixture();
    const authority = generateVaultPrincipal("tax-authority-1");
    const stranger = generateVaultPrincipal("unrelated-reviewer");
    const encryptedReport = encryptPayrollReport({ payload: report, recipients: [authority] });
    await expect(inspectEncryptedPayrollReport({
      encryptedReport,
      recipient: authority,
      trustedSnapshot,
    })).resolves.toMatchObject({
      payload: { reportType: "complete_payroll_book", scope: "tax_authority" },
      verification: { verified: true, entryCount: 2 },
    });
    await expect(inspectEncryptedPayrollReport({
      encryptedReport,
      recipient: stranger,
      trustedSnapshot,
    })).rejects.toThrow("unauthorized, tampered, or unreadable");
  });

  it("rejects an omitted entry, changed salary, and a forged trusted checkpoint", async () => {
    const { report, trustedSnapshot } = await fixture();
    const omitted = structuredClone(report);
    omitted.entries.pop();
    await expect(verifyCompletePayrollBookReport({ report: omitted, trustedSnapshot }))
      .rejects.toThrow("omits");

    const changed = structuredClone(report);
    changed.entries[0].lines[0].source.earningsAtomic[0] = "101";
    await expect(verifyCompletePayrollBookReport({ report: changed, trustedSnapshot }))
      .rejects.toThrow(/agreement leaf|statutory policy/);

    const forged = structuredClone(trustedSnapshot);
    forged.checkpoint.accumulatorRoot = hex("f");
    await expect(verifyCompletePayrollBookReport({ report, trustedSnapshot: forged }))
      .rejects.toThrow("does not reconstruct");
  });
});

describe("viewing-identity worker income statements", () => {
  it("reveals only one worker while proving each line against the complete opaque book", async () => {
    const { report, trustedSnapshot } = await fixture();
    const statement = await createWorkerIncomeStatement({
      reportId: WORKER_REPORT_ID,
      completeReport: report,
      trustedSnapshot,
      recipientAddress: "0x789",
      recipientReference: "worker-a",
      generatedAt: new Date("2026-09-04T00:02:00.000Z"),
    });
    expect(JSON.stringify(statement)).not.toContain("worker-b-agreement-1");
    await expect(verifyWorkerIncomeStatement({ statement, trustedSnapshot })).resolves.toMatchObject({
      verified: true,
      lineCount: 1,
      netTotals: { STRK: "100", USDC: "0" },
    });

    const worker = generateVaultPrincipal("worker-a-identity");
    const encrypted = encryptPayrollReport({ payload: statement, recipients: [worker] });
    await expect(inspectEncryptedPayrollReport({
      encryptedReport: encrypted,
      recipient: worker,
      trustedSnapshot,
    })).resolves.toMatchObject({
      payload: { reportType: "worker_income_statement", recipientReference: "worker-a" },
      verification: { verified: true, lineCount: 1 },
    });
  });

  it("rejects a mutated worker amount or Merkle opening", async () => {
    const { report, trustedSnapshot } = await fixture();
    const statement = await createWorkerIncomeStatement({
      reportId: WORKER_REPORT_ID,
      completeReport: report,
      trustedSnapshot,
      recipientAddress: "0x789",
      recipientReference: "worker-a",
    });
    const changed = structuredClone(statement);
    changed.lines[0].line.source.earningsAtomic[0] = "99";
    await expect(verifyWorkerIncomeStatement({ statement: changed, trustedSnapshot }))
      .rejects.toThrow(/agreement leaf|statutory policy/);

    const forgedOpening = structuredClone(statement);
    forgedOpening.lines[0].payrollOpening.siblings[0] = hex("f");
    await expect(verifyWorkerIncomeStatement({ statement: forgedOpening, trustedSnapshot }))
      .rejects.toThrow("opening");
  });
});
