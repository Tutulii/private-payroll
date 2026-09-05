import { describe, expect, it } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  appendPayrollBookRoot,
  initialPayrollBookRoot,
  payrollBookEntryCommitment,
  type PayrollBookEntry,
} from "@/lib/domain/vesting-tax";
import {
  CA_2026_SMALL_IRREGULAR_PAYMENT,
  UK_2026_27_MONTHLY_NI_CATEGORY_A,
  US_2026_SUPPLEMENTAL_FLAT,
} from "@/lib/policy/reference-packs";
import { buildPayrollIntegrityInputs } from "@/lib/proof/input-builder";
import {
  buildPayrollBookReportEntry,
  createWorkerIncomeStatement,
  type CompletePayrollBookReport,
  type TrustedPayrollBookSnapshot,
} from "./payroll-book-report";
import {
  createVerifiedIncomeEvidence,
  familiarTaxEvidenceFilename,
  renderFamiliarTaxDocuments,
  verifyFamiliarTaxDocument,
  verifyVerifiedIncomeEvidence,
} from "./tax-evidence";

const hex = (nibble: string): `0x${string}` => `0x${nibble.repeat(64)}`;
const ZERO = `0x${"00".repeat(32)}` as const;
const CHAIN = "0x534e5f4d41494e";
const SEAL = "0x456";
const OWNER = "0x123";
const ORGANIZATION_ID = "01991f00-1000-7000-8000-000000000001";
const REPORT_ID = "01991f00-1001-7000-8000-000000000002";
const WORKER_REPORT_ID = "01991f00-1002-7000-8000-000000000003";
const PERIOD_START = BigInt(Date.UTC(2026, 0, 1) / 1_000);
const PERIOD_END = BigInt(Date.UTC(2027, 0, 1) / 1_000);
const PAYDAY = BigInt(Date.UTC(2026, 6, 1) / 1_000);

async function fixture(): Promise<{
  report: CompletePayrollBookReport;
  trustedSnapshot: TrustedPayrollBookSnapshot;
}> {
  const observedAt = new Date(Number(PAYDAY - 10n) * 1_000).toISOString();
  const fx = ["USD", "GBP"].map((referenceCurrency) => buildFxSnapshot({
    baseToken: "USDC",
    referenceCurrency,
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 1,
    quotes: [{ source: `reference-${referenceCurrency.toLowerCase()}`, priceAtomic: "1000000", observedAt }],
    now: new Date(Number(PAYDAY) * 1_000),
  }));
  const policies = [
    US_2026_SUPPLEMENTAL_FLAT.pack,
    UK_2026_27_MONTHLY_NI_CATEGORY_A.pack,
    CA_2026_SMALL_IRREGULAR_PAYMENT.pack,
  ];
  const payroll = await buildPayrollIntegrityInputs({
    chainId: CHAIN,
    sealAddress: SEAL,
    organizationSecret: hex("a"),
    cycleId: "familiar-tax-evidence-2026",
    revision: 1,
    validityStart: PAYDAY,
    validityExpiry: PAYDAY + 300n,
    policies,
    fxSnapshots: fx,
    lines: [
      {
        agreementId: "us-worker-agreement",
        recipientAddress: "0x101",
        recipientSalt: hex("1"), agreementSalt: hex("2"), lineSalt: hex("3"),
        token: "USDC", earningsAtomic: ["10000"], deductionsAtomic: ["2200"],
        policyId: policies[0].id, scheduleCommitment: hex("4"), dueAt: PAYDAY,
        validUntil: PAYDAY + 300n, classification: { declared: 1, score: 6, employeeThreshold: 5 },
        fxFloorAtomic: "0", referenceCurrency: "USD",
      },
      {
        agreementId: "uk-worker-agreement",
        recipientAddress: "0x102",
        recipientSalt: hex("5"), agreementSalt: hex("6"), lineSalt: hex("7"),
        token: "USDC", earningsAtomic: ["500000"], deductionsAtomic: ["26750"],
        policyId: policies[1].id, scheduleCommitment: hex("8"), dueAt: PAYDAY,
        validUntil: PAYDAY + 300n, classification: { declared: 1, score: 6, employeeThreshold: 5 },
        fxFloorAtomic: "0", referenceCurrency: "GBP",
      },
      {
        agreementId: "ca-worker-agreement",
        recipientAddress: "0x103",
        recipientSalt: hex("9"), agreementSalt: hex("b"), lineSalt: hex("c"),
        token: "USDC", earningsAtomic: ["500000"], deductionsAtomic: ["75000"],
        policyId: policies[2].id, scheduleCommitment: hex("d"), dueAt: PAYDAY,
        validUntil: PAYDAY + 300n, classification: { declared: 1, score: 6, employeeThreshold: 5 },
        fxFloorAtomic: "0", referenceCurrency: "USD",
      },
    ],
  });
  const bookEntry: PayrollBookEntry = {
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
  };
  const entry = await buildPayrollBookReportEntry({
    index: 0,
    entry: bookEntry,
    payroll,
    policies,
    lineMetadata: {
      "us-worker-agreement": { recipientReference: "us-worker", workerType: "employee" },
      "uk-worker-agreement": { recipientReference: "uk-worker", workerType: "employee" },
      "ca-worker-agreement": { recipientReference: "ca-worker", workerType: "employee" },
    },
    integrityVerificationTransactionHash: "0x100",
    settlementTransactionHash: "0x200",
  });
  const accumulatorRoot = appendPayrollBookRoot({
    previousRoot: initialPayrollBookRoot(bookEntry),
    entryCommitment: payrollBookEntryCommitment(bookEntry),
    index: 0,
  });
  const checkpoint = {
    checkpointVersion: "payo-payroll-book-checkpoint-v1" as const,
    chainId: CHAIN,
    sealAddress: SEAL,
    ownerAddress: OWNER,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    entryCount: 1,
    accumulatorRoot,
  };
  return {
    report: {
      reportVersion: "payo-private-payroll-report-v1",
      reportType: "complete_payroll_book",
      reportId: REPORT_ID,
      organizationId: ORGANIZATION_ID,
      scope: "tax_authority",
      checkpoint,
      entries: [entry],
      generatedAt: "2027-01-02T00:00:00.000Z",
    },
    trustedSnapshot: {
      snapshotVersion: "payo-trusted-payroll-book-snapshot-v1",
      checkpoint,
      entries: [{ index: 0, entryCommitment: entry.entryCommitment }],
      observedAt: "2027-01-02T00:01:00.000Z",
      blockNumber: "1234567",
    },
  };
}

describe("canonical familiar tax evidence", () => {
  it("renders W-2-, P60- and T4-style views from one verified income schema", async () => {
    const { report, trustedSnapshot } = await fixture();
    const evidence = await createVerifiedIncomeEvidence({
      report,
      trustedSnapshot,
      generatedAt: new Date("2027-01-02T00:02:00.000Z"),
    });
    expect(verifyVerifiedIncomeEvidence(evidence)).toEqual(evidence);
    expect(evidence.coverage).toEqual({
      completeBookEntryCount: 1,
      disclosedLineCount: 3,
      mode: "complete_book",
    });
    const documents = renderFamiliarTaxDocuments(evidence);
    expect(documents.map(({ style }) => style).sort()).toEqual(["p60_style", "t4_style", "w2_style"]);
    expect(documents.map(({ title }) => title).sort()).toEqual([
      "P60-style PAYO pay evidence",
      "T4-style PAYO remuneration evidence",
      "W-2-style PAYO wage evidence",
    ]);
    for (const document of documents) {
      expect(verifyFamiliarTaxDocument({ document, evidence })).toEqual(document);
      expect(familiarTaxEvidenceFilename(document)).toMatch(/^payo-(w-2|p60|t4)-style-/);
      expect(document.policyBindings).toHaveLength(1);
      expect(document.disclaimer).toContain("not an official tax form");
    }
    expect(documents.find(({ style }) => style === "w2_style")?.fields).toEqual([
      { code: "BOX_1", label: "Wages, tips, other compensation", amountAtomic: "10000" },
      { code: "BOX_2", label: "Federal income tax withheld under bound policy", amountAtomic: "2200" },
      { code: "PAYO_NET", label: "Private net pay", amountAtomic: "7800" },
    ]);
  });

  it("lets a worker derive only their own familiar statement against the complete book", async () => {
    const { report, trustedSnapshot } = await fixture();
    const statement = await createWorkerIncomeStatement({
      reportId: WORKER_REPORT_ID,
      completeReport: report,
      trustedSnapshot,
      recipientAddress: "0x103",
      recipientReference: "ca-worker",
      generatedAt: new Date("2027-01-02T00:02:00.000Z"),
    });
    const evidence = await createVerifiedIncomeEvidence({ report: statement, trustedSnapshot });
    expect(evidence.coverage.mode).toBe("worker_lines_in_complete_book");
    const documents = renderFamiliarTaxDocuments(evidence);
    expect(documents).toHaveLength(1);
    expect(documents[0]).toMatchObject({
      style: "t4_style",
      recipientReference: "ca-worker",
      fields: [
        { amountAtomic: "500000" },
        { amountAtomic: "75000" },
        { amountAtomic: "425000" },
      ],
    });
  });

  it("rejects omission and exact-policy substitution before rendering", async () => {
    const { report, trustedSnapshot } = await fixture();
    const omitted = structuredClone(report);
    omitted.entries[0].lines.pop();
    await expect(createVerifiedIncomeEvidence({ report: omitted, trustedSnapshot }))
      .rejects.toThrow(/agreement root|manifest root|omitted/);

    const substituted = structuredClone(report);
    substituted.entries[0].policyCatalog[0].revision = 2;
    await expect(createVerifiedIncomeEvidence({ report: substituted, trustedSnapshot }))
      .rejects.toThrow(/proved root|proved catalog/);
  });

  it("rejects mutated canonical evidence and familiar documents", async () => {
    const { report, trustedSnapshot } = await fixture();
    const evidence = await createVerifiedIncomeEvidence({ report, trustedSnapshot });
    const changedEvidence = structuredClone(evidence);
    changedEvidence.lines[0].recipientReference = "somebody-else";
    expect(() => verifyVerifiedIncomeEvidence(changedEvidence)).toThrow("mutated after verification");

    const document = renderFamiliarTaxDocuments(evidence)[0];
    const changedDocument = structuredClone(document);
    changedDocument.fields[0].amountAtomic = "1";
    expect(() => verifyFamiliarTaxDocument({ document: changedDocument, evidence }))
      .toThrow("omitted, mutated, or bound to different");
  });
});
