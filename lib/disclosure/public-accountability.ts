import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { commitmentSchema, starknetAddressSchema, uuidV7Schema } from "@/lib/domain/records";
import {
  payrollBookEntryKindSchema,
  payrollBookTokenTotalsSchema,
} from "@/lib/domain/universal-payroll-book";
import {
  completePayrollBookReportSchema,
  payrollReportPayloadCommitment,
  trustedPayrollBookSnapshotSchema,
  verifyCompletePayrollBookReport,
  type CompletePayrollBookReport,
  type TrustedPayrollBookSnapshot,
} from "./payroll-book-report";

const unixSecondsSchema = z.string().regex(/^(0|[1-9]\d*)$/);
const u32Schema = z.number().int().nonnegative().max(0xffff_ffff);
const quarterSchema = z.string().regex(/^\d{4}-Q[1-4]$/);
const disclosureStateSchema = z.enum(["complete_public", "partial_public", "hidden"]);
const countCoverageSchema = z.enum(["complete_public", "partial_public", "unavailable"]);

const publicTokenTotalsSchema = z.object({
  STRK: payrollBookTokenTotalsSchema,
  USDC: payrollBookTokenTotalsSchema,
}).strict();

const accountabilityEntrySchema = z.object({
  index: u32Schema,
  entryCommitment: commitmentSchema,
  entryKind: z.union([payrollBookEntryKindSchema, z.literal("legacy_vesting")]),
  contributorPayments: z.number().int().positive().max(50).nullable(),
  totalsDisclosure: z.enum(["public", "hidden", "unavailable"]),
  publicTotals: publicTokenTotalsSchema.optional(),
  integrityVerificationTransactionHash: starknetAddressSchema,
  settlementTransactionHash: starknetAddressSchema,
}).strict().superRefine((entry, context) => {
  if ((entry.totalsDisclosure === "public") !== Boolean(entry.publicTotals)) {
    context.addIssue({
      code: "custom",
      path: ["publicTotals"],
      message: "Public entry totals must be present exactly when the on-chain entry opted into public totals.",
    });
  }
  if (entry.totalsDisclosure === "unavailable" && entry.contributorPayments !== null) {
    context.addIssue({
      code: "custom",
      path: ["contributorPayments"],
      message: "Legacy entries cannot claim a public contributor count.",
    });
  }
});
export type PublicAccountabilityEntry = z.infer<typeof accountabilityEntrySchema>;

const accountabilityQuarterSchema = z.object({
  quarter: quarterSchema,
  entryCount: z.number().int().positive(),
  contributorPayments: z.object({
    value: z.number().int().nonnegative(),
    coverage: countCoverageSchema,
    meaning: z.literal("payment_slots_not_unique_people"),
  }).strict(),
  aggregateState: disclosureStateSchema,
  publicEntryCount: z.number().int().nonnegative(),
  hiddenEntryCount: z.number().int().nonnegative(),
  legacyEntryCount: z.number().int().nonnegative(),
  publicTotals: publicTokenTotalsSchema.optional(),
  smallCohortWarning: z.boolean(),
  entries: z.array(accountabilityEntrySchema).min(1),
}).strict().superRefine((quarter, context) => {
  if (quarter.entries.length !== quarter.entryCount) {
    context.addIssue({ code: "custom", path: ["entryCount"], message: "Quarter entry count does not match its evidence entries." });
  }
  const publicEntries = quarter.entries.filter(({ totalsDisclosure }) => totalsDisclosure === "public");
  const hiddenEntries = quarter.entries.filter(({ totalsDisclosure }) => totalsDisclosure === "hidden");
  const legacyEntries = quarter.entries.filter(({ totalsDisclosure }) => totalsDisclosure === "unavailable");
  if (publicEntries.length !== quarter.publicEntryCount
    || hiddenEntries.length !== quarter.hiddenEntryCount
    || legacyEntries.length !== quarter.legacyEntryCount) {
    context.addIssue({ code: "custom", path: ["entries"], message: "Quarter disclosure counts do not match their evidence entries." });
  }
  const expectedState = publicEntries.length === 0
    ? "hidden"
    : publicEntries.length === quarter.entries.length
      ? "complete_public"
      : "partial_public";
  if (quarter.aggregateState !== expectedState) {
    context.addIssue({ code: "custom", path: ["aggregateState"], message: "Quarter aggregate state does not match its public entries." });
  }
  if ((publicEntries.length > 0) !== Boolean(quarter.publicTotals)) {
    context.addIssue({ code: "custom", path: ["publicTotals"], message: "Quarter totals must contain only the sum of opted-in public entries." });
  }

  const countedEntries = quarter.entries.filter((entry) => entry.contributorPayments !== null);
  const countedPayments = countedEntries.reduce((sum, entry) => sum + (entry.contributorPayments ?? 0), 0);
  const expectedCoverage = countedEntries.length === 0
    ? "unavailable"
    : countedEntries.length === quarter.entries.length
      ? "complete_public"
      : "partial_public";
  if (quarter.contributorPayments.value !== countedPayments
    || quarter.contributorPayments.coverage !== expectedCoverage) {
    context.addIssue({ code: "custom", path: ["contributorPayments"], message: "Quarter contributor-payment coverage does not match its public entries." });
  }
  const expectedSmallCohort = expectedCoverage === "complete_public"
    && countedPayments > 0
    && countedPayments < 5;
  if (quarter.smallCohortWarning !== expectedSmallCohort) {
    context.addIssue({ code: "custom", path: ["smallCohortWarning"], message: "Small-cohort state does not match the complete public count." });
  }

  if (quarter.publicTotals) {
    for (const token of ["STRK", "USDC"] as const) {
      const expected = publicEntries.reduce((totals, entry) => {
        const values = entry.publicTotals?.[token];
        if (!values) return totals;
        totals.gross += BigInt(values.grossAtomic);
        totals.deductions += BigInt(values.deductionsAtomic);
        totals.net += BigInt(values.netAtomic);
        return totals;
      }, { gross: 0n, deductions: 0n, net: 0n });
      const actual = quarter.publicTotals[token];
      if (BigInt(actual.grossAtomic) !== expected.gross
        || BigInt(actual.deductionsAtomic) !== expected.deductions
        || BigInt(actual.netAtomic) !== expected.net) {
        context.addIssue({ code: "custom", path: ["publicTotals", token], message: `${token} public totals do not equal the opted-in entry totals.` });
      }
    }
  }
});
export type PublicAccountabilityQuarter = z.infer<typeof accountabilityQuarterSchema>;

const publicAccountabilityCoreSchema = z.object({
  packageVersion: z.literal("payo-public-payroll-accountability-v1"),
  generatedAt: z.string().datetime(),
  source: z.object({
    reportId: uuidV7Schema,
    reportCommitment: commitmentSchema,
    organizationId: uuidV7Schema,
    reportScope: z.enum(["employer", "tax_authority"]),
    periodStart: unixSecondsSchema,
    periodEnd: unixSecondsSchema,
    entryCount: z.number().int().positive(),
    chainId: starknetAddressSchema,
    sealAddress: starknetAddressSchema,
    ownerAddress: starknetAddressSchema,
    accumulatorRoot: commitmentSchema,
    observedAt: z.string().datetime(),
    blockNumber: unixSecondsSchema,
  }).strict(),
  privacy: z.object({
    recipientDetails: z.literal("omitted"),
    contributorCountMeaning: z.literal("payment_slots_not_unique_people"),
    quarterAssignment: z.literal("derived_from_verified_proof_bound_due_dates"),
    fiatConversion: z.literal("not_included_without_verified_period_fx"),
  }).strict(),
  quarters: z.array(accountabilityQuarterSchema).min(1),
}).strict();

export const publicAccountabilitySummarySchema = publicAccountabilityCoreSchema.extend({
  summaryCommitment: commitmentSchema,
}).strict().superRefine((summary, context) => {
  const quarters = summary.quarters.map(({ quarter }) => quarter);
  if (new Set(quarters).size !== quarters.length
    || quarters.some((quarter, index) => index > 0 && quarter <= quarters[index - 1]!)) {
    context.addIssue({ code: "custom", path: ["quarters"], message: "Accountability quarters must be unique and canonically ordered." });
  }
  const entries = summary.quarters.flatMap(({ entries: quarterEntries }) => quarterEntries);
  if (entries.length !== summary.source.entryCount
    || new Set(entries.map(({ index }) => index)).size !== entries.length) {
    context.addIssue({ code: "custom", path: ["quarters"], message: "Accountability evidence must cover every payroll-book entry exactly once." });
  }
});
export type PublicAccountabilitySummary = z.infer<typeof publicAccountabilitySummarySchema>;

function quarterForUnixSeconds(value: string): string {
  const date = new Date(Number(BigInt(value)) * 1_000);
  if (Number.isNaN(date.getTime())) throw new Error("A payroll due date is outside the supported Date range.");
  return `${date.getUTCFullYear()}-Q${Math.floor(date.getUTCMonth() / 3) + 1}`;
}

function emptyTotals() {
  return {
    STRK: { grossAtomic: 0n, deductionsAtomic: 0n, netAtomic: 0n },
    USDC: { grossAtomic: 0n, deductionsAtomic: 0n, netAtomic: 0n },
  };
}

function serializeTotals(totals: ReturnType<typeof emptyTotals>) {
  return {
    STRK: {
      grossAtomic: totals.STRK.grossAtomic.toString(),
      deductionsAtomic: totals.STRK.deductionsAtomic.toString(),
      netAtomic: totals.STRK.netAtomic.toString(),
    },
    USDC: {
      grossAtomic: totals.USDC.grossAtomic.toString(),
      deductionsAtomic: totals.USDC.deductionsAtomic.toString(),
      netAtomic: totals.USDC.netAtomic.toString(),
    },
  };
}

export async function createPublicAccountabilitySummary(input: {
  report: CompletePayrollBookReport;
  trustedSnapshot: TrustedPayrollBookSnapshot;
  reportCommitment: string;
  generatedAt?: Date;
}): Promise<PublicAccountabilitySummary> {
  const report = completePayrollBookReportSchema.parse(input.report);
  const snapshot = trustedPayrollBookSnapshotSchema.parse(input.trustedSnapshot);
  const reportCommitment = commitmentSchema.parse(input.reportCommitment);
  if (reportCommitment !== payrollReportPayloadCommitment(report)) {
    throw new Error("The public-accountability report commitment does not match the verified payroll book.");
  }
  await verifyCompletePayrollBookReport({ report, trustedSnapshot: snapshot });

  const grouped = new Map<string, PublicAccountabilityEntry[]>();
  for (const reportEntry of report.entries) {
    const quarters = new Set(reportEntry.lines.map(({ source }) => quarterForUnixSeconds(source.dueAt)));
    if (quarters.size !== 1) {
      throw new Error("One payroll-book entry spans multiple quarters, so its public aggregate cannot be assigned to one quarter.");
    }
    const quarter = [...quarters][0]!;
    const quarterStartYear = Number(quarter.slice(0, 4));
    const reportStartYear = new Date(Number(BigInt(report.checkpoint.periodStart)) * 1_000).getUTCFullYear();
    const reportEnd = BigInt(report.checkpoint.periodEnd);
    const dueTimes = reportEntry.lines.map(({ source }) => BigInt(source.dueAt));
    if (quarterStartYear < reportStartYear
      || dueTimes.some((dueAt) => dueAt < BigInt(report.checkpoint.periodStart) || dueAt >= reportEnd)) {
      throw new Error("A payroll due date falls outside the selected on-chain payroll-book period.");
    }

    const onchain = reportEntry.entry;
    const evidenceEntry: PublicAccountabilityEntry = onchain.entryVersion === "payo-payroll-book-entry-v2"
      ? {
          index: reportEntry.index,
          entryCommitment: reportEntry.entryCommitment,
          entryKind: onchain.entryKind,
          contributorPayments: onchain.contributorCount,
          totalsDisclosure: onchain.totalsDisclosure,
          ...(onchain.totalsDisclosure === "public" ? { publicTotals: onchain.totals } : {}),
          integrityVerificationTransactionHash: reportEntry.integrityVerificationTransactionHash,
          settlementTransactionHash: reportEntry.settlementTransactionHash,
        }
      : {
          index: reportEntry.index,
          entryCommitment: reportEntry.entryCommitment,
          entryKind: "legacy_vesting",
          contributorPayments: null,
          totalsDisclosure: "unavailable",
          integrityVerificationTransactionHash: reportEntry.integrityVerificationTransactionHash,
          settlementTransactionHash: reportEntry.settlementTransactionHash,
        };
    grouped.set(quarter, [...(grouped.get(quarter) ?? []), accountabilityEntrySchema.parse(evidenceEntry)]);
  }

  const quarters = [...grouped.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([quarter, entries]) => {
      const publicEntries = entries.filter(({ totalsDisclosure }) => totalsDisclosure === "public");
      const hiddenEntries = entries.filter(({ totalsDisclosure }) => totalsDisclosure === "hidden");
      const legacyEntries = entries.filter(({ totalsDisclosure }) => totalsDisclosure === "unavailable");
      const countedEntries = entries.filter(({ contributorPayments }) => contributorPayments !== null);
      const contributorPayments = countedEntries.reduce((sum, entry) => sum + (entry.contributorPayments ?? 0), 0);
      const totals = emptyTotals();
      for (const entry of publicEntries) {
        for (const token of ["STRK", "USDC"] as const) {
          const values = entry.publicTotals![token];
          totals[token].grossAtomic += BigInt(values.grossAtomic);
          totals[token].deductionsAtomic += BigInt(values.deductionsAtomic);
          totals[token].netAtomic += BigInt(values.netAtomic);
        }
      }
      return accountabilityQuarterSchema.parse({
        quarter,
        entryCount: entries.length,
        contributorPayments: {
          value: contributorPayments,
          coverage: countedEntries.length === 0
            ? "unavailable"
            : countedEntries.length === entries.length
              ? "complete_public"
              : "partial_public",
          meaning: "payment_slots_not_unique_people",
        },
        aggregateState: publicEntries.length === 0
          ? "hidden"
          : publicEntries.length === entries.length
            ? "complete_public"
            : "partial_public",
        publicEntryCount: publicEntries.length,
        hiddenEntryCount: hiddenEntries.length,
        legacyEntryCount: legacyEntries.length,
        ...(publicEntries.length > 0 ? { publicTotals: serializeTotals(totals) } : {}),
        smallCohortWarning: countedEntries.length === entries.length
          && contributorPayments > 0
          && contributorPayments < 5,
        entries: [...entries].sort((left, right) => left.index - right.index),
      });
    });

  const core = publicAccountabilityCoreSchema.parse({
    packageVersion: "payo-public-payroll-accountability-v1",
    generatedAt: (input.generatedAt ?? new Date(report.generatedAt)).toISOString(),
    source: {
      reportId: report.reportId,
      reportCommitment,
      organizationId: report.organizationId,
      reportScope: report.scope,
      periodStart: report.checkpoint.periodStart,
      periodEnd: report.checkpoint.periodEnd,
      entryCount: report.entries.length,
      chainId: report.checkpoint.chainId,
      sealAddress: report.checkpoint.sealAddress,
      ownerAddress: report.checkpoint.ownerAddress,
      accumulatorRoot: report.checkpoint.accumulatorRoot,
      observedAt: snapshot.observedAt,
      blockNumber: snapshot.blockNumber,
    },
    privacy: {
      recipientDetails: "omitted",
      contributorCountMeaning: "payment_slots_not_unique_people",
      quarterAssignment: "derived_from_verified_proof_bound_due_dates",
      fiatConversion: "not_included_without_verified_period_fx",
    },
    quarters,
  });
  return publicAccountabilitySummarySchema.parse({
    ...core,
    summaryCommitment: hashCanonicalJson({
      domain: "PAYO_PUBLIC_PAYROLL_ACCOUNTABILITY_V1",
      summary: core,
    }),
  });
}

export function verifyPublicAccountabilitySummary(input: unknown): PublicAccountabilitySummary {
  const summary = publicAccountabilitySummarySchema.parse(input);
  const { summaryCommitment, ...core } = summary;
  const expected = hashCanonicalJson({
    domain: "PAYO_PUBLIC_PAYROLL_ACCOUNTABILITY_V1",
    summary: core,
  });
  if (summaryCommitment !== expected) {
    throw new Error("The public-accountability summary was mutated after verification.");
  }
  return summary;
}

export function publicAccountabilityFilename(summary: PublicAccountabilitySummary): string {
  const year = new Date(Number(BigInt(summary.source.periodStart)) * 1_000).getUTCFullYear();
  return `payo-public-accountability-${year}-${summary.summaryCommitment.slice(2, 10)}.json`;
}
