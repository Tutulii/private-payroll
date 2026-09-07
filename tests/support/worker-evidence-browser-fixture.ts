import { encryptVaultRecord, generateVaultPrincipal, type VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { createReadyReportingIdentity } from "@/lib/crypto/reporting-identity";
import { buildFxSnapshot } from "@/lib/domain/fx";
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
import type { TrustedPayrollBookSnapshot } from "@/lib/disclosure/payroll-book-report";
import { createEncryptedPayrollReportFromBook, createWorkerStatementSourceFromBook } from "@/lib/client/payroll-report-workflow";
import type { PayAgreementDirectoryRecord } from "@/lib/client/agreement-directory";
import type { PayeeDirectoryRecord } from "@/lib/client/payee-directory";
import { STRK20_MAINNET_POOL_ADDRESS } from "@/lib/starknet/deployment";
import { createPayoPublicIdentity } from "@/lib/client/proof-package-files";

const ORGANIZATION_ID = "018f1000-0000-7000-8000-000000000030";
const RUN_ID = "018f1000-0000-7000-8000-000000000081";
const AGREEMENT_ID = "browser-my-pay-agreement";
const PAYEE_ID = "018f1000-0000-7000-8000-000000000082";
const CHAIN_ID = "0x534e5f4d41494e";
const SEAL_ADDRESS = "0x123";
const OWNER_ADDRESS = "0x456";
const RECIPIENT_ADDRESS = "0x789";
const PERIOD_START = 1_767_225_600n;
const PERIOD_END = 1_798_761_600n;
const zero = `0x${"0".repeat(64)}` as `0x${string}`;
const hex = (digit: string): `0x${string}` => `0x${digit.repeat(64)}`;

// Matches the deliberately synthetic, server-gated browser-evidence vault.
const BROWSER_EVIDENCE_PRINCIPAL: VaultPrincipalKeyPair = {
  principalId: "phase3-browser-evidence",
  publicKey: "KsD1+YKrizU8vEyTJQ2MrSbRreOHGeXtvoaLYUXVoF8=",
  secretKey: "pT60QxIT6W8XlFM5ejV1bLRKfjGqc4vEXQuJFgpiEQU=",
};

export async function workerEvidenceBrowserFixture() {
  const employer = generateVaultPrincipal("browser-my-pay-employer");
  const committee = generateVaultPrincipal("browser-my-pay-committee");
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
      source: "pragma-browser-my-pay",
      priceAtomic: "100000",
      observedAt: new Date(Number(validityStart - 10n) * 1_000).toISOString(),
    }],
    now: new Date(Number(validityStart) * 1_000),
  });
  const buildInput = serializePayrollIntegrityBuildRequest({
    chainId: CHAIN_ID,
    sealAddress: SEAL_ADDRESS,
    organizationSecret: hex("1"),
    cycleId: "browser-my-pay-cycle",
    revision: 1,
    validityStart,
    validityExpiry: validityStart + 300n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [fx],
    lines: [{
      agreementId: AGREEMENT_ID,
      recipientAddress: RECIPIENT_ADDRESS,
      recipientSalt: hex("2"),
      agreementSalt: hex("3"),
      lineSalt: hex("4"),
      token: "STRK",
      earningsAtomic: ["1250000000000000000"],
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
  const totals = {
    STRK: {
      grossAtomic: "1250000000000000000",
      deductionsAtomic: "0",
      netAtomic: "1250000000000000000",
    },
    USDC: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
  };
  const totalsSalt = derivePayrollBookTotalsSalt({
    organizationSecret: hex("1"),
    runNullifier: payroll.runNullifier,
  });
  const bookEntry = {
    entryVersion: "payo-payroll-book-entry-v2" as const,
    entryKind: "ordinary" as const,
    chainId: CHAIN_ID,
    sealAddress: SEAL_ADDRESS,
    sourceSealAddress: SEAL_ADDRESS,
    ownerAddress: OWNER_ADDRESS,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    agreementRoot: payroll.agreementRoot,
    manifestRoot: payroll.manifestRoot,
    policyRoot: payroll.policyRoot,
    fxRoot: payroll.fxRoot,
    runNullifier: payroll.runNullifier,
    subjectNullifier: payroll.runNullifier,
    parentFactCommitment: zero,
    factCommitment: zero,
    sourceProofVersion: 2,
    attestationRoot: zero,
    contributorCount: 1,
    totalsDisclosure: "public" as const,
    totalsCommitment: payrollBookTotalsCommitment({
      subjectNullifier: payroll.runNullifier,
      contributorCount: 1,
      totals,
      salt: totalsSalt,
    }),
    totals,
    vestingScheduleId: zero,
    vestingStateCommitment: zero,
  };
  const entryCommitment = payrollBookEntryCommitment(bookEntry);
  const snapshot: TrustedPayrollBookSnapshot = {
    snapshotVersion: "payo-trusted-payroll-book-snapshot-v1",
    checkpoint: {
      checkpointVersion: "payo-payroll-book-checkpoint-v1",
      chainId: CHAIN_ID,
      sealAddress: SEAL_ADDRESS,
      ownerAddress: OWNER_ADDRESS,
      periodStart: PERIOD_START.toString(),
      periodEnd: PERIOD_END.toString(),
      entryCount: 1,
      accumulatorRoot: appendPayrollBookRoot({
        previousRoot: initialPayrollBookRoot(bookEntry),
        entryCommitment,
        index: 0,
      }),
    },
    entries: [{ index: 0, entryCommitment }],
    observedAt: "2026-09-07T03:00:00.000Z",
    blockNumber: "987654",
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
    getPayrollBookSnapshot: async () => ({ snapshot }),
    getPayrollBookSources: async () => ({ sources: [source] }),
  };
  const agreements = [{
    payeeId: PAYEE_ID,
    agreement: { id: AGREEMENT_ID, classification: "contractor" },
  }] as unknown as PayAgreementDirectoryRecord[];
  const payees = [{
    id: PAYEE_ID,
    displayName: "Ada Worker",
    principalKind: "human",
    recipientAddress: RECIPIENT_ADDRESS,
  }] as unknown as PayeeDirectoryRecord[];
  const identity = createReadyReportingIdentity({
    principal: BROWSER_EVIDENCE_PRINCIPAL,
    context: {
      chainId: CHAIN_ID,
      poolAddress: STRK20_MAINNET_POOL_ADDRESS,
      recipientAddress: RECIPIENT_ADDRESS,
    },
    createdAt: new Date("2026-09-07T03:01:00.000Z"),
  });
  const employerBook = await createEncryptedPayrollReportFromBook({
    client: client as never,
    organizationId: ORGANIZATION_ID,
    ownerAddress: OWNER_ADDRESS,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    principal: employer,
    recipient: BROWSER_EVIDENCE_PRINCIPAL,
    kind: "employer_book",
    agreements,
    payees,
    now: new Date("2026-09-07T03:01:30.000Z"),
  });
  const taxReviewerBook = await createEncryptedPayrollReportFromBook({
    client: client as never,
    organizationId: ORGANIZATION_ID,
    ownerAddress: OWNER_ADDRESS,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    principal: employer,
    recipient: BROWSER_EVIDENCE_PRINCIPAL,
    recipientIdentities: [
      createPayoPublicIdentity(
        BROWSER_EVIDENCE_PRINCIPAL,
        new Date("2026-09-07T03:01:15.000Z"),
      ),
      createPayoPublicIdentity(
        committee,
        new Date("2026-09-07T03:01:20.000Z"),
      ),
    ],
    kind: "tax_book",
    agreements,
    payees,
    now: new Date("2026-09-07T03:01:45.000Z"),
  });
  const result = await createWorkerStatementSourceFromBook({
    client: client as never,
    organizationId: ORGANIZATION_ID,
    ownerAddress: OWNER_ADDRESS,
    periodStart: PERIOD_START.toString(),
    periodEnd: PERIOD_END.toString(),
    principal: employer,
    recipientIdentity: identity.identity,
    agreements,
    payees,
    workerPayeeId: PAYEE_ID,
    now: new Date("2026-09-07T03:02:00.000Z"),
  });
  return {
    encryptedSource: result.encryptedSource,
    employerBook: employerBook.encryptedReport,
    taxReviewerBook: taxReviewerBook.encryptedReport,
    snapshot,
    expected: {
      workerName: "Ada Worker",
      net: "1.25",
      blockNumber: "987654",
      integrityTransactionHash: "0xabc",
      settlementTransactionHash: "0xdef",
    },
  };
}
