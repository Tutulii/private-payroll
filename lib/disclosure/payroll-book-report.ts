import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import {
  hashRecipientCommitment,
  hashTextCommitment,
} from "@/lib/crypto/commitments";
import { stableJson, toHex } from "@/lib/crypto/encoding";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  encryptedVaultRecordSchema,
  type EncryptedVaultRecord,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import {
  atomicAmountSchema,
  calculatePayrollLine,
  payrollTokenSchema,
} from "@/lib/domain/payroll";
import {
  appendPayrollBookRoot,
  completePayrollBookSchema,
  initialPayrollBookRoot,
  payrollBookCheckpointSchema,
  payrollBookEntryCommitment,
  payrollBookEntrySchema,
  verifyCompletePayrollBook,
  type PayrollBookCheckpoint,
  type PayrollBookEntry,
} from "@/lib/domain/vesting-tax";
import {
  evaluatePolicyPack,
  policyPackCommitment,
  policyPackSchema,
  type PolicyPack,
} from "@/lib/policy/engine";
import {
  createProofCommitter,
} from "@/lib/proof/commitments";
import type {
  PayrollIntegrityInputBuild,
  PayrollIntegrityLineInput,
} from "@/lib/proof/input-builder";
import { commitmentSchema, starknetAddressSchema, uuidV7Schema } from "@/lib/domain/records";

const unixSecondsSchema = z.string().regex(/^(0|[1-9]\d*)$/);
const u32Schema = z.number().int().nonnegative().max(0xffff_ffff);
const workerTypeSchema = z.enum(["employee", "contractor", "agent_service"]);

const disclosedPayrollSourceSchema = z.object({
  agreementId: z.string().min(1).max(160),
  recipientAddress: starknetAddressSchema,
  recipientSalt: commitmentSchema,
  agreementSalt: commitmentSchema,
  lineSalt: commitmentSchema,
  token: payrollTokenSchema,
  earningsAtomic: z.array(atomicAmountSchema).min(1).max(8),
  deductionsAtomic: z.array(atomicAmountSchema).max(8),
  policyId: z.string().min(1).max(160),
  scheduleCommitment: commitmentSchema,
  dueAt: unixSecondsSchema,
  validUntil: unixSecondsSchema,
  classification: z.object({
    declared: z.union([z.literal(1), z.literal(2)]),
    score: z.number().int().min(0).max(0xffff),
    employeeThreshold: z.number().int().min(1).max(0xffff),
  }).strict(),
  finalPay: z.object({
    requiredMask: z.number().int().min(0).max(31),
    includedMask: z.number().int().min(0).max(31),
    componentsAtomic: z.array(atomicAmountSchema).max(5),
  }).strict().optional(),
  fxFloorAtomic: atomicAmountSchema.optional(),
  referenceCurrency: z.enum(["USD", "GBP"]),
}).strict();

export const payrollBookReportLineSchema = z.object({
  index: z.number().int().min(0).max(49),
  recipientReference: z.string().min(1).max(240),
  workerType: workerTypeSchema,
  source: disclosedPayrollSourceSchema,
  policy: policyPackSchema,
  classificationTreatment: z.union([z.literal(1), z.literal(2)]),
  finalIncludedMask: z.number().int().min(0).max(31),
  referenceValueAtomic: atomicAmountSchema,
  agreementLeaf: commitmentSchema,
  payrollLeaf: commitmentSchema,
}).strict();
export type PayrollBookReportLine = z.infer<typeof payrollBookReportLineSchema>;

export const payrollBookReportEntrySchema = z.object({
  index: u32Schema,
  entry: payrollBookEntrySchema,
  entryCommitment: commitmentSchema,
  policyCatalog: z.array(policyPackSchema).min(1).max(4),
  policyCatalogRoot: commitmentSchema,
  lines: z.array(payrollBookReportLineSchema).min(1).max(50),
  integrityVerificationTransactionHash: starknetAddressSchema,
  settlementTransactionHash: starknetAddressSchema,
}).strict();
export type PayrollBookReportEntry = z.infer<typeof payrollBookReportEntrySchema>;

export const trustedPayrollBookSnapshotSchema = z.object({
  snapshotVersion: z.literal("payo-trusted-payroll-book-snapshot-v1"),
  checkpoint: payrollBookCheckpointSchema,
  entries: z.array(z.object({
    index: u32Schema,
    entryCommitment: commitmentSchema,
  }).strict()),
  observedAt: z.string().datetime(),
  blockNumber: unixSecondsSchema,
}).strict();
export type TrustedPayrollBookSnapshot = z.infer<typeof trustedPayrollBookSnapshotSchema>;

export const payrollBookReportSourceSchema = z.object({
  runId: uuidV7Schema,
  runRevision: z.number().int().positive(),
  runEnvelope: encryptedVaultRecordSchema,
  entryKind: z.enum(["ordinary", "vesting"]),
  bookEntry: payrollBookEntrySchema,
  bookEntryCommitment: commitmentSchema,
  integrityVerificationTransactionHash: starknetAddressSchema,
  settlementTransactionHash: starknetAddressSchema,
}).strict();
export type PayrollBookReportSource = z.infer<typeof payrollBookReportSourceSchema>;

export const completePayrollBookReportSchema = z.object({
  reportVersion: z.literal("payo-private-payroll-report-v1"),
  reportType: z.literal("complete_payroll_book"),
  reportId: uuidV7Schema,
  organizationId: uuidV7Schema,
  scope: z.enum(["employer", "tax_authority"]),
  checkpoint: payrollBookCheckpointSchema,
  entries: z.array(payrollBookReportEntrySchema),
  generatedAt: z.string().datetime(),
}).strict();
export type CompletePayrollBookReport = z.infer<typeof completePayrollBookReportSchema>;

const proofOpeningSchema = z.object({
  leaf: commitmentSchema,
  siblings: z.array(commitmentSchema).length(6),
  pathBits: z.array(z.boolean()).length(6),
}).strict();

const workerStatementLineSchema = z.object({
  bookIndex: u32Schema,
  entry: payrollBookEntrySchema,
  entryCommitment: commitmentSchema,
  policyCatalog: z.array(policyPackSchema).min(1).max(4),
  policyCatalogRoot: commitmentSchema,
  line: payrollBookReportLineSchema,
  agreementOpening: proofOpeningSchema,
  payrollOpening: proofOpeningSchema,
  integrityVerificationTransactionHash: starknetAddressSchema,
  settlementTransactionHash: starknetAddressSchema,
}).strict();

export const workerIncomeStatementSchema = z.object({
  reportVersion: z.literal("payo-private-payroll-report-v1"),
  reportType: z.literal("worker_income_statement"),
  reportId: uuidV7Schema,
  organizationId: uuidV7Schema,
  scope: z.literal("worker"),
  recipientAddress: starknetAddressSchema,
  recipientReference: z.string().min(1).max(240),
  checkpoint: payrollBookCheckpointSchema,
  opaqueBookEntries: z.array(z.object({
    index: u32Schema,
    entryCommitment: commitmentSchema,
  }).strict()),
  lines: z.array(workerStatementLineSchema).min(1),
  coverage: z.literal("worker-lines-included-in-complete-onchain-book"),
  generatedAt: z.string().datetime(),
}).strict();
export type WorkerIncomeStatement = z.infer<typeof workerIncomeStatementSchema>;

export const payrollReportPayloadSchema = z.discriminatedUnion("reportType", [
  completePayrollBookReportSchema,
  workerIncomeStatementSchema,
]);
export type PayrollReportPayload = z.infer<typeof payrollReportPayloadSchema>;

export const payrollReportRecordSchema = z.object({
  schemaVersion: z.literal(1),
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  revision: z.literal(1),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  payload: payrollReportPayloadSchema,
  packageCommitment: commitmentSchema,
}).strict().superRefine((record, context) => {
  if (record.id !== record.payload.reportId) {
    context.addIssue({
      code: "custom",
      path: ["id"],
      message: "The encrypted report record ID must match its payload.",
    });
  }
  if (record.organizationId !== record.payload.organizationId) {
    context.addIssue({
      code: "custom",
      path: ["organizationId"],
      message: "The encrypted report record belongs to another organization.",
    });
  }
});
export type PayrollReportRecord = z.infer<typeof payrollReportRecordSchema>;

export const encryptedPayrollReportSchema = z.object({
  packageVersion: z.literal("payo-encrypted-payroll-report-v1"),
  reportId: uuidV7Schema,
  reportType: z.enum(["complete_payroll_book", "worker_income_statement"]),
  packageCommitment: commitmentSchema,
  envelope: encryptedVaultRecordSchema,
}).strict();
export type EncryptedPayrollReport = z.infer<typeof encryptedPayrollReportSchema>;

function sameField(left: string, right: string): boolean {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

function assertSameCheckpoint(
  disclosed: PayrollBookCheckpoint,
  trusted: PayrollBookCheckpoint,
): void {
  if (
    disclosed.checkpointVersion !== trusted.checkpointVersion
    || !sameField(disclosed.chainId, trusted.chainId)
    || !sameField(disclosed.sealAddress, trusted.sealAddress)
    || !sameField(disclosed.ownerAddress, trusted.ownerAddress)
    || disclosed.periodStart !== trusted.periodStart
    || disclosed.periodEnd !== trusted.periodEnd
    || disclosed.entryCount !== trusted.entryCount
    || !sameField(disclosed.accumulatorRoot, trusted.accumulatorRoot)
  ) {
    throw new Error("The report checkpoint differs from the independently observed on-chain checkpoint.");
  }
}

export function verifyTrustedPayrollBookSnapshot(
  input: TrustedPayrollBookSnapshot,
): TrustedPayrollBookSnapshot {
  const snapshot = trustedPayrollBookSnapshotSchema.parse(input);
  if (snapshot.entries.length !== snapshot.checkpoint.entryCount) {
    throw new Error("The trusted snapshot omits one or more on-chain payroll-book entries.");
  }
  let root = initialPayrollBookRoot(snapshot.checkpoint);
  for (const [index, entry] of snapshot.entries.entries()) {
    if (entry.index !== index) {
      throw new Error("The trusted snapshot contains an omitted, duplicated, or reordered book index.");
    }
    root = appendPayrollBookRoot({
      previousRoot: root,
      entryCommitment: entry.entryCommitment,
      index,
    });
  }
  if (!sameField(root, snapshot.checkpoint.accumulatorRoot)) {
    throw new Error("The trusted entry list does not reconstruct the on-chain payroll-book accumulator.");
  }
  return snapshot;
}

function serializedSource(source: PayrollIntegrityLineInput) {
  return disclosedPayrollSourceSchema.parse({
    ...source,
    dueAt: source.dueAt.toString(),
    validUntil: source.validUntil.toString(),
  });
}

function policyDeduction(policy: PolicyPack, source: z.infer<typeof disclosedPayrollSourceSchema>): bigint {
  const gross = source.earningsAtomic.reduce((sum, amount) => sum + BigInt(amount), 0n);
  const values: Record<string, string> = {
    gross: gross.toString(),
    taxable_gross: gross.toString(),
  };
  source.earningsAtomic.forEach((amount, index) => { values[`earning_${index}`] = amount; });
  const evaluated = evaluatePolicyPack(policy, values);
  const result = evaluated.statutoryWithholding
    ?? evaluated.statutoryDeduction
    ?? Object.values(evaluated)[0];
  if (result === undefined) throw new Error(`Policy ${policy.id} has no deduction output.`);
  return BigInt(result);
}

async function verifyReportLine(lineInput: PayrollBookReportLine): Promise<{
  line: PayrollBookReportLine;
  calculated: ReturnType<typeof calculatePayrollLine>;
}> {
  const line = payrollBookReportLineSchema.parse(lineInput);
  const source = line.source;
  if (line.policy.id !== source.policyId) throw new Error("A report line discloses the wrong statutory policy.");
  if (line.policy.jurisdictionCode !== line.policy.jurisdictionCode.toUpperCase()) {
    throw new Error("A report line has a non-canonical jurisdiction code.");
  }
  if (!line.policy.appliesTo.includes(line.workerType)) {
    throw new Error("The disclosed statutory policy does not apply to this worker type.");
  }
  if ((source.classification.declared === 1) !== (line.workerType === "employee")) {
    throw new Error("The worker type conflicts with the privately proved classification treatment.");
  }
  const dueDate = new Date(Number(BigInt(source.dueAt)) * 1_000).toISOString().slice(0, 10);
  if (dueDate < line.policy.effectiveFrom || dueDate > line.policy.effectiveUntil) {
    throw new Error("The statutory policy was not effective on this payday.");
  }
  const calculated = calculatePayrollLine({
    agreementId: source.agreementId,
    recipientAddress: source.recipientAddress,
    token: source.token,
    earningsAtomic: source.earningsAtomic,
    deductionsAtomic: source.deductionsAtomic,
    committedPolicyId: source.policyId,
    scheduleCommitment: source.scheduleCommitment,
    salt: source.lineSalt,
  });
  const deductions = source.deductionsAtomic.reduce((sum, amount) => sum + BigInt(amount), 0n);
  if (deductions !== policyDeduction(line.policy, source)) {
    throw new Error("The disclosed deductions do not match the committed statutory policy.");
  }
  const expectedTreatment = source.classification.score >= source.classification.employeeThreshold ? 1 : 2;
  if (source.classification.declared !== expectedTreatment
    || line.classificationTreatment !== source.classification.declared) {
    throw new Error("The disclosed classification facts do not match the proved treatment.");
  }
  if (line.finalIncludedMask !== (source.finalPay?.includedMask ?? 0)) {
    throw new Error("The disclosed final-pay mask differs from the proved payroll line.");
  }
  const committer = await createProofCommitter();
  const agreementLeaf = committer.proofAgreementCommitment({
    agreementIdCommitment: toHex(hashTextCommitment("PAYO_AGREEMENT_ID_V1", source.agreementId)),
    recipientCommitment: toHex(hashRecipientCommitment(source.recipientAddress, source.recipientSalt)),
    earningsAtomic: source.earningsAtomic,
    token: source.token,
    policyCommitment: policyPackCommitment(line.policy),
    scheduleCommitment: source.scheduleCommitment,
    dueAt: BigInt(source.dueAt),
    validUntil: BigInt(source.validUntil),
    classificationDeclared: source.classification.declared,
    classificationScore: source.classification.score,
    classificationEmployeeThreshold: source.classification.employeeThreshold,
    finalPayMode: source.finalPay !== undefined,
    finalRequiredMask: source.finalPay?.requiredMask ?? 0,
    finalComponentsAtomic: source.finalPay?.componentsAtomic ?? [],
    fxFloorAtomic: source.fxFloorAtomic ?? "0",
    referenceCurrency: source.referenceCurrency,
    salt: source.agreementSalt,
  });
  if (!sameField(agreementLeaf, line.agreementLeaf)) {
    throw new Error("The disclosed agreement facts do not reconstruct the proved agreement leaf.");
  }
  const payrollLeaf = committer.proofPayrollCommitment(calculated, agreementLeaf, {
    classificationTreatment: line.classificationTreatment,
    finalIncludedMask: line.finalIncludedMask,
    referenceValueAtomic: line.referenceValueAtomic,
  });
  if (!sameField(payrollLeaf, line.payrollLeaf)) {
    throw new Error("The disclosed payroll facts do not reconstruct the proved payroll leaf.");
  }
  return { line, calculated };
}

async function verifyPolicyCatalogBinding(input: {
  policyCatalog: readonly PolicyPack[];
  policyCatalogRoot: string;
  lines: readonly PayrollBookReportLine[];
}): Promise<void> {
  const policyCatalog = input.policyCatalog.map((policy) => policyPackSchema.parse(policy));
  const policyKeys = new Set(policyCatalog.map(({ id, revision }) => `${id}:${revision}`));
  if (policyKeys.size !== policyCatalog.length) {
    throw new Error("A payroll report contains duplicate statutory policy releases.");
  }
  const committer = await createProofCommitter();
  const root = committer.buildProofCatalog(policyCatalog.map(policyPackCommitment)).root;
  if (!sameField(root, input.policyCatalogRoot)) {
    throw new Error("The disclosed statutory policy catalog does not reconstruct its proved root.");
  }
  const catalogByKey = new Map(policyCatalog.map((policy) => [
    `${policy.id}:${policy.revision}`,
    policy,
  ]));
  for (const line of input.lines) {
    const policy = catalogByKey.get(`${line.policy.id}:${line.policy.revision}`);
    if (!policy || stableJson(policy) !== stableJson(line.policy)) {
      throw new Error("A payroll line substitutes a policy outside its proved catalog.");
    }
  }
}

async function verifyReportEntry(entryInput: PayrollBookReportEntry): Promise<{
  disclosure: z.infer<typeof completePayrollBookSchema>["entries"][number];
  agreementLeaves: `0x${string}`[];
  payrollLeaves: `0x${string}`[];
}> {
  const entry = payrollBookReportEntrySchema.parse(entryInput);
  if (!sameField(payrollBookEntryCommitment(entry.entry), entry.entryCommitment)) {
    throw new Error("The disclosed payroll-book entry commitment is invalid.");
  }
  await verifyPolicyCatalogBinding(entry);
  const verified = [];
  for (const [index, rawLine] of entry.lines.entries()) {
    if (rawLine.index !== index) {
      throw new Error("A payroll report contains an omitted, duplicated, or reordered line index.");
    }
    verified.push(await verifyReportLine(rawLine));
  }
  const committer = await createProofCommitter();
  const agreementLeaves = verified.map(({ line }) => line.agreementLeaf as `0x${string}`);
  const payrollLeaves = verified.map(({ line }) => line.payrollLeaf as `0x${string}`);
  if (!sameField(committer.buildProofFixedMerkleRoot(agreementLeaves), entry.entry.agreementRoot)) {
    throw new Error("The disclosed agreements do not reconstruct the proved agreement root.");
  }
  if (!sameField(committer.buildProofFixedMerkleRoot(payrollLeaves), entry.entry.manifestRoot)) {
    throw new Error("The disclosed payroll lines do not reconstruct the proved manifest root.");
  }
  return {
    agreementLeaves,
    payrollLeaves,
    disclosure: {
      index: entry.index,
      entry: entry.entry,
      entryCommitment: entry.entryCommitment,
      lines: verified.map(({ line, calculated }) => ({
        recipientReference: line.recipientReference,
        jurisdictionCode: line.policy.jurisdictionCode,
        token: calculated.token,
        grossAtomic: calculated.grossAtomic,
        deductionsAtomic: calculated.deductionsTotalAtomic,
        netAtomic: calculated.netAtomic,
      })),
      integrityVerificationTransactionHash: entry.integrityVerificationTransactionHash,
      settlementTransactionHash: entry.settlementTransactionHash,
    },
  };
}

export async function buildPayrollBookReportEntry(input: {
  index: number;
  entry: PayrollBookEntry;
  payroll: PayrollIntegrityInputBuild;
  policies: readonly PolicyPack[];
  lineMetadata: Readonly<Record<string, {
    recipientReference: string;
    workerType: z.infer<typeof workerTypeSchema>;
  }>>;
  integrityVerificationTransactionHash: string;
  settlementTransactionHash: string;
}): Promise<PayrollBookReportEntry> {
  const entry = payrollBookEntrySchema.parse(input.entry);
  if (!sameField(entry.agreementRoot, input.payroll.agreementRoot)
    || !sameField(entry.manifestRoot, input.payroll.manifestRoot)
    || !sameField(entry.runNullifier, input.payroll.runNullifier)) {
    throw new Error("The payroll-book entry is not bound to this proved payroll run.");
  }
  const policies = new Map(input.policies.map((policy) => [policy.id, policyPackSchema.parse(policy)]));
  if (policies.size !== input.policies.length) throw new Error("Statutory policy IDs must be unique.");
  const policyCatalog = input.policies.map((policy) => policyPackSchema.parse(policy));
  const committer = await createProofCommitter();
  const policyCatalogRoot = committer.buildProofCatalog(policyCatalog.map(policyPackCommitment)).root;
  if (!sameField(policyCatalogRoot, input.payroll.policyRoot)) {
    throw new Error("The disclosed statutory policy catalog differs from the proved payroll root.");
  }
  const lines = input.payroll.proofBindings.map((binding, index) => {
    if (binding.index !== index) throw new Error("Payroll proof bindings are not canonically ordered.");
    const metadata = input.lineMetadata[binding.agreementId];
    if (!metadata) throw new Error(`Tax metadata is missing for agreement ${binding.agreementId}.`);
    const policy = policies.get(binding.source.policyId);
    if (!policy) throw new Error(`Statutory policy ${binding.source.policyId} is unavailable.`);
    return {
      index,
      ...metadata,
      source: serializedSource(binding.source),
      policy,
      classificationTreatment: Number(binding.line.classification_treatment) as 1 | 2,
      finalIncludedMask: Number(binding.line.final_included_mask),
      referenceValueAtomic: binding.line.reference_value_atomic,
      agreementLeaf: binding.agreementLeaf,
      payrollLeaf: binding.payrollLeaf,
    };
  });
  if (Object.keys(input.lineMetadata).length !== lines.length) {
    throw new Error("Tax metadata must cover the payroll batch exactly once.");
  }
  const reportEntry = payrollBookReportEntrySchema.parse({
    index: input.index,
    entry,
    entryCommitment: payrollBookEntryCommitment(entry),
    policyCatalog,
    policyCatalogRoot,
    lines,
    integrityVerificationTransactionHash: input.integrityVerificationTransactionHash,
    settlementTransactionHash: input.settlementTransactionHash,
  });
  await verifyReportEntry(reportEntry);
  return reportEntry;
}

export async function verifyCompletePayrollBookReport(input: {
  report: CompletePayrollBookReport;
  trustedSnapshot: TrustedPayrollBookSnapshot;
}) {
  const report = completePayrollBookReportSchema.parse(input.report);
  const trusted = verifyTrustedPayrollBookSnapshot(input.trustedSnapshot);
  assertSameCheckpoint(report.checkpoint, trusted.checkpoint);
  if (report.entries.length !== trusted.entries.length) {
    throw new Error("The encrypted payroll book omits one or more on-chain entries.");
  }
  const disclosures = [];
  for (const [index, entry] of report.entries.entries()) {
    if (entry.index !== index || trusted.entries[index]?.index !== index) {
      throw new Error("The encrypted payroll book contains an omitted, duplicated, or reordered entry.");
    }
    if (!sameField(entry.entryCommitment, trusted.entries[index].entryCommitment)) {
      throw new Error("A disclosed payroll entry differs from the independently read on-chain entry.");
    }
    disclosures.push((await verifyReportEntry(entry)).disclosure);
  }
  const result = verifyCompletePayrollBook(completePayrollBookSchema.parse({
    packageVersion: "payo-complete-payroll-book-v1",
    scope: report.scope,
    checkpoint: report.checkpoint,
    entries: disclosures,
    generatedAt: report.generatedAt,
  }));
  return { ...result, scope: report.scope, reportId: report.reportId };
}

function foldOpening(
  committer: Awaited<ReturnType<typeof createProofCommitter>>,
  opening: z.infer<typeof proofOpeningSchema>,
): `0x${string}` {
  let current = opening.leaf as `0x${string}`;
  for (const [level, sibling] of opening.siblings.entries()) {
    current = opening.pathBits[level]
      ? committer.proofMerkleNode(sibling, current)
      : committer.proofMerkleNode(current, sibling);
  }
  return current;
}

export async function createWorkerIncomeStatement(input: {
  reportId: string;
  completeReport: CompletePayrollBookReport;
  trustedSnapshot: TrustedPayrollBookSnapshot;
  recipientAddress: string;
  recipientReference: string;
  generatedAt?: Date;
}): Promise<WorkerIncomeStatement> {
  await verifyCompletePayrollBookReport({
    report: input.completeReport,
    trustedSnapshot: input.trustedSnapshot,
  });
  const committer = await createProofCommitter();
  const selected = [];
  for (const entry of input.completeReport.entries) {
    const agreementLeaves = entry.lines.map(({ agreementLeaf }) => agreementLeaf);
    const payrollLeaves = entry.lines.map(({ payrollLeaf }) => payrollLeaf);
    for (const line of entry.lines) {
      if (!sameField(line.source.recipientAddress, input.recipientAddress)) continue;
      if (line.recipientReference !== input.recipientReference) {
        throw new Error("Recipient reference is inconsistent across the complete payroll book.");
      }
      const agreementOpening = committer.buildProofFixedMerkleMembership(agreementLeaves, line.index);
      const payrollOpening = committer.buildProofFixedMerkleMembership(payrollLeaves, line.index);
      selected.push({
        bookIndex: entry.index,
        entry: entry.entry,
        entryCommitment: entry.entryCommitment,
        policyCatalog: entry.policyCatalog,
        policyCatalogRoot: entry.policyCatalogRoot,
        line,
        agreementOpening: {
          leaf: agreementOpening.leaf,
          siblings: agreementOpening.siblings,
          pathBits: agreementOpening.pathBits,
        },
        payrollOpening: {
          leaf: payrollOpening.leaf,
          siblings: payrollOpening.siblings,
          pathBits: payrollOpening.pathBits,
        },
        integrityVerificationTransactionHash: entry.integrityVerificationTransactionHash,
        settlementTransactionHash: entry.settlementTransactionHash,
      });
    }
  }
  if (selected.length === 0) throw new Error("The complete payroll book has no line for this worker.");
  return workerIncomeStatementSchema.parse({
    reportVersion: "payo-private-payroll-report-v1",
    reportType: "worker_income_statement",
    reportId: input.reportId,
    organizationId: input.completeReport.organizationId,
    scope: "worker",
    recipientAddress: input.recipientAddress,
    recipientReference: input.recipientReference,
    checkpoint: input.completeReport.checkpoint,
    opaqueBookEntries: input.trustedSnapshot.entries,
    lines: selected,
    coverage: "worker-lines-included-in-complete-onchain-book",
    generatedAt: (input.generatedAt ?? new Date()).toISOString(),
  });
}

export async function verifyWorkerIncomeStatement(input: {
  statement: WorkerIncomeStatement;
  trustedSnapshot: TrustedPayrollBookSnapshot;
}) {
  const statement = workerIncomeStatementSchema.parse(input.statement);
  const trusted = verifyTrustedPayrollBookSnapshot(input.trustedSnapshot);
  assertSameCheckpoint(statement.checkpoint, trusted.checkpoint);
  if (stableJson(statement.opaqueBookEntries) !== stableJson(trusted.entries)) {
    throw new Error("The worker statement does not contain the complete opaque on-chain book.");
  }
  const committer = await createProofCommitter();
  const seen = new Set<string>();
  const totals = { STRK: 0n, USDC: 0n };
  for (const disclosed of statement.lines) {
    const key = `${disclosed.bookIndex}:${disclosed.line.index}`;
    if (seen.has(key)) throw new Error("The worker statement duplicates a payroll line.");
    seen.add(key);
    const trustedEntry = trusted.entries[disclosed.bookIndex];
    if (!trustedEntry || !sameField(trustedEntry.entryCommitment, disclosed.entryCommitment)
      || !sameField(payrollBookEntryCommitment(disclosed.entry), disclosed.entryCommitment)) {
      throw new Error("A worker statement line is not bound to the trusted payroll book.");
    }
    if (!sameField(disclosed.line.source.recipientAddress, statement.recipientAddress)
      || disclosed.line.recipientReference !== statement.recipientReference) {
      throw new Error("A worker statement contains another recipient's payroll line.");
    }
    await verifyPolicyCatalogBinding({
      policyCatalog: disclosed.policyCatalog,
      policyCatalogRoot: disclosed.policyCatalogRoot,
      lines: [disclosed.line],
    });
    const verified = await verifyReportLine(disclosed.line);
    if (!sameField(disclosed.agreementOpening.leaf, disclosed.line.agreementLeaf)
      || !sameField(foldOpening(committer, disclosed.agreementOpening), disclosed.entry.agreementRoot)
      || !sameField(disclosed.payrollOpening.leaf, disclosed.line.payrollLeaf)
      || !sameField(foldOpening(committer, disclosed.payrollOpening), disclosed.entry.manifestRoot)) {
      throw new Error("A worker line opening does not reconstruct its proved payroll roots.");
    }
    totals[verified.calculated.token] += BigInt(verified.calculated.netAtomic);
  }
  return {
    verified: true as const,
    reportId: statement.reportId,
    lineCount: statement.lines.length,
    netTotals: { STRK: totals.STRK.toString(), USDC: totals.USDC.toString() },
    coverage: statement.coverage,
  };
}

function reportCommitment(payload: PayrollReportPayload): `0x${string}` {
  return toHex(sha256(new TextEncoder().encode(stableJson(payload))));
}

export function encryptPayrollReport(input: {
  payload: PayrollReportPayload;
  recipients: readonly VaultPrincipal[];
}): EncryptedPayrollReport {
  const payload = payrollReportPayloadSchema.parse(input.payload);
  const packageCommitment = reportCommitment(payload);
  const record = payrollReportRecordSchema.parse({
    schemaVersion: 1,
    id: payload.reportId,
    organizationId: payload.organizationId,
    revision: 1,
    createdAt: payload.generatedAt,
    updatedAt: payload.generatedAt,
    payload,
    packageCommitment,
  });
  const envelope = encryptVaultRecord(
    record,
    {
      schemaVersion: 1,
      organizationId: payload.organizationId,
      recordType: "payroll-report",
      recordId: payload.reportId,
      revision: 1,
    },
    input.recipients,
  );
  return encryptedPayrollReportSchema.parse({
    packageVersion: "payo-encrypted-payroll-report-v1",
    reportId: payload.reportId,
    reportType: payload.reportType,
    packageCommitment,
    envelope,
  });
}

export function openEncryptedPayrollReport(input: {
  encryptedReport: EncryptedPayrollReport;
  recipient: VaultPrincipalKeyPair;
}) {
  const encrypted = encryptedPayrollReportSchema.parse(input.encryptedReport);
  if (encrypted.envelope.aad.recordType !== "payroll-report"
    || encrypted.envelope.aad.recordId !== encrypted.reportId
    || encrypted.envelope.aad.revision !== 1) {
    throw new Error("The encrypted payroll report has invalid associated data.");
  }
  let decrypted: PayrollReportRecord;
  try {
    decrypted = payrollReportRecordSchema.parse(
      decryptVaultRecord(encrypted.envelope as EncryptedVaultRecord, input.recipient),
    );
  } catch {
    throw new Error("The encrypted payroll report is unauthorized, tampered, or unreadable.");
  }
  const payload = decrypted.payload;
  const commitment = reportCommitment(payload);
  if (commitment !== encrypted.packageCommitment
    || commitment !== decrypted.packageCommitment
    || decrypted.id !== encrypted.reportId
    || decrypted.organizationId !== encrypted.envelope.aad.organizationId
    || decrypted.revision !== encrypted.envelope.aad.revision
    || payload.reportId !== encrypted.reportId
    || payload.reportType !== encrypted.reportType
    || payload.organizationId !== encrypted.envelope.aad.organizationId) {
    throw new Error("The encrypted payroll report commitment or identity is invalid.");
  }
  return { payload, packageCommitment: commitment };
}

export async function inspectEncryptedPayrollReport(input: {
  encryptedReport: EncryptedPayrollReport;
  recipient: VaultPrincipalKeyPair;
  trustedSnapshot: TrustedPayrollBookSnapshot;
}) {
  const opened = openEncryptedPayrollReport(input);
  const verification = opened.payload.reportType === "complete_payroll_book"
    ? await verifyCompletePayrollBookReport({ report: opened.payload, trustedSnapshot: input.trustedSnapshot })
    : await verifyWorkerIncomeStatement({ statement: opened.payload, trustedSnapshot: input.trustedSnapshot });
  return { ...opened, verification };
}
