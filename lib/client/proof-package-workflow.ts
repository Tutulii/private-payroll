import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { stableJson } from "@/lib/crypto/encoding";
import {
  decryptVaultRecord,
  type EncryptedVaultRecord,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { buildProofPackage } from "@/lib/domain/payroll";
import { remediationRecordSchema, wageClaimRecordSchema } from "@/lib/domain/records";
import {
  createRecipientEncryptedProofPackage,
  proofPackageGrantSchema,
  type EncryptedRecipientProofPackage,
  type ProofPackageGrant,
  type RecipientProofPackagePayload,
} from "@/lib/disclosure/proof-package";
import { createProofCommitter } from "@/lib/proof/commitments";
import { buildPayrollIntegrityInputsFromSerialized, type SerializedPayrollIntegrityBuildRequest } from "@/lib/proof/input-builder";
import type { PayrollIntegrityPublicInputs } from "@/lib/proof/protocol";
import { buildWageClaimInputs, buildWageRemediationInputs } from "@/lib/proof/wage-claim-input";
import type { PayoClient } from "./payo-client";
import { createEncryptedDisclosureGrant, type DisclosureField } from "./disclosure-grants";

const encryptedProofPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  scheme: z.string().min(1),
  circuitSha256: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  verificationKeySha256: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  provingTimeMs: z.number().nonnegative(),
  shards: z.tuple([
    z.object({
      shardIndex: z.literal(0),
      proofBase64: z.string().min(1),
      proofCalldata: z.array(z.string()).min(1),
      calldataHash: z.string().regex(/^0x[0-9a-fA-F]+$/),
      publicInputs: z.record(z.string(), z.union([z.string(), z.number()])),
    }).strict(),
    z.object({
      shardIndex: z.literal(1),
      proofBase64: z.string().min(1),
      proofCalldata: z.array(z.string()).min(1),
      calldataHash: z.string().regex(/^0x[0-9a-fA-F]+$/),
      publicInputs: z.record(z.string(), z.union([z.string(), z.number()])),
    }).strict(),
  ]),
}).strict();

const runPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  cycleId: z.string(),
  dueAt: z.string().datetime(),
  agreementRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  manifestRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  policyRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  fxRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  runNullifier: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  manifest: z.unknown(),
  claimProofSource: z.object({ buildInput: z.unknown() }).strict(),
}).passthrough();

const proofJobSchema = z.object({
  proofBundleId: z.string().uuid(),
  state: z.string(),
  shard0TransactionHash: z.string().nullable(),
  shard1TransactionHash: z.string().nullable(),
  updatedAt: z.union([z.string(), z.date()]),
}).passthrough();

const settlementSchema = z.object({
  id: z.string().uuid(),
  runId: z.string().uuid(),
  organizationId: z.string().uuid().optional(),
  workflowType: z.enum(["payroll", "wage_claim", "wage_remediation"]).optional(),
  subjectRecordId: z.string().uuid().optional(),
  state: z.string(),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
  tokenTotalsCommitment: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  blockNumber: z.union([z.string(), z.bigint()]).nullable().optional(),
  confirmationDepth: z.number().int().nonnegative(),
  confirmedAt: z.union([z.string(), z.date()]).nullable().optional(),
}).passthrough();

type PackageScope = ProofPackageGrant["scope"];

export const PROOF_PACKAGE_SCOPE_FIELDS: Record<PackageScope, DisclosureField[]> = {
  worker: ["identity", "gross", "deductions", "net", "token", "schedule", "settlement"],
  employer: ["identity", "gross", "deductions", "net", "token", "schedule", "classification", "aggregate", "settlement"],
  auditor: ["gross", "deductions", "net", "token", "schedule", "classification", "aggregate", "settlement"],
  tax: ["gross", "deductions", "net", "token", "aggregate", "settlement"],
};

export const PROOF_PACKAGE_EXCEPTION_SCOPE_FIELDS: Record<PackageScope, DisclosureField[]> = {
  worker: [...PROOF_PACKAGE_SCOPE_FIELDS.worker, "exception"],
  employer: [...PROOF_PACKAGE_SCOPE_FIELDS.employer, "exception"],
  auditor: [...PROOF_PACKAGE_SCOPE_FIELDS.auditor, "exception"],
  tax: [...PROOF_PACKAGE_SCOPE_FIELDS.tax, "exception"],
};

function rootFromLimbs(high: string | number, low: string | number): `0x${string}` {
  const value = (BigInt(high) << 128n) | BigInt(low);
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function canonicalFelt(value: string | number): string {
  return `0x${BigInt(value).toString(16)}`;
}

function canonicalDecimal(value: string | number): string {
  return BigInt(value).toString();
}

function commonInputs(value: Record<string, string | number>) {
  const publicInputs = value as unknown as PayrollIntegrityPublicInputs;
  return {
    chainId: canonicalFelt(publicInputs.chainId),
    sealAddress: canonicalFelt(publicInputs.sealAddress),
    proofVersion: canonicalDecimal(publicInputs.proofVersion),
    schemaVersion: canonicalDecimal(publicInputs.schemaVersion),
    agreementRootHigh: canonicalDecimal(publicInputs.agreementRootHigh),
    agreementRootLow: canonicalDecimal(publicInputs.agreementRootLow),
    manifestRootHigh: canonicalDecimal(publicInputs.manifestRootHigh),
    manifestRootLow: canonicalDecimal(publicInputs.manifestRootLow),
    policyRootHigh: canonicalDecimal(publicInputs.policyRootHigh),
    policyRootLow: canonicalDecimal(publicInputs.policyRootLow),
    fxRootHigh: canonicalDecimal(publicInputs.fxRootHigh),
    fxRootLow: canonicalDecimal(publicInputs.fxRootLow),
    runNullifierHigh: canonicalDecimal(publicInputs.runNullifierHigh),
    runNullifierLow: canonicalDecimal(publicInputs.runNullifierLow),
    validityStart: canonicalDecimal(publicInputs.validityStart),
    validityExpiry: canonicalDecimal(publicInputs.validityExpiry),
  };
}

function journalForLines(
  lines: Awaited<ReturnType<typeof buildPayrollIntegrityInputsFromSerialized>>["calculatedLines"],
  date: string,
): RecipientProofPackagePayload["journal"] {
  const byToken = new Map<"STRK" | "USDC", { gross: bigint; deductions: bigint; net: bigint }>();
  for (const line of lines) {
    const total = byToken.get(line.token) ?? { gross: 0n, deductions: 0n, net: 0n };
    total.gross += BigInt(line.grossAtomic);
    total.deductions += BigInt(line.deductionsTotalAtomic);
    total.net += BigInt(line.netAtomic);
    byToken.set(line.token, total);
  }
  return [...byToken].flatMap(([token, total]) => [
    { date, accountCode: "PAYROLL_EXPENSE", debitAtomic: total.gross.toString(), creditAtomic: "0", token, memo: "Proof-bound private compensation" },
    ...(total.deductions > 0n ? [{ date, accountCode: "STATUTORY_PAYABLE", debitAtomic: "0", creditAtomic: total.deductions.toString(), token, memo: "Committed payroll deductions" }] : []),
    { date, accountCode: "PRIVATE_TREASURY", debitAtomic: "0", creditAtomic: total.net.toString(), token, memo: "STRK20 private settlement" },
  ]);
}

function journalForException(input: {
  workflowType: "wage_claim" | "wage_remediation";
  amountAtomic: string;
  token: "STRK" | "USDC";
  date: string;
}): RecipientProofPackagePayload["journal"] {
  const claim = input.workflowType === "wage_claim";
  return [{
    date: input.date,
    accountCode: claim ? "WAGE_CLAIM_EXPENSE" : "WAGE_REMEDIATION_EXPENSE",
    debitAtomic: input.amountAtomic,
    creditAtomic: "0",
    token: input.token,
    memo: claim ? "Proof-bound private wage claim" : "Proof-bound private wage remediation",
  }, {
    date: input.date,
    accountCode: claim ? "WAGE_CLAIM_PAYABLE" : "PRIVATE_TREASURY",
    debitAtomic: "0",
    creditAtomic: input.amountAtomic,
    token: input.token,
    memo: claim ? "Private claim liability" : "STRK20 private remediation settlement",
  }];
}

function disclosedFields(input: {
  fieldScope: readonly DisclosureField[];
  lines: Awaited<ReturnType<typeof buildPayrollIntegrityInputsFromSerialized>>["calculatedLines"];
  sourceLines: SerializedPayrollIntegrityBuildRequest["lines"];
  settlement: z.infer<typeof settlementSchema>;
  exception?: Record<string, unknown>;
}) {
  const values: Partial<Record<DisclosureField, unknown>> = {};
  const sourceById = new Map(input.sourceLines.map((line) => [line.agreementId, line]));
  const project = input.lines.map((line) => {
    const source = sourceById.get(line.agreementId);
    if (!source) throw new Error(`Disclosure source is missing agreement ${line.agreementId}.`);
    return { line, source };
  });
  for (const field of input.fieldScope) {
    if (field === "identity") values.identity = project.map(({ source }) => ({ agreementId: source.agreementId, recipientAddress: source.recipientAddress }));
    if (field === "gross") values.gross = project.map(({ line }) => ({ agreementId: line.agreementId, atomic: line.grossAtomic }));
    if (field === "deductions") values.deductions = project.map(({ line }) => ({ agreementId: line.agreementId, atomic: line.deductionsTotalAtomic }));
    if (field === "net") values.net = project.map(({ line }) => ({ agreementId: line.agreementId, atomic: line.netAtomic }));
    if (field === "token") values.token = project.map(({ line }) => ({ agreementId: line.agreementId, token: line.token }));
    if (field === "schedule") values.schedule = project.map(({ source }) => ({ agreementId: source.agreementId, commitment: source.scheduleCommitment, dueAt: source.dueAt, validUntil: source.validUntil }));
    if (field === "classification") values.classification = project.map(({ source }) => ({ agreementId: source.agreementId, treatment: source.classification.declared }));
    if (field === "aggregate") values.aggregate = project.reduce<Record<string, string>>((totals, { line }) => {
      totals[line.token] = (BigInt(totals[line.token] ?? "0") + BigInt(line.netAtomic)).toString();
      return totals;
    }, {});
    if (field === "settlement") values.settlement = {
      transactionHash: input.settlement.transactionHash,
      tokenTotalsCommitment: input.settlement.tokenTotalsCommitment,
      blockNumber: input.settlement.blockNumber?.toString() ?? null,
      confirmationDepth: input.settlement.confirmationDepth,
    };
    if (field === "exception") {
      if (!input.exception) throw new Error("The disclosure scope requests exception facts from an ordinary payroll.");
      values.exception = input.exception;
    }
  }
  return values;
}

export async function createProofPackageForSettlement(input: {
  client: Pick<PayoClient, "getSettlement" | "getPayrollRun" | "getProofVerification" | "getEncryptedRecord" | "createDisclosureGrant" | "revokeDisclosureGrant">;
  organizationId: string;
  settlementId: string;
  issuerPrincipal: VaultPrincipalKeyPair;
  grantee: VaultPrincipal;
  scope: PackageScope;
  expiresAt: string;
  fieldScope?: DisclosureField[];
  workerAgreementId?: string;
  now?: Date;
}): Promise<{ grant: ProofPackageGrant; encryptedPackage: EncryptedRecipientProofPackage }> {
  const now = input.now ?? new Date();
  const settlement = settlementSchema.parse((await input.client.getSettlement(input.settlementId)).settlement);
  if (settlement.organizationId && settlement.organizationId !== input.organizationId) throw new Error("Settlement belongs to another organization.");
  const workflowType = settlement.workflowType ?? "payroll";
  if (!["confirmed", "finalized", "reconciled"].includes(settlement.state)) throw new Error("The proof-bound settlement is not final enough for disclosure.");
  const [runResponse, proofJobResponse] = await Promise.all([
    input.client.getPayrollRun(settlement.runId),
    input.client.getProofVerification(settlement.id),
  ]);
  const run = runResponse.run as typeof runResponse.run & { proofBundleId?: string; envelope: EncryptedVaultRecord };
  if (run.organizationId !== input.organizationId) throw new Error("Payroll run belongs to another organization.");
  const proofJob = proofJobSchema.parse(proofJobResponse.proofVerification);
  if (proofJob.state !== "complete") throw new Error("The payroll proof is not yet verified on-chain.");
  const proofRecord = (await input.client.getEncryptedRecord({
    organizationId: input.organizationId,
    recordId: proofJob.proofBundleId,
  })).record as { envelope?: EncryptedVaultRecord };
  if (!proofRecord.envelope) throw new Error("The encrypted proof bundle is missing.");
  const runPayload = runPayloadSchema.parse(decryptVaultRecord(run.envelope, input.issuerPrincipal));
  const proofPayload = encryptedProofPayloadSchema.parse(decryptVaultRecord(proofRecord.envelope, input.issuerPrincipal));
  const publicInput = proofPayload.shards[0].publicInputs;
  const common = commonInputs(publicInput);
  const expectedProofVersion = workflowType === "wage_claim"
    ? "3"
    : workflowType === "wage_remediation"
      ? "4"
      : common.proofVersion;
  if (
    common.proofVersion !== expectedProofVersion
    || (workflowType === "payroll" && common.proofVersion !== "1" && common.proofVersion !== "2")
  ) throw new Error(`Proof version ${common.proofVersion} does not match ${workflowType}.`);
  const buildInput = runPayload.claimProofSource.buildInput as SerializedPayrollIntegrityBuildRequest;
  const rebuilt = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  if (rebuilt.manifestRoot.toLowerCase() !== runPayload.manifestRoot.toLowerCase()) {
    throw new Error("The encrypted payroll witness does not reconstruct its proved manifest root.");
  }
  for (const [actual, expected, label] of [
    [rootFromLimbs(common.agreementRootHigh, common.agreementRootLow), rebuilt.agreementRoot, "agreement"],
    [rootFromLimbs(common.policyRootHigh, common.policyRootLow), rebuilt.policyRoot, "policy"],
    [rootFromLimbs(common.fxRootHigh, common.fxRootLow), rebuilt.fxRoot, "FX"],
  ] as const) {
    if (BigInt(actual) !== BigInt(expected)) throw new Error(`Proof bundle and encrypted ${label} root differ.`);
  }

  const fieldScope = input.fieldScope ?? (workflowType === "payroll"
    ? PROOF_PACKAGE_SCOPE_FIELDS[input.scope]
    : PROOF_PACKAGE_EXCEPTION_SCOPE_FIELDS[input.scope]);
  let selectedIndex = input.scope === "worker" && workflowType === "payroll"
    ? rebuilt.calculatedLines.findIndex(({ agreementId }) => agreementId === input.workerAgreementId)
    : -1;
  let derivedManifestRoot = rebuilt.manifestRoot;
  let openingLeaves: string[] | undefined;
  let exception: Record<string, unknown> | undefined;
  let journal = journalForLines(rebuilt.calculatedLines, runPayload.dueAt.slice(0, 10));

  if (workflowType !== "payroll") {
    if (!settlement.subjectRecordId) throw new Error("An exception settlement requires its encrypted subject record.");
    const subjectResponse = await input.client.getEncryptedRecord({
      organizationId: input.organizationId,
      recordId: settlement.subjectRecordId,
    });
    const subjectEnvelope = (subjectResponse.record as { envelope?: EncryptedVaultRecord }).envelope;
    if (!subjectEnvelope) throw new Error("The encrypted exception subject is missing.");
    const validityStart = BigInt(common.validityStart);
    const validityExpiry = BigInt(common.validityExpiry);
    if (workflowType === "wage_claim") {
      const claim = wageClaimRecordSchema.parse(decryptVaultRecord(subjectEnvelope, input.issuerPrincipal));
      if (
        claim.id !== settlement.subjectRecordId
        || claim.runId !== settlement.runId
        || claim.settlementId !== settlement.id
        || claim.proofBundleId !== proofJob.proofBundleId
        || !claim.claimNullifier
        || !claim.shortfallAtomic
        || !claim.token
      ) throw new Error("The encrypted wage claim does not match its final settlement and proof bundle.");
      const claimBuild = await buildWageClaimInputs({
        payroll: rebuilt,
        agreementId: claim.agreementId,
        claimKind: claim.claimKind,
        claimSalt: claim.claimSalt as `0x${string}`,
        validityStart,
        validityExpiry,
        disputedReferenceValueAtomic: claim.disputedReferenceValueAtomic,
        disputedFinalIncludedMask: claim.disputedFinalIncludedMask,
      });
      if (BigInt(claimBuild.claimNullifier) !== BigInt(claim.claimNullifier)) {
        throw new Error("The encrypted wage claim does not reconstruct its proved nullifier.");
      }
      selectedIndex = claimBuild.targetIndex;
      derivedManifestRoot = claimBuild.disputedManifestRoot;
      const witness = claimBuild.witness.circuitInputs[0] as Record<string, unknown>;
      if (!Array.isArray(witness.payroll_leaves)) throw new Error("The wage-claim witness has no disputed manifest leaves.");
      openingLeaves = witness.payroll_leaves.map(String);
      exception = {
        workflowType,
        subjectRecordId: claim.id,
        agreementId: claim.agreementId,
        claimKind: claim.claimKind,
        claimNullifier: claim.claimNullifier,
        shortfallAtomic: claim.shortfallAtomic,
        token: claim.token,
        ...(claim.disputedReferenceValueAtomic ? { disputedReferenceValueAtomic: claim.disputedReferenceValueAtomic } : {}),
        ...(claim.disputedFinalIncludedMask === undefined ? {} : { disputedFinalIncludedMask: claim.disputedFinalIncludedMask }),
      };
      journal = journalForException({ workflowType, amountAtomic: claim.shortfallAtomic, token: claim.token, date: runPayload.dueAt.slice(0, 10) });
    } else {
      const remediation = remediationRecordSchema.parse(decryptVaultRecord(subjectEnvelope, input.issuerPrincipal));
      if (
        remediation.id !== settlement.subjectRecordId
        || remediation.runId !== settlement.runId
        || remediation.settlementId !== settlement.id
        || remediation.proofBundleId !== proofJob.proofBundleId
        || !remediation.agreementId
        || !remediation.claimNullifier
        || !remediation.amountAtomic
        || !remediation.token
      ) throw new Error("The encrypted remediation does not match its final settlement and proof bundle.");
      const claimResponse = await input.client.getEncryptedRecord({
        organizationId: input.organizationId,
        recordId: remediation.claimId,
      });
      const claimEnvelope = (claimResponse.record as { envelope?: EncryptedVaultRecord }).envelope;
      if (!claimEnvelope) throw new Error("The encrypted remediation claim source is missing.");
      const claim = wageClaimRecordSchema.parse(decryptVaultRecord(claimEnvelope, input.issuerPrincipal));
      const claimBuild = await buildWageClaimInputs({
        payroll: rebuilt,
        agreementId: claim.agreementId,
        claimKind: claim.claimKind,
        claimSalt: claim.claimSalt as `0x${string}`,
        validityStart,
        validityExpiry,
        disputedReferenceValueAtomic: claim.disputedReferenceValueAtomic,
        disputedFinalIncludedMask: claim.disputedFinalIncludedMask,
      });
      if (
        claim.id !== remediation.claimId
        || claimBuild.claimNullifier !== remediation.claimNullifier
        || claimBuild.claimNullifier !== claim.claimNullifier
      ) throw new Error("The encrypted remediation cannot reconstruct its accepted claim.");
      const remediationBuild = await buildWageRemediationInputs({
        claim: claimBuild,
        amountAtomic: remediation.amountAtomic,
        token: remediation.token,
        remediationSalt: remediation.remediationSalt as `0x${string}`,
        validityStart,
        validityExpiry,
      });
      selectedIndex = claimBuild.targetIndex;
      derivedManifestRoot = remediationBuild.remediationManifestRoot;
      const witness = remediationBuild.witness.circuitInputs[0] as Record<string, unknown>;
      if (!Array.isArray(witness.remediation_leaves)) throw new Error("The remediation witness has no manifest leaves.");
      openingLeaves = witness.remediation_leaves.map(String);
      exception = {
        workflowType,
        subjectRecordId: remediation.id,
        claimId: remediation.claimId,
        agreementId: remediation.agreementId,
        claimNullifier: remediation.claimNullifier,
        amountAtomic: remediation.amountAtomic,
        token: remediation.token,
        ...(remediation.remediationNullifier ? { remediationNullifier: remediation.remediationNullifier } : {}),
      };
      journal = journalForException({ workflowType, amountAtomic: remediation.amountAtomic, token: remediation.token, date: runPayload.dueAt.slice(0, 10) });
    }
  }
  if (input.scope === "worker" && selectedIndex < 0) throw new Error("Choose the worker's proved payroll line.");
  if (
    input.scope === "worker"
    && input.workerAgreementId
    && rebuilt.calculatedLines[selectedIndex]?.agreementId !== input.workerAgreementId
  ) throw new Error("The worker disclosure does not match the exception agreement.");
  const scopedLines = selectedIndex >= 0 ? [rebuilt.calculatedLines[selectedIndex]] : rebuilt.calculatedLines;
  if (workflowType === "payroll") journal = journalForLines(scopedLines, runPayload.dueAt.slice(0, 10));
  const scopedSourceLines = selectedIndex >= 0
    ? buildInput.lines.filter(({ agreementId }) => agreementId === scopedLines[0].agreementId)
    : buildInput.lines;
  const manifestRoot = rootFromLimbs(common.manifestRootHigh, common.manifestRootLow);
  if (BigInt(manifestRoot) !== BigInt(derivedManifestRoot)) throw new Error("Proof bundle and encrypted workflow manifest root differ.");
  const payrollLeaves = openingLeaves ?? (rebuilt.witness.circuitInputs[0] as Record<string, unknown>).payroll_leaves;
  if (!Array.isArray(payrollLeaves) || payrollLeaves.some((leaf) => typeof leaf !== "string")) {
    throw new Error("The rebuilt workflow witness has no canonical manifest leaves.");
  }
  const lineOpening = input.scope === "worker" && selectedIndex >= 0
    ? (() => {
        const leaves = (payrollLeaves as string[]).slice(0, rebuilt.calculatedLines.length)
          .map((leaf) => `0x${BigInt(leaf).toString(16).padStart(64, "0")}` as `0x${string}`);
        return createProofCommitter().then((committer) => {
          const opening = committer.buildProofFixedMerkleMembership(leaves, selectedIndex);
          return { manifestRoot: opening.root, lineCommitment: opening.leaf, lineIndex: selectedIndex, siblings: opening.siblings, pathBits: opening.pathBits };
        });
      })()
    : undefined;
  const verificationTransactionHash = proofJob.shard1TransactionHash
    ?? proofJob.shard0TransactionHash
    ?? settlement.transactionHash;
  const checkedAt = new Date(proofJob.updatedAt).toISOString();
  const publicInputsHash = hashCanonicalJson([
    { ...common, shardIndex: "0" },
    { ...common, shardIndex: "1" },
  ]);
  const proofPackage = buildProofPackage({
    runId: settlement.runId,
    organizationId: input.organizationId,
    proofType: workflowType === "wage_claim"
      ? "wage_claim"
      : workflowType === "wage_remediation"
        ? "wage_remediation"
        : "payroll_integrity",
    proofVersion: common.proofVersion,
    verifier: { chainId: common.chainId, contractAddress: common.sealAddress },
    publicInputs: {
      ...common,
      agreementRoot: rootFromLimbs(common.agreementRootHigh, common.agreementRootLow),
      manifestRoot,
      policyRoot: rootFromLimbs(common.policyRootHigh, common.policyRootLow),
      fxRoot: rootFromLimbs(common.fxRootHigh, common.fxRootLow),
      runNullifier: rootFromLimbs(common.runNullifierHigh, common.runNullifierLow),
      shard0CalldataHash: proofPayload.shards[0].calldataHash,
      shard1CalldataHash: proofPayload.shards[1].calldataHash,
    },
    proof: stableJson({ scheme: proofPayload.scheme, shards: proofPayload.shards.map(({ shardIndex, proofBase64, calldataHash }) => ({ shardIndex, proofBase64, calldataHash })) }),
    transactionHash: settlement.transactionHash,
  });
  const createdGrant = await createEncryptedDisclosureGrant({
    client: input.client,
    organizationId: input.organizationId,
    runId: settlement.runId,
    granteePrincipalId: input.grantee.principalId,
    granteePublicKey: input.grantee.publicKey,
    issuerPrincipal: input.issuerPrincipal,
    fieldScope,
    expiresAt: input.expiresAt,
    now,
  });
  const grant = proofPackageGrantSchema.parse({
    grantVersion: "payo-proof-package-grant-v1",
    id: createdGrant.record.id,
    organizationId: input.organizationId,
    runId: settlement.runId,
    scope: input.scope,
    granteePrincipalId: input.grantee.principalId,
    fieldScope,
    recipientEncryptionKey: input.grantee.publicKey,
    validAfter: createdGrant.record.validAfter,
    expiresAt: createdGrant.record.expiresAt,
  });
  try {
    const payload: RecipientProofPackagePayload = {
      packageVersion: "payo-recipient-proof-package-v1",
      grant,
      journal,
      proofPackage,
      verification: {
        verified: true,
        verificationState: "onchain_verified",
        verifierAddress: common.sealAddress,
        proofVersion: common.proofVersion,
        publicInputsHash,
        verificationTransactionHash,
        checkedAt,
      },
      starknetReceipt: settlement,
      disclosedFields: disclosedFields({ fieldScope, lines: scopedLines, sourceLines: scopedSourceLines, settlement, exception }),
      ...(lineOpening ? { lineOpening: await lineOpening } : {}),
    };
    return {
      grant,
      encryptedPackage: createRecipientEncryptedProofPackage({ payload, recipient: input.grantee, at: now }),
    };
  } catch (error) {
    await input.client.revokeDisclosureGrant(input.organizationId, createdGrant.record.id).catch(() => undefined);
    throw error;
  }
}
