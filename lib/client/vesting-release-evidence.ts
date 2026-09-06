import { z } from "zod";
import { readyWalletPrincipalId, READY_AUTH_CHAIN_ID } from "@/lib/auth/ready-session";
import { agreementProofScheduleCommitment, type PayAgreementDirectoryRecord } from "@/lib/client/agreement-directory";
import type { PayoClient, VestingAuthorizationStatus } from "@/lib/client/payo-client";
import type { PayeeDirectoryRecord } from "@/lib/client/payee-directory";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  decryptVaultRecord,
  encryptedVaultRecordSchema,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { advancedPlanEntitlement } from "@/lib/domain/obligations";
import { calculatePayrollLine, privatePayrollLineSchema } from "@/lib/domain/payroll";
import { payAgreementRecordSchema } from "@/lib/domain/records";
import {
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { formatTokenAmount } from "@/lib/starknet/tokens";

const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const transactionHashSchema = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const atomicSchema = z.string().regex(/^(0|[1-9]\d*)$/);

export const PAYO_VESTING_V3_MAINNET_CONTRACTS = Object.freeze({
  verifier: "0x4b35d2d366848169ea4fb32d4fffda498b5251160da2e60fc53030a37d5551c",
  bundle: "0x1bc7517191802bf82ccfb60fa4f27f9306d6cfee9160b545d7dea662e8870a8",
  vestingBookSeal: "0x5208cc07cb4153235ab5c6ecd1936ee77f9be7a2ea09f6cc69518a6362493f",
} as const);

const vestingReleaseEvidenceCoreSchema = z.object({
  packageVersion: z.literal("payo-vesting-release-evidence-v1"),
  evidenceType: z.literal("private-vesting-release"),
  sourceId: z.string().min(8).max(128),
  releaseReference: z.string().min(32).max(640),
  organizationId: z.string().min(8).max(128),
  generatedAt: z.string().datetime(),
  privacyNotice: z.string().min(20).max(500),
  recipient: z.object({
    payeeId: z.string().min(8).max(128),
    directoryPrincipalId: z.string().min(1).max(160),
    identityPrincipalId: z.string().min(1).max(160).nullable(),
    walletPrincipalId: z.string().min(16).max(320),
    walletAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
  }).strict(),
  release: z.object({
    runId: z.string().min(8).max(128),
    settlementId: z.string().min(8).max(128),
    agreementId: z.string().min(1).max(160),
    agreementRevision: z.number().int().positive(),
    releaseNumber: z.number().int().positive(),
    sequenceBefore: z.number().int().nonnegative(),
    sequenceAfter: z.number().int().positive(),
    checkpointAt: z.string().datetime(),
    startsAt: z.string().datetime(),
    cliffAt: z.string().datetime(),
    endsAt: z.string().datetime(),
    token: z.enum(["STRK", "USDC"]),
    totalAtomic: atomicSchema,
    previouslyReleasedAtomic: atomicSchema,
    cumulativeReleasedAtomic: atomicSchema,
    grossReleaseAtomic: atomicSchema,
    deductionsAtomic: atomicSchema,
    netPaidAtomic: atomicSchema,
    display: z.object({
      grossRelease: z.string().min(1),
      deductions: z.string().min(1),
      netPaid: z.string().min(1),
      cumulativeReleased: z.string().min(1),
    }).strict(),
  }).strict(),
  proof: z.object({
    authorizationMode: z.literal("vesting_book_v3"),
    authorizationId: z.string().min(8).max(128),
    proofBundleId: z.string().min(8).max(128),
    authorizationState: z.literal("complete"),
    proofVersion: z.literal(3),
    circuitSha256: commitmentSchema,
    verificationKeySha256: commitmentSchema,
    agreementRoot: commitmentSchema,
    manifestRoot: commitmentSchema,
    policyRoot: commitmentSchema,
    fxRoot: commitmentSchema,
    runNullifier: commitmentSchema,
    tokenTotalsCommitment: commitmentSchema,
    proofValidityExpiry: atomicSchema.nullable(),
    agreementCommitment: commitmentSchema,
    scheduleCommitment: commitmentSchema,
  }).strict(),
  onchain: z.object({
    network: z.literal("starknet-mainnet"),
    chainId: z.literal(READY_AUTH_CHAIN_ID),
    contracts: z.object({
      vestingTransitionVerifierV3: z.literal(PAYO_VESTING_V3_MAINNET_CONTRACTS.verifier),
      vestingTransitionBundleV3: z.literal(PAYO_VESTING_V3_MAINNET_CONTRACTS.bundle),
      vestingBookSeal: z.literal(PAYO_VESTING_V3_MAINNET_CONTRACTS.vestingBookSeal),
    }).strict(),
    authorizationTransactions: z.object({
      begin: transactionHashSchema,
      payrollShard0: transactionHashSchema,
      payrollShard1: transactionHashSchema,
      transitionShard0: transactionHashSchema,
      transitionShard1: transactionHashSchema,
    }).strict(),
    authorizationCompletedAt: z.string().datetime(),
    paymentTransactionHash: transactionHashSchema,
    paymentBlockNumber: atomicSchema,
    paymentConfirmedAt: z.string().datetime(),
    confirmationDepth: z.number().int().nonnegative(),
  }).strict(),
}).strict();

export const vestingReleaseEvidenceSchema = vestingReleaseEvidenceCoreSchema.extend({
  evidenceCommitment: commitmentSchema,
}).strict();
export type VestingReleaseEvidence = z.infer<typeof vestingReleaseEvidenceSchema>;

const decryptedRunSchema = z.object({
  schemaVersion: z.literal(1),
  dueAt: z.string().datetime(),
  agreementRoot: commitmentSchema,
  manifestRoot: commitmentSchema,
  policyRoot: commitmentSchema,
  fxRoot: commitmentSchema,
  runNullifier: commitmentSchema,
  manifest: z.object({
    lines: z.array(privatePayrollLineSchema).min(1).max(50),
  }).passthrough(),
}).passthrough();

type SettlementForVestingEvidence = {
  id: string;
  runId: string;
  workflowType: "payroll" | "wage_claim" | "wage_remediation";
  subjectRecordId: string;
  state: string;
  tokenTotalsCommitment: string;
  transactionHash: string | null;
  confirmedAt: string | null;
  blockNumber: string | null;
  confirmationDepth: number;
  proofValidityExpiry: string | null;
};

function sameFelt(left: string | null, right: string): boolean {
  try {
    return left !== null && BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

function releaseReference(input: { organizationId: string; runId: string; settlementId: string }): string {
  return [
    "payo",
    "vesting-release",
    "v1",
    READY_AUTH_CHAIN_ID,
    input.organizationId,
    input.runId,
    input.settlementId,
  ].join(":");
}

export function decryptedRunAgreementIds(
  envelopeInput: unknown,
  principal: VaultPrincipalKeyPair,
): string[] {
  const envelope = encryptedVaultRecordSchema.parse(envelopeInput);
  const payload = decryptedRunSchema.parse(decryptVaultRecord(envelope, principal));
  return payload.manifest.lines.map(({ agreementId }) => agreementId);
}

async function findExactAgreementRevision(input: {
  client: Pick<PayoClient, "getEncryptedRecord">;
  current: PayAgreementDirectoryRecord;
  organizationId: string;
  scheduleCommitment: string;
  principal: VaultPrincipalKeyPair;
}): Promise<PayAgreementDirectoryRecord> {
  for (let revision = input.current.revision; revision >= 1; revision -= 1) {
    let candidate: PayAgreementDirectoryRecord;
    if (revision === input.current.revision) {
      candidate = input.current;
    } else {
      const response = await input.client.getEncryptedRecord({
        organizationId: input.organizationId,
        recordId: input.current.id,
        revision,
      });
      const stored = response.record as { id?: unknown; revision?: unknown; envelope?: unknown };
      if (stored.id !== input.current.id || stored.revision !== revision || !stored.envelope) {
        throw new Error("A historical vesting agreement revision has invalid storage metadata.");
      }
      const envelope = encryptedVaultRecordSchema.parse(stored.envelope);
      candidate = payAgreementRecordSchema.parse(decryptVaultRecord(envelope, input.principal));
      if (
        candidate.organizationId !== input.organizationId
        || candidate.id !== input.current.id
        || candidate.revision !== revision
      ) throw new Error("A historical vesting agreement revision has invalid encrypted identity.");
    }
    const scheduleCommitment = candidate.proofScheduleCommitment
      ?? await agreementProofScheduleCommitment(candidate.agreement);
    if (sameFelt(scheduleCommitment, input.scheduleCommitment)) {
      return candidate.proofScheduleCommitment ? candidate : { ...candidate, proofScheduleCommitment: scheduleCommitment };
    }
  }
  throw new Error("The exact encrypted vesting agreement revision for this release was not found.");
}

function completeAuthorizationTransactions(authorization: VestingAuthorizationStatus) {
  const transactions = {
    begin: authorization.beginTransactionHash,
    payrollShard0: authorization.payrollShard0TransactionHash,
    payrollShard1: authorization.payrollShard1TransactionHash,
    transitionShard0: authorization.transitionShard0TransactionHash,
    transitionShard1: authorization.transitionShard1TransactionHash,
  };
  if (Object.values(transactions).some((value) => !value)) {
    throw new Error("The vesting authorization is missing one or more Mainnet transaction hashes.");
  }
  return transactions as { [Key in keyof typeof transactions]: string };
}

export function createVestingReleaseEvidence(input: {
  organizationId: string;
  settlement: SettlementForVestingEvidence;
  run: {
    id: string;
    organizationId: string;
    state: string;
    agreementRoot: string | null;
    manifestRoot: string | null;
    policyRoot: string | null;
    fxRoot: string | null;
    runNullifier: string | null;
    transactionHash: string | null;
  };
  decryptedRun: z.infer<typeof decryptedRunSchema>;
  lineAgreement: PayAgreementDirectoryRecord;
  payee: PayeeDirectoryRecord;
  authorization: VestingAuthorizationStatus;
  now?: Date;
}): VestingReleaseEvidence {
  const { settlement, run, decryptedRun, lineAgreement, payee, authorization } = input;
  if (
    settlement.workflowType !== "payroll"
    || settlement.runId !== run.id
    || settlement.subjectRecordId !== run.id
    || !["confirmed", "finalized", "reconciled"].includes(settlement.state)
    || !settlement.transactionHash
    || !settlement.blockNumber
    || !settlement.confirmedAt
  ) throw new Error("Only a confirmed Mainnet payroll settlement can produce vesting release evidence.");
  if (
    run.organizationId !== input.organizationId
    || !["confirmed", "reconciled"].includes(run.state)
    || !run.transactionHash
    || !sameFelt(run.transactionHash, settlement.transactionHash)
  ) throw new Error("The vesting run and confirmed settlement do not share one payment transaction.");
  for (const [key, value] of Object.entries({
    agreementRoot: run.agreementRoot,
    manifestRoot: run.manifestRoot,
    policyRoot: run.policyRoot,
    fxRoot: run.fxRoot,
    runNullifier: run.runNullifier,
  })) {
    if (!value || !sameFelt(value, decryptedRun[key as keyof Pick<typeof decryptedRun, "agreementRoot" | "manifestRoot" | "policyRoot" | "fxRoot" | "runNullifier">])) {
      throw new Error(`The encrypted vesting run does not match its public ${key}.`);
    }
  }
  if (
    authorization.organizationId !== input.organizationId
    || authorization.runId !== run.id
    || authorization.state !== "complete"
    || !authorization.authorizedAt
  ) throw new Error("The release does not have a complete vesting_book_v3 authorization.");
  if (
    lineAgreement.organizationId !== input.organizationId
    || lineAgreement.payeeId !== payee.id
    || lineAgreement.agreement.agreementVersion !== "payo-agreement-v2"
    || lineAgreement.agreement.paymentPlan.kind !== "private_vesting"
  ) throw new Error("The release source is not an exact private vesting agreement.");
  const lineInput = decryptedRun.manifest.lines.find(({ agreementId }) =>
    agreementId === lineAgreement.agreement.id);
  if (!lineInput) throw new Error("The vesting agreement is absent from the encrypted payroll manifest.");
  if (!sameFelt(lineAgreement.proofScheduleCommitment ?? "", lineInput.scheduleCommitment)) {
    throw new Error("The vesting release schedule commitment differs from its payroll proof.");
  }
  if (!sameFelt(lineInput.recipientAddress, payee.recipientAddress)) {
    throw new Error("The vesting release recipient differs from the encrypted contributor wallet.");
  }
  const plan = lineAgreement.agreement.paymentPlan;
  if (new Date(plan.releaseAt).getTime() !== new Date(decryptedRun.dueAt).getTime()) {
    throw new Error("The vesting checkpoint differs from the immutable payroll due time.");
  }
  const calculated = calculatePayrollLine(lineInput);
  const entitlement = advancedPlanEntitlement(plan, new Date(plan.releaseAt));
  if (
    !entitlement.due
    || entitlement.sequence !== plan.releaseSequence
    || entitlement.payableAtomic !== BigInt(calculated.grossAtomic)
  ) throw new Error("The payroll amount does not equal the deterministic vesting entitlement.");
  const transactions = completeAuthorizationTransactions(authorization);
  const token = calculated.token;
  const core = vestingReleaseEvidenceCoreSchema.parse({
    packageVersion: "payo-vesting-release-evidence-v1",
    evidenceType: "private-vesting-release",
    sourceId: settlement.id,
    releaseReference: releaseReference({
      organizationId: input.organizationId,
      runId: run.id,
      settlementId: settlement.id,
    }),
    organizationId: input.organizationId,
    generatedAt: (input.now ?? new Date()).toISOString(),
    privacyNotice: "This employer-held evidence names one private recipient and exact vesting amounts. Share it only with the intended worker, reviewer, or authority.",
    recipient: {
      payeeId: payee.id,
      directoryPrincipalId: payee.principalId,
      identityPrincipalId: payee.claimIdentityPrincipalId ?? null,
      walletPrincipalId: readyWalletPrincipalId(READY_AUTH_CHAIN_ID, calculated.recipientAddress),
      walletAddress: calculated.recipientAddress,
    },
    release: {
      runId: run.id,
      settlementId: settlement.id,
      agreementId: lineAgreement.agreement.id,
      agreementRevision: lineAgreement.revision,
      releaseNumber: plan.releaseSequence + 1,
      sequenceBefore: plan.releaseSequence,
      sequenceAfter: plan.releaseSequence + 1,
      checkpointAt: plan.releaseAt,
      startsAt: plan.startsAt,
      cliffAt: plan.cliffAt,
      endsAt: plan.endsAt,
      token,
      totalAtomic: plan.totalAtomic,
      previouslyReleasedAtomic: plan.releasedAtomic,
      cumulativeReleasedAtomic: entitlement.cumulativeEntitlementAtomic.toString(),
      grossReleaseAtomic: calculated.grossAtomic,
      deductionsAtomic: calculated.deductionsTotalAtomic,
      netPaidAtomic: calculated.netAtomic,
      display: {
        grossRelease: `${formatTokenAmount(BigInt(calculated.grossAtomic), token)} ${token}`,
        deductions: `${formatTokenAmount(BigInt(calculated.deductionsTotalAtomic), token)} ${token}`,
        netPaid: `${formatTokenAmount(BigInt(calculated.netAtomic), token)} ${token}`,
        cumulativeReleased: `${formatTokenAmount(entitlement.cumulativeEntitlementAtomic, token)} ${token}`,
      },
    },
    proof: {
      authorizationMode: "vesting_book_v3",
      authorizationId: authorization.id,
      proofBundleId: authorization.payrollProofBundleId,
      authorizationState: "complete",
      proofVersion: 3,
      circuitSha256: VESTING_TRANSITION_CIRCUIT_SHA256,
      verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
      agreementRoot: run.agreementRoot,
      manifestRoot: run.manifestRoot,
      policyRoot: run.policyRoot,
      fxRoot: run.fxRoot,
      runNullifier: run.runNullifier,
      tokenTotalsCommitment: settlement.tokenTotalsCommitment,
      proofValidityExpiry: settlement.proofValidityExpiry,
      agreementCommitment: lineAgreement.agreementCommitment,
      scheduleCommitment: lineInput.scheduleCommitment,
    },
    onchain: {
      network: "starknet-mainnet",
      chainId: READY_AUTH_CHAIN_ID,
      contracts: {
        vestingTransitionVerifierV3: PAYO_VESTING_V3_MAINNET_CONTRACTS.verifier,
        vestingTransitionBundleV3: PAYO_VESTING_V3_MAINNET_CONTRACTS.bundle,
        vestingBookSeal: PAYO_VESTING_V3_MAINNET_CONTRACTS.vestingBookSeal,
      },
      authorizationTransactions: transactions,
      authorizationCompletedAt: authorization.authorizedAt,
      paymentTransactionHash: settlement.transactionHash,
      paymentBlockNumber: settlement.blockNumber,
      paymentConfirmedAt: settlement.confirmedAt,
      confirmationDepth: settlement.confirmationDepth,
    },
  });
  return vestingReleaseEvidenceSchema.parse({
    ...core,
    evidenceCommitment: hashCanonicalJson(core),
  });
}

export function verifyVestingReleaseEvidence(value: unknown): VestingReleaseEvidence {
  const evidence = vestingReleaseEvidenceSchema.parse(value);
  const { evidenceCommitment, ...core } = evidence;
  if (hashCanonicalJson(core) !== evidenceCommitment) {
    throw new Error("The vesting release evidence commitment is invalid.");
  }
  if (
    evidence.releaseReference !== releaseReference({
      organizationId: evidence.organizationId,
      runId: evidence.release.runId,
      settlementId: evidence.release.settlementId,
    })
    || evidence.recipient.walletPrincipalId !== readyWalletPrincipalId(
      evidence.onchain.chainId,
      evidence.recipient.walletAddress,
    )
  ) throw new Error("The vesting release reference is inconsistent.");
  if (
    BigInt(evidence.release.previouslyReleasedAtomic) + BigInt(evidence.release.grossReleaseAtomic)
      !== BigInt(evidence.release.cumulativeReleasedAtomic)
    || BigInt(evidence.release.grossReleaseAtomic) - BigInt(evidence.release.deductionsAtomic)
      !== BigInt(evidence.release.netPaidAtomic)
    || evidence.release.sequenceAfter !== evidence.release.sequenceBefore + 1
    || evidence.release.releaseNumber !== evidence.release.sequenceAfter
  ) throw new Error("The vesting release amount or sequence is inconsistent.");
  return evidence;
}

export async function loadVestingReleaseEvidence(input: {
  client: Pick<PayoClient, "getPayrollRun" | "getEncryptedRecord" | "getVestingAuthorization">;
  organizationId: string;
  settlement: SettlementForVestingEvidence;
  agreements: readonly PayAgreementDirectoryRecord[];
  payees: readonly PayeeDirectoryRecord[];
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<VestingReleaseEvidence> {
  const { run } = await input.client.getPayrollRun(input.settlement.runId);
  const decryptedRun = decryptedRunSchema.parse(decryptVaultRecord(run.envelope, input.principal));
  const vestingAgreementIds = new Set(input.agreements.flatMap((record) =>
    record.agreement.agreementVersion === "payo-agreement-v2"
    && record.agreement.paymentPlan.kind === "private_vesting"
      ? [record.agreement.id]
      : []));
  const vestingLines = decryptedRun.manifest.lines.filter(({ agreementId }) =>
    vestingAgreementIds.has(agreementId));
  if (vestingLines.length !== 1) {
    throw new Error("This payroll is not a single private vesting release.");
  }
  const current = input.agreements.find(({ agreement }) =>
    agreement.id === vestingLines[0].agreementId);
  if (!current) throw new Error("The encrypted vesting agreement is unavailable.");
  const exact = await findExactAgreementRevision({
    client: input.client,
    current,
    organizationId: input.organizationId,
    scheduleCommitment: vestingLines[0].scheduleCommitment,
    principal: input.principal,
  });
  const payee = input.payees.find(({ id }) => id === exact.payeeId);
  if (!payee) throw new Error("The encrypted vesting recipient is unavailable.");
  const { authorization } = await input.client.getVestingAuthorization(run.id);
  return createVestingReleaseEvidence({
    organizationId: input.organizationId,
    settlement: input.settlement,
    run,
    decryptedRun,
    lineAgreement: exact,
    payee,
    authorization,
    now: input.now,
  });
}

export function vestingReleaseEvidenceFilename(evidence: VestingReleaseEvidence): string {
  return `payo-vesting-release-${evidence.release.runId}.json`;
}
