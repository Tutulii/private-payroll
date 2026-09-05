import type { STRK20_INVOKE_ACTION } from "starknet";
import { z } from "zod";
import { formatTokenAmount, type PayrollTokenSymbol } from "@/app/starknet/tokens";
import {
  prepareEncryptedExceptionProofBundle,
  prepareEncryptedPayrollIntegrityBundle,
} from "@/lib/client/proof-bundle";
import { openStoredPayrollBookProof } from "@/lib/client/payroll-proof-recovery";
import { PayoApiError, PayoClient, prepareEncryptedPayrollRun } from "@/lib/client/payo-client";
import { hashRecipientCommitment } from "@/lib/crypto/commitments";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { toHex } from "@/lib/crypto/encoding";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  encryptedVaultRecordSchema,
  type EncryptedVaultRecord,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import type { PrivatePayrollLine } from "@/lib/domain/payroll";
import type { ObligationSnapshotPlanPrivate } from "@/lib/domain/obligation-snapshot-plan";
import {
  fxCatalogPublicationWindow,
  type FxSnapshot,
} from "@/lib/domain/fx";
import { isAgreementDue, type EmploymentAgreement } from "@/lib/domain/obligations";
import { generateUuidV7, settlementRecordSchema } from "@/lib/domain/records";
import { commitAgentSettlementPlan, commitTokenTotals } from "@/lib/domain/settlement";
import { vestingStateSalt } from "@/lib/domain/vesting-tax";
import { policyPackCommitment } from "@/lib/policy/engine";
import {
  calculatePolicyDeductions,
  resolveExecutionPolicyForAgreement,
  resolvePayrollPolicyCohort,
} from "@/lib/policy/execution-catalog";
import {
  buildFxCatalogRoot,
  buildPayrollAgreementRoot,
  buildPayrollIntegrityInputsFromSerialized,
  randomCommitmentSalt,
  serializePayrollIntegrityBuildRequest,
  type PayrollIntegrityLineInput,
  type SerializedPayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";
import { buildObligationSnapshotLinkInputs } from "@/lib/proof/exception-input-builder";
import { advancedPlanProofCommitment } from "@/lib/proof/advanced-plan-commitment";
import { proveEncryptedPayroll, type ProofProgressListener } from "@/lib/proof/client";
import {
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
  type ExceptionProofWorkerSuccess,
  type ProofWorkerSuccess,
  type VestingBookProof,
} from "@/lib/proof/protocol";
import { buildPayoSealedPayroll } from "@/lib/starknet/payo-seal";
import { buildAuthorizedPayrollAction } from "@/lib/starknet/payo-exception-seal";
import { buildVestingBookAction } from "@/lib/starknet/payo-vesting-book";
import {
  agreementScheduleCommitment,
  recordProofScheduleCommitment,
  type PayAgreementDirectoryRecord,
} from "./agreement-directory";
import type { PayeeDirectoryRecord } from "./payee-directory";
import { awaitWalletOrRecoveredTransaction, readRecoveredSettlementTransactionHash } from "./wallet-submission-recovery";

export type PayrollExecutionObligation = {
  agreement: PayAgreementDirectoryRecord;
  payee: PayeeDirectoryRecord;
};

type AdvancedEmploymentAgreement = Extract<EmploymentAgreement, { agreementVersion: "payo-agreement-v2" }>;
type PrivateVestingAgreement = AdvancedEmploymentAgreement & {
  paymentPlan: Extract<AdvancedEmploymentAgreement["paymentPlan"], { kind: "private_vesting" }>;
};

function isPrivateVestingAgreement(agreement: EmploymentAgreement): agreement is PrivateVestingAgreement {
  return agreement.agreementVersion === "payo-agreement-v2"
    && agreement.paymentPlan.kind === "private_vesting";
}

export function payrollAgreementDueAt(record: PayAgreementDirectoryRecord): bigint {
  const agreement = record.agreement;
  const dueAt = agreement.agreementVersion === "payo-agreement-v2"
    ? agreement.paymentPlan.kind === "recurring"
      ? agreement.paymentPlan.nextDueAt
      : agreement.paymentPlan.kind === "checkpoint_stream"
        ? agreement.paymentPlan.checkpoint.checkpointAt
        : agreement.paymentPlan.kind === "milestone"
          ? agreement.paymentPlan.dueAt
          : agreement.paymentPlan.releaseAt
    : agreement.schedule.kind === "recurring"
      ? agreement.schedule.nextDueAt
      : agreement.schedule.kind === "milestone"
        ? agreement.schedule.dueAt
        : agreement.schedule.kind === "stream"
          ? agreement.schedule.startsAt
          : agreement.schedule.cliffAt;
  const milliseconds = new Date(dueAt).getTime();
  if (!Number.isSafeInteger(milliseconds)) {
    throw new Error(`Agreement ${agreement.id} has an invalid payday.`);
  }
  return BigInt(Math.floor(milliseconds / 1_000));
}

export type PayrollExecutionStage =
  | "fx"
  | "authorizing"
  | "loading"
  | "executing"
  | "proving"
  | "verifying"
  | "encoding"
  | "preflight"
  | "snapshot"
  | "proof_authorization"
  | "persisting"
  | "agent_policy"
  | "wallet"
  | "wallet_recovery"
  | "recording"
  | "recorded"
  | "queued";

export type PendingPayrollSubmission = {
  version: 3 | 4 | 5;
  organizationId: string;
  runId: string;
  proofBundleId: string;
  settlementId: string;
  walletRequestId: string;
  idempotencyKey: string;
  tokenTotalsCommitment: `0x${string}`;
  settlementEnvelope: EncryptedVaultRecord;
  proofShards: [string[], string[]];
  authorizationMode?: "staged_vnext" | "vesting_book_v3";
  snapshotProofBundleId?: string;
  transactionHash?: string;
  createdAt: string;
};

export type PayrollExecutionResult = PendingPayrollSubmission & {
  settlementId: string;
  transactionHash: string;
  verificationQueued: boolean;
  proofDeliveryWarning?: string;
};

export type AutonomousPayrollPreparationResult = {
  mode: "autonomous_bounded";
  organizationId: string;
  capabilityId: string;
  runId: string;
  runVersion: number;
  proofBundleId: string;
  accountId: string;
  policyId: string;
  witnessCommitment: string;
  activationState: "pending" | "active";
  configurationTransactionHash?: string;
};

const PAYROLL_PROOF_DELIVERY_WARNING =
  "The private payment is submitted and durably recorded, but its ZK proof was not queued. PAYO will retry from the encrypted vault without another wallet request; use a fresh payroll for claims if the proof window has expired.";

export function buildPayrollExecutionLines(input: {
  organizationId: string;
  obligations: readonly PayrollExecutionObligation[];
  validityStart: bigint;
  createLineSalt?: () => `0x${string}`;
  advancedScheduleCommitments?: ReadonlyMap<string, `0x${string}`>;
}): PayrollIntegrityLineInput[] {
  return input.obligations.map(({ agreement: record, payee }) => {
    const agreement = record.agreement;
    if (
      record.organizationId !== input.organizationId
      || agreement.organizationId !== input.organizationId
      || payee.organizationId !== input.organizationId
      || record.payeeId !== payee.id
    ) throw new Error("A selected obligation does not belong to this encrypted organization directory.");
    if (payee.status !== "active" || record.effectiveUntil) {
      throw new Error(`Agreement ${agreement.id} is not active.`);
    }
    if (agreement.settlementToken !== payee.tokenPreference) {
      throw new Error(`Agreement ${agreement.id} does not match its payee token commitment.`);
    }
    const recipientCommitment = toHex(hashRecipientCommitment(payee.recipientAddress, record.recipientSalt));
    if (BigInt(recipientCommitment) !== BigInt(record.recipientCommitment)) {
      throw new Error(`Agreement ${agreement.id} does not match its committed payout recipient.`);
    }
    const agreementCommitment = hashCanonicalJson({
      domain: "PAYO_ENCRYPTED_AGREEMENT_V1",
      agreement,
      recipientCommitment: record.recipientCommitment,
      agreementSalt: record.agreementSalt,
    });
    if (BigInt(agreementCommitment) !== BigInt(record.agreementCommitment)) {
      throw new Error(`Agreement ${agreement.id} failed its encrypted-record commitment check.`);
    }
    if (
      (payee.principalKind === "agent" && agreement.classification !== "agent_service")
      || (payee.principalKind === "human" && agreement.classification === "agent_service")
    ) throw new Error(`Agreement ${agreement.id} does not match its committed contributor kind.`);
    if (!isAgreementDue(agreement, new Date(Number(input.validityStart) * 1_000))) {
      throw new Error(`Agreement ${agreement.id} is not due yet.`);
    }
    const policy = resolveExecutionPolicyForAgreement(
      agreement,
      new Date(Number(input.validityStart) * 1_000),
    );
    const referenceCurrency = agreement.fxProtection?.referenceCurrency ?? "USD";
    if (referenceCurrency !== "USD" && referenceCurrency !== "GBP") {
      throw new Error(`Agreement ${agreement.id} selects an unsupported proof reference currency.`);
    }
    const dueAt = payrollAgreementDueAt(record);
    const validUntil = record.effectiveUntil
      ? BigInt(Math.floor(new Date(record.effectiveUntil).getTime() / 1_000))
      : 253_402_300_799n;
    return {
      agreementId: agreement.id,
      recipientAddress: payee.recipientAddress,
      recipientSalt: record.recipientSalt as `0x${string}`,
      agreementSalt: record.agreementSalt as `0x${string}`,
      lineSalt: input.createLineSalt?.() ?? randomCommitmentSalt(),
      token: agreement.settlementToken,
      earningsAtomic: agreement.earningsAtomic,
      deductionsAtomic: calculatePolicyDeductions(policy, agreement.earningsAtomic),
      policyId: agreement.statutoryPolicy.policyId,
      scheduleCommitment: agreement.agreementVersion === "payo-agreement-v2"
        ? input.advancedScheduleCommitments?.get(agreement.id) ?? agreementScheduleCommitment(agreement)
        : agreementScheduleCommitment(agreement),
      dueAt,
      validUntil,
      classification: agreement.classification === "employee"
        ? {
            declared: 1 as const,
            score: agreement.classificationAssessment?.score ?? 5,
            employeeThreshold: agreement.classificationAssessment?.employeeThreshold ?? 5,
          }
        : {
            declared: 2 as const,
            score: agreement.classificationAssessment?.score ?? 2,
            employeeThreshold: agreement.classificationAssessment?.employeeThreshold ?? 5,
          },
      ...(agreement.agreementVersion === "payo-agreement-v2" && agreement.termination
        ? {
            finalPay: {
              requiredMask: (agreement.termination.pay.requiredComponents.accruedLeave ? 1 : 0)
                | (agreement.termination.pay.requiredComponents.notice ? 2 : 0)
                | (agreement.termination.pay.requiredComponents.severance ? 4 : 0),
              includedMask: (agreement.termination.pay.includedComponents.accruedLeave ? 1 : 0)
                | (agreement.termination.pay.includedComponents.notice ? 2 : 0)
                | (agreement.termination.pay.includedComponents.severance ? 4 : 0),
              componentsAtomic: [
                agreement.termination.pay.ordinaryPayAtomic,
                agreement.termination.pay.accruedLeaveAtomic,
                agreement.termination.pay.noticeAtomic,
                agreement.termination.pay.severanceAtomic,
                agreement.termination.pay.adjustmentsAtomic,
              ],
            },
          }
        : {}),
      fxFloorAtomic: agreement.fxProtection?.minimumReferenceAtomic ?? "0",
      referenceCurrency,
    };
  });
}

export async function preparePayrollObligationRoot(input: {
  organizationId: string;
  obligations: readonly PayrollExecutionObligation[];
  at?: Date;
}): Promise<{ root: `0x${string}`; lines: PayrollIntegrityLineInput[] }> {
  if (input.obligations.length < 1 || input.obligations.length > 50) {
    throw new Error("An obligation-root schedule requires 1–50 authoritative obligations.");
  }
  const at = input.at ?? new Date();
  const policies = resolvePayrollPolicyCohort(
    input.obligations.map(({ agreement }) => agreement.agreement),
    at,
  );
  const advancedScheduleCommitments = new Map<string, `0x${string}`>(await Promise.all(
    input.obligations.flatMap(({ agreement }) => agreement.agreement.agreementVersion === "payo-agreement-v2"
      ? [advancedPlanProofCommitment(agreement.agreement).then((commitment) => [agreement.agreement.id, commitment] as const)]
      : []),
  ));
  const lines = buildPayrollExecutionLines({
    organizationId: input.organizationId,
    obligations: input.obligations,
    validityStart: BigInt(Math.floor(at.getTime() / 1_000)),
    // Salary-line salts do not enter the agreement root. A fixed value keeps
    // this preflight deterministic and makes accidental coupling testable.
    createLineSalt: () => `0x${"00".repeat(32)}`,
    advancedScheduleCommitments,
  });
  return {
    root: await buildPayrollAgreementRoot({
      policies,
      lines,
    }),
    lines,
  };
}

export function derivePayrollCycleId(
  organizationId: string,
  obligations: readonly PayrollExecutionObligation[],
): string {
  return `payday:${hashCanonicalJson({
    domain: "PAYO_OBLIGATION_CYCLE_V1",
    organizationId,
    obligations: obligations.map(({ agreement }) => ({
      agreementId: agreement.agreement.id,
      schedule: agreement.agreement.schedule,
    })).sort((left, right) => left.agreementId.localeCompare(right.agreementId)),
  }).slice(2, 50)}`;
}

export class PayrollSubmissionPersistenceError extends Error {
  constructor(
    message: string,
    readonly pendingSubmission: PendingPayrollSubmission,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "PayrollSubmissionPersistenceError";
  }
}

const pendingPayrollSubmissionV2Schema = z.object({
  version: z.literal(2),
  organizationId: z.string().uuid(),
  runId: z.string().uuid(),
  proofBundleId: z.string().uuid(),
  settlementId: z.string().uuid(),
  walletRequestId: z.string().uuid(),
  idempotencyKey: z.string().min(16).max(256),
  tokenTotalsCommitment: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  settlementEnvelope: encryptedVaultRecordSchema,
  proofShards: z.tuple([
    z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
  ]),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
  createdAt: z.string().datetime(),
}).strict();

const pendingPayrollSubmissionV3Schema = pendingPayrollSubmissionV2Schema.extend({
  version: z.literal(3),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/).optional(),
}).strict();

const pendingPayrollSubmissionV4Schema = pendingPayrollSubmissionV3Schema.extend({
  version: z.literal(4),
  authorizationMode: z.literal("staged_vnext"),
  snapshotProofBundleId: z.string().uuid(),
}).strict();

const pendingPayrollSubmissionV5Schema = pendingPayrollSubmissionV3Schema.extend({
  version: z.literal(5),
  authorizationMode: z.literal("vesting_book_v3"),
}).strict();

export function parsePendingPayrollSubmission(input: unknown): PendingPayrollSubmission {
  const parsed = z.union([
    pendingPayrollSubmissionV5Schema,
    pendingPayrollSubmissionV4Schema,
    pendingPayrollSubmissionV3Schema,
    pendingPayrollSubmissionV2Schema,
  ]).parse(input);
  return (parsed.version >= 4 ? parsed : { ...parsed, version: 3 }) as PendingPayrollSubmission;
}

type ProvePayroll = (input: {
  encryptedWitness: Parameters<typeof proveEncryptedPayroll>[0]["encryptedWitness"];
  principal: VaultPrincipalKeyPair;
  onProgress?: ProofProgressListener;
}) => Promise<ProofWorkerSuccess>;

type ProveSnapshot = (input: {
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
  onProgress?: ProofProgressListener;
}) => Promise<ExceptionProofWorkerSuccess>;

export type ExecuteProofBoundPayrollInput = {
  client: PayoClient;
  organizationId: string;
  organizationSecret: string;
  principal: VaultPrincipalKeyPair;
  chainId: string;
  sealAddress: string;
  obligations: readonly PayrollExecutionObligation[];
  submitPayroll: (
    recipients: Array<{ address: string; amount: string; token: PayrollTokenSymbol }>,
    action: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  onStage?: (stage: PayrollExecutionStage) => void;
  persistPendingSubmission?: (submission: PendingPayrollSubmission | null) => void;
  prove?: ProvePayroll;
  snapshotPlan?: ObligationSnapshotPlanPrivate;
  proveSnapshot?: ProveSnapshot;
  vestingBook?: {
    ownerAddress: string;
    bookSealAddress?: string;
    entryKind?: "ordinary" | "agent";
    attestation?: import("@/lib/proof/vesting-transition-input").ExternalAttestationProofInput;
  };
  authorizeFxRoot?: (input: {
    root: `0x${string}`;
    snapshots: readonly FxSnapshot[];
    publicationWindow: ReturnType<typeof fxCatalogPublicationWindow>;
    publicationTicket: string;
    proof: ProofWorkerSuccess;
  }) => Promise<void>;
  runRevision?: number;
  authorizationPollIntervalMs?: number;
  authorizationTimeoutMs?: number;
  humanAgentApproval?: {
    capabilityId: string;
    executionId: string;
  };
  onRecoveredTransactionHash?: (transactionHash: string) => void | Promise<void>;
  walletRecoveryPollIntervalMs?: number;
  walletRecoveryTimeoutMs?: number;
  walletRecoveryNoticeDelayMs?: number;
  now?: () => Date;
};

export type PrepareAutonomousPayrollInput = Omit<
  ExecuteProofBoundPayrollInput,
  "submitPayroll" | "humanAgentApproval" | "persistPendingSubmission"
> & {
  autonomousAgent: {
    capabilityId: string;
    policyAccountAddress: string;
    validForSeconds?: number;
  };
};

const STARK_FIELD_PRIME = (1n << 251n) + 17n * (1n << 192n) + 1n;

function autonomousPolicyId(capabilityId: string, runId: string): `0x${string}` {
  const digest = BigInt(hashCanonicalJson({
    domain: "PAYO_AUTONOMOUS_POLICY_ID_V1",
    capabilityId,
    runId,
  })) % STARK_FIELD_PRIME;
  return `0x${(digest === 0n ? 1n : digest).toString(16)}`;
}

type ResumableEncryptedPayrollRun = {
  state: "draft" | "calculated" | "proven";
  buildInput: SerializedPayrollIntegrityBuildRequest;
};

const resumablePayrollPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  cycleId: z.string().min(1),
  dueAt: z.string().datetime(),
  agreementRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  manifestRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  policyRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  fxRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  runNullifier: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  obligationSnapshotPlanId: z.string().uuid(),
  claimProofSource: z.object({ buildInput: z.unknown() }).strict(),
}).passthrough();

function sameField(left: string | null, right: string): boolean {
  return left !== null && BigInt(left) === BigInt(right);
}

/**
 * A browser can close after the encrypted run is persisted or autonomous
 * witness staging can fail after proof storage. Snapshot runs have a fixed run
 * ID, so retrying with fresh salts would correctly fail replay checks. Reuse
 * the authenticated encrypted build input only while the run is unsubmitted;
 * a proven run may resume only through the exact server-authorized agent
 * binding. No server plaintext or caller-selected version is trusted here.
 */
async function loadResumableEncryptedPayrollRun(input: {
  client: PayoClient;
  organizationId: string;
  organizationSecret: string;
  principal: VaultPrincipalKeyPair;
  chainId: string;
  sealAddress: string;
  snapshotPlan: ObligationSnapshotPlanPrivate;
  obligations: readonly PayrollExecutionObligation[];
  nowUnix: bigint;
}): Promise<ResumableEncryptedPayrollRun | undefined> {
  let response: Awaited<ReturnType<PayoClient["getPayrollRun"]>>;
  try {
    response = await input.client.getPayrollRun(input.snapshotPlan.runId);
  } catch (error) {
    if (
      error instanceof PayoApiError
      && (error.code === "RUN_NOT_FOUND" || error.code === "RUN_VAULT_MISSING")
    ) return undefined;
    throw error;
  }
  const { run } = response;
  if (run.state !== "draft" && run.state !== "calculated" && run.state !== "proven") {
    throw new Error(
      `This protected payroll is already ${run.state}; refresh Activity instead of generating another proof.`,
    );
  }
  if (
    run.organizationId !== input.organizationId
    || run.id !== input.snapshotPlan.runId
    || run.obligationSnapshotPlanId !== input.snapshotPlan.planId
    || run.transactionHash !== null
  ) throw new Error("The interrupted payroll does not match this protected payday.");

  const payload = resumablePayrollPayloadSchema.parse(
    decryptVaultRecord(run.envelope, input.principal),
  );
  const buildInput = payload.claimProofSource.buildInput as SerializedPayrollIntegrityBuildRequest;
  const rebuilt = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  const bindingsMatch = payload.cycleId === input.snapshotPlan.cycleId
    && new Date(payload.dueAt).getTime() === Number(input.snapshotPlan.snapshot.dueAt) * 1_000
    && payload.obligationSnapshotPlanId === input.snapshotPlan.planId
    && buildInput.chainId === input.chainId
    && BigInt(buildInput.sealAddress) === BigInt(input.sealAddress)
    && buildInput.organizationSecret === input.organizationSecret
    && buildInput.cycleId === input.snapshotPlan.cycleId
    && buildInput.revision === input.snapshotPlan.payrollRevision
    && sameField(run.agreementRoot, rebuilt.agreementRoot)
    && sameField(run.manifestRoot, rebuilt.manifestRoot)
    && sameField(run.policyRoot, rebuilt.policyRoot)
    && sameField(run.fxRoot, rebuilt.fxRoot)
    && sameField(run.runNullifier, rebuilt.runNullifier)
    && BigInt(payload.agreementRoot) === BigInt(rebuilt.agreementRoot)
    && BigInt(payload.manifestRoot) === BigInt(rebuilt.manifestRoot)
    && BigInt(payload.policyRoot) === BigInt(rebuilt.policyRoot)
    && BigInt(payload.fxRoot) === BigInt(rebuilt.fxRoot)
    && BigInt(payload.runNullifier) === BigInt(rebuilt.runNullifier)
    && BigInt(rebuilt.agreementRoot) === BigInt(input.snapshotPlan.snapshot.baseAgreementRoot)
    && BigInt(rebuilt.policyRoot) === BigInt(input.snapshotPlan.snapshot.policyRoot)
    && BigInt(rebuilt.runNullifier) === BigInt(input.snapshotPlan.snapshot.runNullifier);
  if (!bindingsMatch) {
    throw new Error("The interrupted payroll changed an immutable snapshot or proof binding.");
  }
  const currentObligations = new Map(input.obligations.map(({ agreement, payee }) => [
    agreement.agreement.id,
    { recipientAddress: payee.recipientAddress, token: agreement.agreement.settlementToken },
  ]));
  const linesMatch = buildInput.lines.length === currentObligations.size
    && buildInput.lines.every((line) => {
      const current = currentObligations.get(line.agreementId);
      return current
        && BigInt(current.recipientAddress) === BigInt(line.recipientAddress)
        && current.token === line.token;
    });
  if (!linesMatch) {
    throw new Error("The selected contributors differ from the interrupted encrypted payroll.");
  }
  if (BigInt(buildInput.validityExpiry) - input.nowUnix < 10n * 60n) {
    throw new Error(
      "The interrupted proof window is too close to expiry for a safe retry. Protect a fresh payday before proving again.",
    );
  }
  rebuilt.witness.circuitInputs = [{}, {}];
  return { state: run.state, buildInput };
}

function rootFromLimbs(high: string, low: string): `0x${string}` {
  const highValue = BigInt(high);
  const lowValue = BigInt(low);
  if (highValue < 0n || highValue >= 1n << 128n || lowValue < 0n || lowValue >= 1n << 128n) {
    throw new Error("PayrollIntegrity returned a non-canonical proof root.");
  }
  return `0x${((highValue << 128n) | lowValue).toString(16).padStart(64, "0")}`;
}

function returnedId(value: Record<string, unknown>, label: string): string {
  if (typeof value.id !== "string") throw new Error(`PAYO did not return a ${label} identifier.`);
  return value.id;
}

function canRetry(error: unknown): boolean {
  return !(error instanceof PayoApiError) || error.status === 408 || error.status === 429 || error.status >= 500;
}

async function retryDurableWrite<T>(operation: () => Promise<T>): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (!canRetry(error) || attempt === 2) throw error;
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
  throw lastError;
}

async function stageAutonomousPayrollRun(input: {
  client: PayoClient;
  organizationId: string;
  runId: string;
  proofWitnessPayload: unknown;
  autonomousAgent: PrepareAutonomousPayrollInput["autonomousAgent"];
  beforeStage?: (binding: { proofBundleId: string; runVersion: number }) => Promise<void>;
  onStage?: (stage: PayrollExecutionStage) => void;
}): Promise<AutonomousPayrollPreparationResult> {
  input.onStage?.("agent_policy");
  const policyId = autonomousPolicyId(input.autonomousAgent.capabilityId, input.runId);
  const validForSeconds = Math.min(input.autonomousAgent.validForSeconds ?? 3_600, 3_600);
  const provisioned = await input.client.provisionDirectPrivacyAccount({
    organizationId: input.organizationId,
    capabilityId: input.autonomousAgent.capabilityId,
    runIds: [input.runId],
    policyAccountAddress: input.autonomousAgent.policyAccountAddress,
    policyId,
    validForSeconds,
    periodSeconds: validForSeconds,
    maxCallsPerPeriod: 1,
    maxCallCount: 1,
  });
  const binding = provisioned.authorizedRuns.find(({ runId }) => runId === input.runId);
  if (
    provisioned.authorizedRuns.length !== 1
    || !binding
    || !Number.isInteger(binding.runVersion)
    || binding.runVersion < 1
    || !binding.proofBundleId
  ) {
    throw new Error("PAYO did not return the exact authorized run binding for this policy account.");
  }
  await input.beforeStage?.({
    proofBundleId: binding.proofBundleId,
    runVersion: binding.runVersion,
  });
  const agentWitness = encryptVaultRecord(input.proofWitnessPayload, {
    schemaVersion: 1,
    organizationId: input.organizationId,
    recordType: "agent_payroll_witness",
    recordId: input.runId,
    revision: binding.runVersion,
  }, [provisioned.account.proofPrincipal]);
  const staged = await input.client.stageDirectPrivacyRunWitness({
    accountId: provisioned.account.id,
    encryptedWitness: agentWitness,
  });
  if (
    staged.witness.runId !== input.runId
    || staged.witness.runVersion !== binding.runVersion
  ) {
    throw new Error("PAYO staged the autonomous witness against a different run version.");
  }
  return {
    mode: "autonomous_bounded",
    organizationId: input.organizationId,
    capabilityId: input.autonomousAgent.capabilityId,
    runId: input.runId,
    runVersion: binding.runVersion,
    proofBundleId: binding.proofBundleId,
    accountId: provisioned.account.id,
    policyId,
    witnessCommitment: staged.witness.witnessCommitment,
    activationState: provisioned.account.activationState,
  };
}

export async function waitForPayrollAuthorization(input: {
  client: Pick<PayoClient, "getPayrollAuthorization">;
  runId: string;
  initial?: Awaited<ReturnType<PayoClient["getPayrollAuthorization"]>>["authorization"];
  pollIntervalMs?: number;
  timeoutMs?: number;
}) {
  const pollIntervalMs = input.pollIntervalMs ?? 3_000;
  const timeoutMs = input.timeoutMs ?? 30 * 60_000;
  if (!Number.isFinite(pollIntervalMs) || pollIntervalMs < 0 || pollIntervalMs > 30_000) {
    throw new Error("Payroll authorization poll interval is invalid.");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 60 * 60_000) {
    throw new Error("Payroll authorization timeout is invalid.");
  }
  const deadline = Date.now() + timeoutMs;
  let authorization = input.initial;
  while (Date.now() < deadline) {
    authorization ??= (await input.client.getPayrollAuthorization(input.runId)).authorization;
    if (authorization.runId !== input.runId) {
      throw new Error("PAYO returned an authorization for another payroll run.");
    }
    if (authorization.state === "complete") {
      if (!authorization.authorizedAt || !authorization.transactionHash) {
        throw new Error("PAYO marked payroll authorization complete without finalized chain evidence.");
      }
      return authorization;
    }
    if (authorization.state === "dead") {
      throw new Error(
        authorization.lastErrorMessage
          ? `Payroll proof authorization failed: ${authorization.lastErrorMessage}`
          : "Payroll proof authorization failed permanently.",
      );
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    authorization = (await input.client.getPayrollAuthorization(input.runId)).authorization;
  }
  throw new Error(
    "PAYO did not finish proof-first payroll authorization within 30 minutes. No Ready payment was requested; resume this authorization safely.",
  );
}

export async function waitForVestingAuthorization(input: {
  client: Pick<PayoClient, "getVestingAuthorization">;
  runId: string;
  initial?: Awaited<ReturnType<PayoClient["getVestingAuthorization"]>>["authorization"];
  pollIntervalMs?: number;
  timeoutMs?: number;
}) {
  const pollIntervalMs = input.pollIntervalMs ?? 3_000;
  const timeoutMs = input.timeoutMs ?? 30 * 60_000;
  if (!Number.isFinite(pollIntervalMs) || pollIntervalMs < 0 || pollIntervalMs > 30_000) {
    throw new Error("Vesting authorization poll interval is invalid.");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 60 * 60_000) {
    throw new Error("Vesting authorization timeout is invalid.");
  }
  const deadline = Date.now() + timeoutMs;
  let authorization = input.initial;
  while (Date.now() < deadline) {
    authorization ??= (await input.client.getVestingAuthorization(input.runId)).authorization;
    if (authorization.runId !== input.runId) {
      throw new Error("PAYO returned a state/book authorization for another payroll run.");
    }
    if (authorization.state === "complete") {
      if (!authorization.authorizedAt || !authorization.transactionHash) {
        throw new Error("PAYO marked state/book authorization complete without finalized chain evidence.");
      }
      return authorization;
    }
    if (authorization.state === "dead") {
      throw new Error(
        authorization.lastErrorMessage
          ? `State/book proof authorization failed: ${authorization.lastErrorMessage}`
          : "State/book proof authorization failed permanently.",
      );
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    authorization = (await input.client.getVestingAuthorization(input.runId)).authorization;
  }
  throw new Error(
    "PAYO did not finish state/book proof authorization within 30 minutes. No Ready payment was requested; resume this authorization safely.",
  );
}

async function authorizePayrollBookProof(input: {
  client: PayoClient;
  runId: string;
  proofBundleId: string;
  payrollProof: ProofWorkerSuccess;
  stateProof: VestingBookProof;
  chainId: string;
  bookSealAddress: string;
  pollIntervalMs?: number;
  timeoutMs?: number;
  onStage?: (stage: PayrollExecutionStage) => void;
}): Promise<STRK20_INVOKE_ACTION> {
  input.onStage?.("proof_authorization");
  const stateProof = input.stateProof;
  if (stateProof.circuitSha256 !== VESTING_TRANSITION_CIRCUIT_SHA256
    || stateProof.verificationKeySha256 !== VESTING_TRANSITION_VERIFICATION_KEY_SHA256) {
    throw new Error("The state/book proof is not bound to the pinned PAYO v3 circuit and verification key.");
  }
  const queued = await input.client.enqueueVestingAuthorization({
    runId: input.runId,
    request: {
      payrollProofBundleId: input.proofBundleId,
      payrollShards: [
        input.payrollProof.shards[0].proofCalldata,
        input.payrollProof.shards[1].proofCalldata,
      ],
      vestingBook: {
        proofVersion: stateProof.proofVersion,
        entryKind: stateProof.entryKind,
        circuitSha256: VESTING_TRANSITION_CIRCUIT_SHA256,
        verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
        scheduleId: stateProof.scheduleId,
        previousStateCommitment: stateProof.previousStateCommitment,
        nextStateCommitment: stateProof.nextStateCommitment,
        releaseNullifier: stateProof.releaseNullifier,
        bookEntry: stateProof.bookEntry,
        bookEntryCommitment: stateProof.bookEntryCommitment,
        shards: stateProof.shards.map((shard) => ({
          shardIndex: shard.shardIndex,
          proofCalldata: shard.proofCalldata,
          calldataHash: shard.calldataHash,
          publicInputs: shard.publicInputs,
        })) as typeof stateProof.shards,
      },
    },
  });
  await waitForVestingAuthorization({
    client: input.client,
    runId: input.runId,
    initial: queued.authorization,
    pollIntervalMs: input.pollIntervalMs,
    timeoutMs: input.timeoutMs,
  });
  return buildVestingBookAction({
    sealAddress: input.bookSealAddress,
    chainId: input.chainId,
    payrollShards: input.payrollProof.shards,
    vestingBook: stateProof,
  });
}

export async function resumePendingPayrollSubmission(input: {
  client: PayoClient;
  pending: PendingPayrollSubmission;
  transactionHash?: string;
  persistPendingSubmission?: (submission: PendingPayrollSubmission | null) => void;
  onStage?: (stage: PayrollExecutionStage) => void;
}): Promise<PayrollExecutionResult> {
  const pending = parsePendingPayrollSubmission(input.pending);
  const transactionHash = input.transactionHash?.trim() || pending.transactionHash;
  if (!transactionHash || !/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
    throw new Error(
      "Ready did not return a transaction hash. Copy the submitted hash from Ready before recording this payroll.",
    );
  }
  const submitted = { ...pending, transactionHash };
  input.persistPendingSubmission?.(submitted);
  input.onStage?.("recording");
  try {
    const response = await retryDurableWrite(() => input.client.createSettlementIntent({
      id: submitted.settlementId,
      organizationId: submitted.organizationId,
      runId: submitted.runId,
      workflowType: "payroll",
      subjectRecordId: submitted.runId,
      walletRequestId: submitted.walletRequestId,
      idempotencyKey: submitted.idempotencyKey,
      tokenTotalsCommitment: submitted.tokenTotalsCommitment,
      envelope: submitted.settlementEnvelope,
    }));
    if (returnedId(response.settlement, "settlement") !== submitted.settlementId) {
      throw new Error("PAYO returned a different settlement identifier for this idempotent request.");
    }
    await retryDurableWrite(() => input.client.recordSettlementSubmission(
      submitted.settlementId,
      submitted.transactionHash,
    ));
  } catch (error) {
    throw new PayrollSubmissionPersistenceError(
      `PAYO could not resume submission recording. Recovery run: ${submitted.runId}.`,
      submitted,
      { cause: error },
    );
  }
  if (!submitted.authorizationMode) {
    try {
      await retryDurableWrite(() => input.client.enqueueProofVerification({
        settlementId: submitted.settlementId,
        proofBundleId: submitted.proofBundleId,
        shards: submitted.proofShards,
      }));
    } catch {
      input.persistPendingSubmission?.(null);
      input.onStage?.("recorded");
      return {
        ...submitted,
        verificationQueued: false,
        proofDeliveryWarning: PAYROLL_PROOF_DELIVERY_WARNING,
      };
    }
  }
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return { ...submitted, verificationQueued: true };
}

/**
 * Reopens Ready for a v3 payroll whose proof and on-chain authorization are
 * already durable but whose wallet request never opened. Every payment line
 * and callback is reconstructed from authenticated encrypted records; no
 * caller-supplied recipient, amount, proof, or callback is accepted.
 */
export async function resumePendingPayrollApproval(input: {
  client: PayoClient;
  pending: PendingPayrollSubmission;
  principal: VaultPrincipalKeyPair;
  chainId: string;
  bookSealAddress: string;
  submitPayroll: (
    recipients: Array<{ address: string; amount: string; token: PayrollTokenSymbol }>,
    payoAction: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  persistPendingSubmission?: (submission: PendingPayrollSubmission | null) => void;
  onStage?: (stage: PayrollExecutionStage) => void;
  walletRecoveryPollIntervalMs?: number;
  walletRecoveryTimeoutMs?: number;
  walletRecoveryNoticeDelayMs?: number;
  now?: () => Date;
}): Promise<PayrollExecutionResult> {
  const pending = parsePendingPayrollSubmission(input.pending);
  if (pending.version !== 5 || pending.authorizationMode !== "vesting_book_v3") {
    throw new Error("Only a v3 payroll-book approval can resume Ready without regenerating proof.");
  }
  if (pending.transactionHash) {
    return resumePendingPayrollSubmission({
      client: input.client,
      pending,
      persistPendingSubmission: input.persistPendingSubmission,
      onStage: input.onStage,
    });
  }

  const [{ run }, { settlement }] = await Promise.all([
    input.client.getPayrollRun(pending.runId),
    input.client.getSettlement(pending.settlementId),
  ]);
  const serverSettlement = settlement as Record<string, unknown>;
  if (
    run.id !== pending.runId
    || run.organizationId !== pending.organizationId
    || run.transactionHash !== null
    || !["proven", "approval_pending"].includes(run.state)
    || serverSettlement.id !== pending.settlementId
    || serverSettlement.organizationId !== pending.organizationId
    || serverSettlement.runId !== pending.runId
    || serverSettlement.state !== "approval_pending"
    || serverSettlement.transactionHash !== null
    || serverSettlement.walletRequestId !== pending.walletRequestId
    || serverSettlement.idempotencyKey !== pending.idempotencyKey
    || BigInt(String(serverSettlement.tokenTotalsCommitment)) !== BigInt(pending.tokenTotalsCommitment)
  ) {
    throw new Error("The durable payroll approval no longer matches its encrypted recovery record.");
  }
  if (
    run.envelope.aad.organizationId !== pending.organizationId
    || run.envelope.aad.recordId !== pending.runId
    || run.envelope.aad.recordType !== "payroll-run"
  ) throw new Error("The recoverable payroll run has invalid encrypted identity metadata.");

  const payload = resumablePayrollPayloadSchema.parse(
    decryptVaultRecord(run.envelope, input.principal),
  );
  const buildInput = payload.claimProofSource.buildInput as SerializedPayrollIntegrityBuildRequest;
  const rebuilt = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  if (
    buildInput.chainId !== input.chainId
    || BigInt(payload.agreementRoot) !== BigInt(rebuilt.agreementRoot)
    || BigInt(payload.manifestRoot) !== BigInt(rebuilt.manifestRoot)
    || BigInt(payload.policyRoot) !== BigInt(rebuilt.policyRoot)
    || BigInt(payload.fxRoot) !== BigInt(rebuilt.fxRoot)
    || BigInt(payload.runNullifier) !== BigInt(rebuilt.runNullifier)
    || !sameField(run.agreementRoot, rebuilt.agreementRoot)
    || !sameField(run.manifestRoot, rebuilt.manifestRoot)
    || !sameField(run.policyRoot, rebuilt.policyRoot)
    || !sameField(run.fxRoot, rebuilt.fxRoot)
    || !sameField(run.runNullifier, rebuilt.runNullifier)
  ) throw new Error("The recoverable payroll proof bindings differ from its encrypted run.");
  rebuilt.witness.circuitInputs = [{}, {}];

  const recovered = await openStoredPayrollBookProof({
    client: input.client,
    proofBundleId: pending.proofBundleId,
    organizationId: pending.organizationId,
    runId: pending.runId,
    principal: input.principal,
    expectedEntryKinds: ["ordinary", "vesting"],
  });
  if (hashCanonicalJson(pending.proofShards) !== hashCanonicalJson(
    recovered.payrollProof.shards.map(({ proofCalldata }) => proofCalldata),
  )) throw new Error("The recovery record differs from the stored payroll proof shards.");
  if (BigInt(recovered.vestingBook.shards[0].publicInputs.validityExpiry)
    <= BigInt(Math.floor((input.now?.() ?? new Date()).getTime() / 1_000)) + 60n) {
    throw new Error("The authorized payroll-book proof has expired; protect a fresh payday before retrying.");
  }

  const tokenTotals = { STRK: 0n, USDC: 0n };
  const recipients = buildInput.lines.map((line) => {
    const netAtomic = line.earningsAtomic.reduce((total, value) => total + BigInt(value), 0n)
      - line.deductionsAtomic.reduce((total, value) => total + BigInt(value), 0n);
    if (netAtomic <= 0n) throw new Error(`Agreement ${line.agreementId} has no positive net settlement.`);
    tokenTotals[line.token] += netAtomic;
    return {
      address: line.recipientAddress,
      amount: formatTokenAmount(netAtomic, line.token),
      token: line.token,
    };
  });
  const totalsCommitment = commitTokenTotals({
    organizationId: pending.organizationId,
    runId: pending.runId,
    totals: { STRK: tokenTotals.STRK.toString(), USDC: tokenTotals.USDC.toString() },
  });
  const encryptedSettlement = settlementRecordSchema.parse(
    decryptVaultRecord(pending.settlementEnvelope, input.principal),
  );
  if (
    BigInt(totalsCommitment) !== BigInt(pending.tokenTotalsCommitment)
    || encryptedSettlement.id !== pending.settlementId
    || encryptedSettlement.runId !== pending.runId
    || encryptedSettlement.walletRequestId !== pending.walletRequestId
    || encryptedSettlement.idempotencyKey !== pending.idempotencyKey
    || BigInt(encryptedSettlement.tokenTotalsCommitment) !== BigInt(pending.tokenTotalsCommitment)
    || encryptedSettlement.tokenTotals.STRK !== tokenTotals.STRK.toString()
    || encryptedSettlement.tokenTotals.USDC !== tokenTotals.USDC.toString()
  ) throw new Error("The recovered private payment differs from its durable settlement commitment.");

  const payoAction = buildVestingBookAction({
    sealAddress: input.bookSealAddress,
    chainId: input.chainId,
    payrollShards: recovered.payrollProof.shards,
    vestingBook: recovered.vestingBook,
  });
  input.onStage?.("wallet");
  const alreadyRecovered = await readRecoveredSettlementTransactionHash(
    input.client,
    pending.settlementId,
  );
  const transactionHash = alreadyRecovered ?? await awaitWalletOrRecoveredTransaction({
    submit: () => input.submitPayroll(recipients, payoAction),
    readRecoveredTransactionHash: () => readRecoveredSettlementTransactionHash(input.client, pending.settlementId),
    onRecoveryPolling: () => input.onStage?.("wallet_recovery"),
    pollIntervalMs: input.walletRecoveryPollIntervalMs,
    timeoutMs: input.walletRecoveryTimeoutMs,
    recoveryNoticeDelayMs: input.walletRecoveryNoticeDelayMs,
  });
  const submitted = { ...pending, transactionHash };
  input.persistPendingSubmission?.(submitted);
  return resumePendingPayrollSubmission({
    client: input.client,
    pending: submitted,
    persistPendingSubmission: input.persistPendingSubmission,
    onStage: input.onStage,
  });
}

const sealedRecoveryProofSchema = z.object({
  shards: z.tuple([
    z.object({
      shardIndex: z.literal(0),
      proofCalldata: z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    }).passthrough(),
    z.object({
      shardIndex: z.literal(1),
      proofCalldata: z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    }).passthrough(),
  ]),
}).passthrough();

/**
 * Repairs a legacy run produced before approval intents were persisted ahead
 * of Ready. The server discloses only a canonical seal-event hash and proof
 * bundle identifier; proof calldata and token totals are decrypted locally.
 */
export async function recoverSealedProvenPayroll(input: {
  client: PayoClient;
  organizationId: string;
  runId: string;
  totals: Readonly<Record<PayrollTokenSymbol, bigint>>;
  principal: VaultPrincipalKeyPair;
  persistPendingSubmission?: (submission: PendingPayrollSubmission | null) => void;
  onStage?: (stage: PayrollExecutionStage) => void;
}): Promise<PayrollExecutionResult> {
  input.onStage?.("recording");
  const { recovery } = await input.client.getSealedPayrollRecovery(input.runId);
  if (
    recovery.recoveryKind !== "submission"
    || recovery.runId !== input.runId
    || !/^0x[0-9a-fA-F]{1,64}$/.test(recovery.transactionHash)
  ) {
    throw new Error("PAYO returned invalid canonical seal recovery evidence.");
  }
  const response = await input.client.getEncryptedRecord({
    organizationId: input.organizationId,
    recordId: recovery.proofBundleId,
  }) as { record?: { envelope?: EncryptedVaultRecord } };
  if (!response.record?.envelope) throw new Error("The encrypted proof bundle is unavailable for recovery.");
  const proof = sealedRecoveryProofSchema.parse(
    decryptVaultRecord(response.record.envelope, input.principal),
  );
  const settlementId = generateUuidV7();
  const walletRequestId = generateUuidV7();
  const idempotencyKey = `payroll-recovery:${input.runId}:${walletRequestId}`;
  const tokenTotalsCommitment = commitTokenTotals({
    organizationId: input.organizationId,
    runId: input.runId,
    totals: {
      STRK: input.totals.STRK.toString(),
      USDC: input.totals.USDC.toString(),
    },
  });
  const timestamp = new Date().toISOString();
  const settlement = settlementRecordSchema.parse({
    schemaVersion: 1,
    id: settlementId,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    runId: input.runId,
    walletRequestId,
    idempotencyKey,
    tokenTotals: {
      STRK: input.totals.STRK.toString(),
      USDC: input.totals.USDC.toString(),
    },
    tokenTotalsCommitment,
    state: "approval_pending",
    noteEvidenceState: "unavailable",
  });
  const settlementEnvelope = encryptVaultRecord(
    settlement,
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "settlement",
      recordId: settlementId,
      revision: 1,
    },
    [input.principal],
  );
  const pending: PendingPayrollSubmission & { transactionHash: string } = {
    version: 3,
    organizationId: input.organizationId,
    runId: input.runId,
    proofBundleId: recovery.proofBundleId,
    settlementId,
    walletRequestId,
    idempotencyKey,
    tokenTotalsCommitment,
    settlementEnvelope,
    proofShards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
    transactionHash: recovery.transactionHash,
    createdAt: timestamp,
  };
  input.persistPendingSubmission?.(pending);
  try {
    const created = await retryDurableWrite(() => input.client.createSettlementIntent({
      id: settlementId,
      organizationId: input.organizationId,
      runId: input.runId,
      workflowType: "payroll",
      subjectRecordId: input.runId,
      walletRequestId,
      idempotencyKey,
      tokenTotalsCommitment,
      envelope: settlementEnvelope,
    }));
    if (returnedId(created.settlement, "settlement") !== settlementId) {
      throw new Error("PAYO returned a different settlement identifier during seal recovery.");
    }
    await retryDurableWrite(() => input.client.recordSettlementSubmission(settlementId, recovery.transactionHash));
  } catch (error) {
    throw new PayrollSubmissionPersistenceError(
      `The sealed transaction was found, but PAYO could not finish recording it. Recovery run: ${input.runId}.`,
      pending,
      { cause: error },
    );
  }
  try {
    await retryDurableWrite(() => input.client.enqueueProofVerification({
      settlementId,
      proofBundleId: recovery.proofBundleId,
      shards: pending.proofShards,
    }));
  } catch {
    input.persistPendingSubmission?.(null);
    input.onStage?.("recorded");
    return {
      ...pending,
      verificationQueued: false,
      proofDeliveryWarning: PAYROLL_PROOF_DELIVERY_WARNING,
    };
  }
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return { ...pending, verificationQueued: true };
}

/**
 * Restores the proof-verification job for a payroll whose private STRK20
 * transfer already finalized. Proof calldata is decrypted only in the
 * authorized browser; the server returns public settlement bindings alone.
 */
export async function recoverConfirmedPayrollVerification(input: {
  client: PayoClient;
  organizationId: string;
  runId: string;
  principal: VaultPrincipalKeyPair;
  onStage?: (stage: PayrollExecutionStage) => void;
}): Promise<{
  runId: string;
  settlementId: string;
  proofBundleId: string;
  transactionHash: string;
  verificationQueued: true;
}> {
  input.onStage?.("recording");
  const { recovery } = await input.client.getSealedPayrollRecovery(input.runId);
  if (
    recovery.recoveryKind !== "verification"
    || recovery.runId !== input.runId
    || typeof recovery.settlementId !== "string"
    || !/^0x[0-9a-fA-F]{1,64}$/.test(recovery.transactionHash)
  ) {
    throw new Error("PAYO returned invalid confirmed-payroll recovery evidence.");
  }
  const response = await input.client.getEncryptedRecord({
    organizationId: input.organizationId,
    recordId: recovery.proofBundleId,
  }) as { record?: { envelope?: EncryptedVaultRecord } };
  if (!response.record?.envelope) {
    throw new Error("The encrypted proof bundle is unavailable for confirmed-payroll recovery.");
  }
  const proof = sealedRecoveryProofSchema.parse(
    decryptVaultRecord(response.record.envelope, input.principal),
  );
  const validityExpiry = proof.shards[0].publicInputs
    && typeof proof.shards[0].publicInputs === "object"
    && "validityExpiry" in proof.shards[0].publicInputs
    && typeof proof.shards[0].publicInputs.validityExpiry === "string"
      ? BigInt(proof.shards[0].publicInputs.validityExpiry)
      : undefined;
  const nowUnix = BigInt(Math.floor(Date.now() / 1_000));
  if (!validityExpiry || validityExpiry - nowUnix < 900n) {
    throw new Error(
      "This confirmed payroll missed its on-chain proof-delivery window and cannot be used for claims. Create a replacement payroll; no wallet transaction was requested.",
    );
  }
  await retryDurableWrite(() => input.client.enqueueProofVerification({
    settlementId: recovery.settlementId!,
    proofBundleId: recovery.proofBundleId,
    shards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
  }));
  input.onStage?.("queued");
  return {
    runId: recovery.runId,
    settlementId: recovery.settlementId,
    proofBundleId: recovery.proofBundleId,
    transactionHash: recovery.transactionHash,
    verificationQueued: true,
  };
}

/**
 * Browser-only production path. Salary inputs are encrypted before entering the
 * proof worker and before any API request. The wallet cannot open until all
 * deployment and registry bindings are active at one Starknet block.
 */
export function executeProofBoundPayroll(
  input: PrepareAutonomousPayrollInput,
): Promise<AutonomousPayrollPreparationResult>;
export function executeProofBoundPayroll(
  input: ExecuteProofBoundPayrollInput,
): Promise<PayrollExecutionResult>;
export async function executeProofBoundPayroll(
  input: ExecuteProofBoundPayrollInput | PrepareAutonomousPayrollInput,
): Promise<PayrollExecutionResult | AutonomousPayrollPreparationResult> {
  if (input.obligations.length < 1 || input.obligations.length > 50) {
    throw new Error("A proof-bound payroll requires 1–50 authoritative obligations.");
  }
  if (!input.sealAddress) throw new Error("The proof-bound PAYO seal is not deployed/configured.");
  if (BigInt(input.chainId) === 0n || BigInt(input.sealAddress) === 0n) {
    throw new Error("PAYO requires non-zero chain and seal bindings.");
  }

  const now = input.now?.() ?? new Date();
  const nowUnix = BigInt(Math.floor(now.getTime() / 1_000));
  const validityStart = nowUnix - 30n;
  const validityExpiry = validityStart + 3_600n;
  const snapshotPlan = input.snapshotPlan;
  const runId = snapshotPlan?.runId ?? generateUuidV7(now.getTime());
  const cycleId = snapshotPlan?.cycleId ?? derivePayrollCycleId(input.organizationId, input.obligations);
  const revision = snapshotPlan?.payrollRevision ?? input.runRevision ?? 1;
  if (!Number.isInteger(revision) || revision < 1) throw new Error("Payroll run revision must be a positive integer.");
  const usedTokens = [...new Set(input.obligations.map(({ agreement }) => agreement.agreement.settlementToken))];
  const advancedCount = input.obligations.filter(
    ({ agreement }) => agreement.agreement.agreementVersion === "payo-agreement-v2",
  ).length;
  if (advancedCount > 0 && advancedCount !== input.obligations.length) {
    throw new Error("Legacy and advanced obligations must be settled in separate proof-bound runs.");
  }
  const advancedProfile = advancedCount === input.obligations.length;
  if (snapshotPlan && (!advancedProfile || (!input.proveSnapshot && !input.vestingBook))) {
    throw new Error(
      "A registered payday snapshot requires Advanced PayrollIntegrity v2 and an authorization proof path.",
    );
  }
  if (input.vestingBook && !snapshotPlan) {
    throw new Error("Stateful vesting and payroll-book proofs require an exact registered payday snapshot.");
  }
  if ("autonomousAgent" in input) {
    if (
      !input.vestingBook
      || input.vestingBook.entryKind !== "agent"
      || !input.vestingBook.bookSealAddress
    ) {
      throw new Error(
        "Bounded autonomous payroll requires the explicit universal agent-book proof and seal.",
      );
    }
    try {
      if (BigInt(input.vestingBook.bookSealAddress) === 0n) throw new Error();
    } catch {
      throw new Error("Bounded autonomous payroll requires a non-zero payroll-book seal.");
    }
  } else if (input.vestingBook?.entryKind === "agent") {
    throw new Error("An agent payroll-book entry requires bounded autonomous execution.");
  }
  if (snapshotPlan) {
    if (
      snapshotPlan.organizationId !== input.organizationId
      || snapshotPlan.agreementBindings.length !== input.obligations.length
      || BigInt(snapshotPlan.snapshot.dueAt) > nowUnix
      || BigInt(snapshotPlan.snapshot.claimEndsAt) < nowUnix
    ) throw new Error("The registered snapshot is not valid for this due payroll window.");
  }
  const policies = resolvePayrollPolicyCohort(
    input.obligations.map(({ agreement }) => agreement.agreement),
    now,
  );

  input.onStage?.("fx");
  const protectedTokens = advancedProfile
    ? [...new Set(input.obligations.flatMap(({ agreement }) =>
        agreement.agreement.agreementVersion === "payo-agreement-v2"
        && agreement.agreement.fxProtection
        && BigInt(agreement.agreement.fxProtection.minimumReferenceAtomic) > 0n
          ? [agreement.agreement.settlementToken]
          : []))]
    : [];
  const unsupportedProtectedToken = protectedTokens.find((token) => token !== "STRK");
  if (unsupportedProtectedToken) {
    throw new Error(
      `FXFloor is unavailable for ${unsupportedProtectedToken}/USD because Pragma Mainnet has no usable TWAP checkpoint history for that pair.`,
    );
  }
  if (advancedProfile && !snapshotPlan) {
    throw new Error(
      "Advanced PayrollIntegrity v2 requires an exact registered pre-payday snapshot; protect this payday before it becomes due.",
    );
  }
  const resumableRun = snapshotPlan
    ? await loadResumableEncryptedPayrollRun({
        client: input.client,
        organizationId: input.organizationId,
        organizationSecret: input.organizationSecret,
        principal: input.principal,
        chainId: input.chainId,
        sealAddress: input.sealAddress,
        snapshotPlan,
        obligations: input.obligations,
        nowUnix,
      })
    : undefined;
  const medianOnlyTokens = usedTokens.filter((token) => !protectedTokens.includes(token));
  let fxCatalog: Awaited<ReturnType<PayoClient["getPayrollFxCatalog"]>> | undefined;
  let snapshots: FxSnapshot[];
  let lines: PayrollIntegrityLineInput[];
  let buildInput: SerializedPayrollIntegrityBuildRequest;
  let proofValidityStart = validityStart;
  let proofValidityExpiry = validityExpiry;
  if (resumableRun) {
    buildInput = resumableRun.buildInput;
    proofValidityStart = BigInt(buildInput.validityStart);
    proofValidityExpiry = BigInt(buildInput.validityExpiry);
    snapshots = buildInput.fxSnapshots;
    lines = buildInput.lines.map((line) => ({
      ...line,
      dueAt: BigInt(line.dueAt),
      validUntil: BigInt(line.validUntil),
    }));
  } else {
    fxCatalog = await input.client.getPayrollFxCatalog({
      organizationId: input.organizationId,
      protectedTokens,
      medianTokens: medianOnlyTokens,
    });
    snapshots = fxCatalog.snapshots;
    const advancedScheduleCommitments = new Map<string, `0x${string}`>(await Promise.all(
      input.obligations.flatMap(({ agreement }) => agreement.agreement.agreementVersion === "payo-agreement-v2"
        ? [advancedPlanProofCommitment(agreement.agreement).then((commitment) => [agreement.agreement.id, commitment] as const)]
        : []),
    ));
    lines = buildPayrollExecutionLines({
      organizationId: input.organizationId,
      obligations: input.obligations,
      validityStart,
      advancedScheduleCommitments,
    });
    buildInput = serializePayrollIntegrityBuildRequest({
      chainId: input.chainId,
      sealAddress: input.sealAddress,
      organizationSecret: input.organizationSecret,
      cycleId,
      revision,
      validityStart,
      validityExpiry,
      policies,
      fxSnapshots: snapshots,
      lines,
    });
  }
  const precomputedFxRoot = await buildFxCatalogRoot(snapshots);
  if (fxCatalog && BigInt(precomputedFxRoot) !== BigInt(fxCatalog.catalogRoot)) {
    throw new Error("The authenticated PAYO FX catalog root does not match its snapshots.");
  }
  let snapshotLink: Awaited<ReturnType<typeof buildObligationSnapshotLinkInputs>> | undefined;
  let encryptedSnapshotWitness: EncryptedVaultRecord | undefined;
  if (snapshotPlan) {
    const byAgreement = new Map(input.obligations.map(({ agreement, payee }) => [
      agreement.agreement.id,
      { agreement, payee },
    ]));
    const directoryMatches = snapshotPlan.agreementBindings.every((binding) => {
      const current = byAgreement.get(binding.agreementId);
      return Boolean(current)
        && binding.payeeId === current!.payee.id
        && BigInt(binding.agreementCommitment) === BigInt(current!.agreement.agreementCommitment)
        && BigInt(binding.recipientCommitment) === BigInt(current!.agreement.recipientCommitment)
        && BigInt(binding.scheduleCommitment) === BigInt(recordProofScheduleCommitment(current!.agreement))
        && BigInt(binding.claimCapabilityCommitment)
          === BigInt(current!.agreement.claimCapabilityCommitment ?? "0x0");
    });
    if (!directoryMatches || byAgreement.size !== snapshotPlan.agreementBindings.length) {
      throw new Error("The selected encrypted agreements differ from the registered payday snapshot.");
    }
    if (input.vestingBook
      && BigInt(input.vestingBook.ownerAddress) !== BigInt(snapshotPlan.snapshot.ownerAddress)) {
      throw new Error("The payroll-book owner differs from the registered payday owner.");
    }
    if (!input.vestingBook) {
      const payrollBuild = await buildPayrollIntegrityInputsFromSerialized(buildInput);
      snapshotLink = await buildObligationSnapshotLinkInputs({
        chainId: input.chainId,
        sealAddress: input.sealAddress,
        ownerAddress: snapshotPlan.snapshot.ownerAddress,
        payroll: payrollBuild,
        claimCapabilityCommitments: Object.fromEntries(snapshotPlan.agreementBindings.map((binding) => [
          binding.agreementId,
          binding.claimCapabilityCommitment,
        ])),
        graceEndsAt: BigInt(snapshotPlan.snapshot.graceEndsAt),
        claimEndsAt: BigInt(snapshotPlan.snapshot.claimEndsAt),
        validityStart: proofValidityStart,
        validityExpiry: proofValidityExpiry,
      });
      payrollBuild.witness.circuitInputs = [{}, {}];
      if (
        BigInt(snapshotLink.snapshotCommitment) !== BigInt(snapshotPlan.snapshotCommitment)
        || hashCanonicalJson(snapshotLink.snapshot) !== hashCanonicalJson(snapshotPlan.snapshot)
      ) {
        snapshotLink.circuitInputs = {};
        throw new Error("The due payroll does not reproduce its immutable pre-payday snapshot.");
      }
      const snapshotRequestId = generateUuidV7();
      encryptedSnapshotWitness = encryptVaultRecord({
        exceptionCircuitProfile: "obligation_snapshot_v5",
        circuitInput: snapshotLink.circuitInputs,
      }, {
        schemaVersion: 1,
        organizationId: input.organizationId,
        recordType: "payroll-proof-request",
        recordId: snapshotRequestId,
        revision,
      }, [input.principal]);
      snapshotLink.circuitInputs = {};
    }
  }
  const proofRequestId = generateUuidV7();
  const vestingAgreements = input.obligations
    .map(({ agreement }) => agreement.agreement)
    .filter(isPrivateVestingAgreement);
  if (input.vestingBook && vestingAgreements.length > 1) {
    throw new Error("Settle only one private vesting schedule per proof-bound payroll.");
  }
  let vestingBookBuildInput: {
    ownerAddress: string;
    bookSealAddress?: string;
    entryKind?: "ordinary" | "agent";
    periodStart: string;
    periodEnd: string;
    previousStateSalt: string;
    nextStateSalt: string;
    attestation?: import("@/lib/proof/vesting-transition-input").ExternalAttestationProofInput;
  } | undefined;
  if (input.vestingBook) {
    const validityDate = new Date(Number(proofValidityStart) * 1_000);
    if (Number.isNaN(validityDate.getTime())) throw new Error("The payroll reporting period is invalid.");
    const year = validityDate.getUTCFullYear();
    const periodStart = BigInt(Math.floor(Date.UTC(year, 0, 1) / 1_000));
    const periodEnd = BigInt(Math.floor(Date.UTC(year + 1, 0, 1) / 1_000));
    const vestingPlan = vestingAgreements[0];
    const zero = `0x${"00".repeat(32)}`;
    vestingBookBuildInput = {
      ownerAddress: input.vestingBook.ownerAddress,
      ...(input.vestingBook.bookSealAddress
        ? { bookSealAddress: input.vestingBook.bookSealAddress }
        : {}),
      ...(input.vestingBook.entryKind ? { entryKind: input.vestingBook.entryKind } : {}),
      periodStart: periodStart.toString(),
      periodEnd: periodEnd.toString(),
      previousStateSalt: vestingPlan
        ? vestingStateSalt(vestingPlan.planSalt, vestingPlan.paymentPlan.releaseSequence)
        : zero,
      nextStateSalt: vestingPlan
        ? vestingStateSalt(vestingPlan.planSalt, vestingPlan.paymentPlan.releaseSequence + 1)
        : zero,
      ...(input.vestingBook.attestation
        ? { attestation: input.vestingBook.attestation }
        : {}),
    };
  }
  const proofWitnessPayload = advancedProfile ? {
      advancedBuildInput: {
        payroll: buildInput,
        agreements: input.obligations.map(({ agreement }) => agreement.agreement),
        ...(vestingBookBuildInput ? { vestingBook: vestingBookBuildInput } : {}),
      },
    } : { buildInput };
  if (resumableRun?.state === "proven") {
    if (!("autonomousAgent" in input)) {
      throw new Error("This protected payroll is already proven; recover its payment from Activity.");
    }
    const agentBookSealAddress = input.vestingBook?.bookSealAddress;
    if (!agentBookSealAddress) {
      throw new Error("Autonomous payroll recovery requires the configured universal payroll-book seal.");
    }
    return stageAutonomousPayrollRun({
      client: input.client,
      organizationId: input.organizationId,
      runId,
      proofWitnessPayload,
      autonomousAgent: input.autonomousAgent,
      beforeStage: async ({ proofBundleId }) => {
        const recovered = await openStoredPayrollBookProof({
          client: input.client,
          proofBundleId,
          organizationId: input.organizationId,
          runId,
          principal: input.principal,
          expectedEntryKinds: ["agent"],
        });
        await authorizePayrollBookProof({
          client: input.client,
          runId,
          proofBundleId,
          payrollProof: recovered.payrollProof,
          stateProof: recovered.vestingBook,
          chainId: input.chainId,
          bookSealAddress: agentBookSealAddress,
          pollIntervalMs: input.authorizationPollIntervalMs,
          timeoutMs: input.authorizationTimeoutMs,
          onStage: input.onStage,
        });
      },
      onStage: input.onStage,
    });
  }
  const encryptedWitness = encryptVaultRecord(
    proofWitnessPayload,
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "payroll-proof-request",
      recordId: proofRequestId,
      revision,
    },
    [input.principal],
  );
  const proof = await (input.prove ?? proveEncryptedPayroll)({
    encryptedWitness,
    principal: input.principal,
    onProgress: (stage) => input.onStage?.(stage),
  });
  if (input.vestingBook && !proof.vestingBook) {
    throw new Error("The prover omitted the required stateful vesting/payroll-book proof.");
  }
  if (!input.vestingBook && proof.vestingBook) {
    throw new Error("The prover returned an unexpected stateful vesting/payroll-book proof.");
  }
  let snapshotProof: ExceptionProofWorkerSuccess | undefined;
  if (snapshotPlan && snapshotLink && encryptedSnapshotWitness && input.proveSnapshot) {
    input.onStage?.("snapshot");
    snapshotProof = await input.proveSnapshot({
      encryptedWitness: encryptedSnapshotWitness,
      principal: input.principal,
      onProgress: (stage) => input.onStage?.(stage),
    });
    if (snapshotProof.profile !== "obligation_snapshot_v5") {
      throw new Error("The prover returned the wrong exception profile for this payday snapshot.");
    }
    const mismatch = Object.entries(snapshotLink.publicInputs).find(([key, value]) =>
      BigInt(snapshotProof!.proof.publicInputs[key as keyof typeof snapshotLink.publicInputs])
        !== BigInt(value));
    if (mismatch) {
      throw new Error(`The snapshot proof changed its immutable ${mismatch[0]} binding.`);
    }
  }
  // Prove before requesting any registry transaction. A remote prover can be
  // unavailable or reject this origin/session; no user should spend Mainnet
  // fees merely to discover that failure. The proved FX root is authorized
  // immediately afterward and still checked by the deployment preflight.
  if (input.authorizeFxRoot && fxCatalog) {
    input.onStage?.("authorizing");
    await input.authorizeFxRoot({
      root: precomputedFxRoot,
      snapshots,
      publicationWindow: fxCatalog.publicationWindow,
      publicationTicket: fxCatalog.publicationTicket,
      proof,
    });
  }
  const publicInputs = proof.shards[0].publicInputs;
  const agreementRoot = rootFromLimbs(publicInputs.agreementRootHigh, publicInputs.agreementRootLow);
  const manifestRoot = rootFromLimbs(publicInputs.manifestRootHigh, publicInputs.manifestRootLow);
  const policyRoot = rootFromLimbs(publicInputs.policyRootHigh, publicInputs.policyRootLow);
  const fxRoot = rootFromLimbs(publicInputs.fxRootHigh, publicInputs.fxRootLow);
  if (BigInt(fxRoot) !== BigInt(precomputedFxRoot)) {
    throw new Error("The proof FX root differs from the root authorized for this payroll.");
  }
  const runNullifier = rootFromLimbs(publicInputs.runNullifierHigh, publicInputs.runNullifierLow);
  if (snapshotPlan && (
    BigInt(publicInputs.proofVersion) !== 2n
    || BigInt(agreementRoot) !== BigInt(snapshotPlan.snapshot.baseAgreementRoot)
    || BigInt(policyRoot) !== BigInt(snapshotPlan.snapshot.policyRoot)
    || BigInt(runNullifier) !== BigInt(snapshotPlan.snapshot.runNullifier)
  )) {
    throw new Error("PayrollIntegrity v2 does not reproduce the registered snapshot run bindings.");
  }
  for (const { agreement } of input.obligations) {
    if (BigInt(agreement.agreement.statutoryPolicy.catalogRoot) !== BigInt(policyRoot)) {
      throw new Error(`Agreement ${agreement.agreement.id} is bound to a different policy catalog root.`);
    }
  }

  if (!snapshotPlan) {
    input.onStage?.("preflight");
    const { readiness } = await input.client.checkDeploymentReadiness({
      chainId: input.chainId,
      sealAddress: input.sealAddress,
      mode: 0,
      proofVersion: Number(BigInt(publicInputs.proofVersion)),
      agreementRoot,
      policyRoot,
      fxRoot,
    });
    if (!readiness.ready) {
      const blockers = readiness.checks.filter((entry) => !entry.ready).map((entry) => entry.message);
      throw new Error(`PAYO deployment is not ready: ${blockers.join(" ")}`);
    }
  }

  const privateLines: PrivatePayrollLine[] = lines.map((line) => ({
    agreementId: line.agreementId,
    recipientAddress: line.recipientAddress,
    token: line.token,
    earningsAtomic: line.earningsAtomic,
    deductionsAtomic: line.deductionsAtomic,
    committedPolicyId: line.policyId,
    scheduleCommitment: line.scheduleCommitment,
    salt: line.lineSalt,
  }));
  input.onStage?.("persisting");
  const preparedRun = prepareEncryptedPayrollRun({
    id: runId,
    organizationId: input.organizationId,
    cycleId,
    revision,
    dueAt: snapshotPlan
      ? new Date(Number(snapshotPlan.snapshot.dueAt) * 1_000).toISOString()
      : new Date(Number(validityStart) * 1_000).toISOString(),
    lines: privateLines,
    lineRecordMetadata: input.obligations.map(({ agreement, payee }) => ({
      agreementId: agreement.agreement.id,
      payeeId: payee.id,
      recipientCommitment: agreement.recipientCommitment as `0x${string}`,
      policyCommitment: policyPackCommitment(
        resolveExecutionPolicyForAgreement(agreement.agreement, now),
      ),
    })),
    organizationSecret: input.organizationSecret,
    principals: [input.principal],
    proofBinding: { agreementRoot, manifestRoot, policyRoot, fxRoot, runNullifier },
    ...(snapshotPlan ? { obligationSnapshotPlanId: snapshotPlan.planId } : {}),
    claimProofSource: { buildInput },
    now,
  });
  if (!resumableRun) {
    await input.client.createPayrollRun(preparedRun);
    await input.client.transitionPayrollRun({ runId, state: "calculated" });
  } else if (resumableRun.state === "draft") {
    await input.client.transitionPayrollRun({ runId, state: "calculated" });
  }
  const proofBundleId = generateUuidV7();
  await input.client.storeEncryptedProofBundle(prepareEncryptedPayrollIntegrityBundle({
    id: proofBundleId,
    organizationId: input.organizationId,
    runId,
    revision,
    proof,
    principals: [input.principal],
  }));
  // Proof storage atomically promotes the run from calculated to proven. Do not
  // request the same transition again: the repository deliberately rejects a
  // proven -> proven transition as an invalid state-machine replay.
  if ("autonomousAgent" in input) {
    if (input.vestingBook && proof.vestingBook) {
      await authorizePayrollBookProof({
        client: input.client,
        runId,
        proofBundleId,
        payrollProof: proof,
        stateProof: proof.vestingBook,
        chainId: input.chainId,
        bookSealAddress: input.vestingBook.bookSealAddress ?? input.sealAddress,
        pollIntervalMs: input.authorizationPollIntervalMs,
        timeoutMs: input.authorizationTimeoutMs,
        onStage: input.onStage,
      });
    }
    return stageAutonomousPayrollRun({
      client: input.client,
      organizationId: input.organizationId,
      runId,
      proofWitnessPayload,
      autonomousAgent: input.autonomousAgent,
      onStage: input.onStage,
    });
  }
  let snapshotProofBundleId: string | undefined;
  let payoAction: STRK20_INVOKE_ACTION;
  if (input.vestingBook && proof.vestingBook) {
    payoAction = await authorizePayrollBookProof({
      client: input.client,
      runId,
      proofBundleId,
      payrollProof: proof,
      stateProof: proof.vestingBook,
      chainId: input.chainId,
      bookSealAddress: input.vestingBook.bookSealAddress ?? input.sealAddress,
      pollIntervalMs: input.authorizationPollIntervalMs,
      timeoutMs: input.authorizationTimeoutMs,
      onStage: input.onStage,
    });
  } else if (snapshotPlan && snapshotProof) {
    snapshotProofBundleId = generateUuidV7();
    await input.client.storeEncryptedProofBundle(prepareEncryptedExceptionProofBundle({
      id: snapshotProofBundleId,
      organizationId: input.organizationId,
      runId,
      revision,
      proof: snapshotProof,
      principals: [input.principal],
    }));
    input.onStage?.("proof_authorization");
    const queued = await input.client.enqueuePayrollAuthorization({
      runId,
      payrollProofBundleId: proofBundleId,
      snapshotProofBundleId,
      payrollShards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
      snapshotProof: snapshotProof.proof.proofCalldata,
    });
    await waitForPayrollAuthorization({
      client: input.client,
      runId,
      initial: queued.authorization,
      pollIntervalMs: input.authorizationPollIntervalMs,
      timeoutMs: input.authorizationTimeoutMs,
    });
    payoAction = buildAuthorizedPayrollAction({
      sealAddress: input.sealAddress,
      payrollPublicInputs: proof.shards[0].publicInputs,
      snapshotPublicInputs: snapshotProof.proof.publicInputs,
    });
  } else {
    payoAction = buildPayoSealedPayroll({
      sealAddress: input.sealAddress,
      chainId: input.chainId,
      shards: proof.shards,
      nowUnixSeconds: nowUnix,
    }).invokeAction;
  }
  const walletRequestId = generateUuidV7();
  const settlementId = generateUuidV7();
  const idempotencyKey = `payroll:${runId}:${walletRequestId}`;
  const walletRecipients = lines.map((line) => {
    const netAtomic = line.earningsAtomic.reduce((total, amount) => total + BigInt(amount), 0n)
      - line.deductionsAtomic.reduce((total, amount) => total + BigInt(amount), 0n);
    if (netAtomic <= 0n) throw new Error(`Agreement ${line.agreementId} has no positive net settlement.`);
    return {
      address: line.recipientAddress,
      amount: formatTokenAmount(netAtomic, line.token),
      token: line.token,
    };
  });
  const tokenTotals = walletRecipients.reduce((totals, recipient, index) => {
    const line = lines[index];
    const netAtomic = line.earningsAtomic.reduce((total, amount) => total + BigInt(amount), 0n)
      - line.deductionsAtomic.reduce((total, amount) => total + BigInt(amount), 0n);
    totals[recipient.token] += netAtomic;
    return totals;
  }, { STRK: 0n, USDC: 0n });
  const tokenTotalsCommitment = commitTokenTotals({
    organizationId: input.organizationId,
    runId,
    totals: { STRK: tokenTotals.STRK.toString(), USDC: tokenTotals.USDC.toString() },
  });
  const agentPlanCommitment = input.humanAgentApproval
    ? commitAgentSettlementPlan({
        organizationId: input.organizationId,
        runId,
        payments: lines.map((line) => ({
          recipientAddress: line.recipientAddress,
          token: line.token,
          amountAtomic: (line.earningsAtomic.reduce((total, amount) => total + BigInt(amount), 0n)
            - line.deductionsAtomic.reduce((total, amount) => total + BigInt(amount), 0n)).toString(),
          purposeCode: "private_payroll",
        })),
      })
    : undefined;
  const settlementTimestamp = new Date().toISOString();
  const encryptedSettlement = settlementRecordSchema.parse({
    schemaVersion: 1,
    id: settlementId,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: settlementTimestamp,
    updatedAt: settlementTimestamp,
    runId,
    walletRequestId,
    idempotencyKey,
    tokenTotals: { STRK: tokenTotals.STRK.toString(), USDC: tokenTotals.USDC.toString() },
    tokenTotalsCommitment,
    ...(agentPlanCommitment ? { agentPlanCommitment } : {}),
    state: "approval_pending",
    noteEvidenceState: "unavailable",
  });
  const settlementEnvelope = encryptVaultRecord(
    encryptedSettlement,
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "settlement",
      recordId: settlementId,
      revision: 1,
    },
    [input.principal],
  );
  const pendingApproval: PendingPayrollSubmission = {
    version: input.vestingBook ? 5 : snapshotProofBundleId ? 4 : 3,
    organizationId: input.organizationId,
    runId,
    proofBundleId,
    settlementId,
    walletRequestId,
    idempotencyKey,
    tokenTotalsCommitment,
    settlementEnvelope,
    proofShards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
    ...(input.vestingBook ? {
      authorizationMode: "vesting_book_v3" as const,
    } : snapshotProofBundleId ? {
      authorizationMode: "staged_vnext" as const,
      snapshotProofBundleId,
    } : {}),
    createdAt: new Date().toISOString(),
  };

  // The approval intent, proof-delivery job, and recovery payload must exist
  // before Ready opens.
  // A Wallet API implementation may submit on-chain yet never resolve its
  // request promise; persisting after that promise would strand the run at
  // `proven` with no settlement or safe hash-recovery path.
  input.onStage?.("recording");
  try {
    const settlementResponse = await retryDurableWrite(() => input.client.createSettlementIntent({
      id: settlementId,
      organizationId: input.organizationId,
      runId,
      workflowType: "payroll",
      subjectRecordId: runId,
      walletRequestId,
      idempotencyKey,
      tokenTotalsCommitment,
      ...(agentPlanCommitment ? { agentPlanCommitment } : {}),
      envelope: settlementEnvelope,
    }));
    if (returnedId(settlementResponse.settlement, "settlement") !== settlementId) {
      throw new Error("PAYO returned a different settlement identifier for this payroll.");
    }
    if (input.humanAgentApproval) {
      try {
        const { execution } = await retryDurableWrite(() => input.client.linkAgentExecutionApproval({
          ...input.humanAgentApproval!,
          settlementId,
        }));
        if (
          execution.executionId !== input.humanAgentApproval.executionId
          || execution.capabilityId !== input.humanAgentApproval.capabilityId
          || execution.runId !== runId
          || execution.settlementId !== settlementId
          || execution.state !== "approval_pending"
          || !execution.requiresApproval
        ) throw new Error("PAYO linked a different agent approval to this Ready settlement.");
      } catch (error) {
        // Ready has not opened. Cancel whichever side committed before a lost
        // response and release the reservation, so a retry cannot strand or
        // duplicate an agent-approved payroll.
        await input.client.cancelSettlementApproval(settlementId).catch(() => undefined);
        await input.client.cancelAgentExecutionApproval(input.humanAgentApproval).catch(() => undefined);
        throw error;
      }
    }
    if (!pendingApproval.authorizationMode) {
      await retryDurableWrite(() => input.client.enqueueProofVerification({
        settlementId,
        proofBundleId,
        shards: pendingApproval.proofShards,
      }));
    }
    input.persistPendingSubmission?.(pendingApproval);
  } catch (error) {
    throw new PayrollSubmissionPersistenceError(
      `PAYO could not prepare approval and proof delivery, so Ready was not opened. Recovery run: ${runId}.`,
      pendingApproval,
      { cause: error },
    );
  }

  input.onStage?.("wallet");
  if (!input.submitPayroll) throw new Error("Ready payroll submission is not configured.");
  const transactionHash = await awaitWalletOrRecoveredTransaction({
    submit: () => input.submitPayroll(walletRecipients, payoAction),
    readRecoveredTransactionHash: () => readRecoveredSettlementTransactionHash(input.client, settlementId),
    onRecoveryPolling: () => input.onStage?.("wallet_recovery"),
    onRecoveredTransactionHash: input.onRecoveredTransactionHash,
    pollIntervalMs: input.walletRecoveryPollIntervalMs,
    timeoutMs: input.walletRecoveryTimeoutMs,
    recoveryNoticeDelayMs: input.walletRecoveryNoticeDelayMs,
  });
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
    throw new PayrollSubmissionPersistenceError(
      `Ready submitted payroll without returning a valid transaction hash. Recovery run: ${runId}.`,
      pendingApproval,
    );
  }
  const pendingSubmission: PendingPayrollSubmission & { transactionHash: string } = {
    ...pendingApproval,
    transactionHash,
  };
  input.persistPendingSubmission?.(pendingSubmission);
  input.onStage?.("recording");
  try {
    await retryDurableWrite(() => input.client.recordSettlementSubmission(settlementId, transactionHash));
  } catch (error) {
    throw new PayrollSubmissionPersistenceError(
      `The private transaction was submitted, but PAYO could not finish recording it. Recovery run: ${runId}.`,
      pendingSubmission,
      { cause: error },
    );
  }
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return {
    ...pendingSubmission,
    verificationQueued: true,
  };
}
