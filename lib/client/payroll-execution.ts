import type { STRK20_INVOKE_ACTION } from "starknet";
import { z } from "zod";
import { formatTokenAmount, type PayrollTokenSymbol } from "@/app/starknet/tokens";
import { prepareEncryptedPayrollIntegrityBundle } from "@/lib/client/proof-bundle";
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
import {
  fxCatalogPublicationWindow,
  type FxSnapshot,
} from "@/lib/domain/fx";
import { isAgreementDue } from "@/lib/domain/obligations";
import { generateUuidV7, settlementRecordSchema } from "@/lib/domain/records";
import { commitTokenTotals } from "@/lib/domain/settlement";
import { policyPackCommitment } from "@/lib/policy/engine";
import {
  calculatePolicyDeductions,
  resolveExecutionPolicyForAgreement,
  resolvePayrollPolicyCohort,
} from "@/lib/policy/execution-catalog";
import {
  buildFxCatalogRoot,
  buildPayrollAgreementRoot,
  randomCommitmentSalt,
  serializePayrollIntegrityBuildRequest,
  type PayrollIntegrityLineInput,
} from "@/lib/proof/input-builder";
import { advancedPlanProofCommitment } from "@/lib/proof/advanced-plan-commitment";
import { proveEncryptedPayroll, type ProofProgressListener } from "@/lib/proof/client";
import { PAYO_MAX_PROOF_CALLDATA_FELTS, type ProofWorkerSuccess } from "@/lib/proof/protocol";
import { buildPayoSealedPayroll } from "@/lib/starknet/payo-seal";
import { agreementScheduleCommitment, type PayAgreementDirectoryRecord } from "./agreement-directory";
import type { PayeeDirectoryRecord } from "./payee-directory";
import { awaitWalletOrRecoveredTransaction, readRecoveredSettlementTransactionHash } from "./wallet-submission-recovery";

export type PayrollExecutionObligation = {
  agreement: PayAgreementDirectoryRecord;
  payee: PayeeDirectoryRecord;
};

export type PayrollExecutionStage =
  | "fx"
  | "authorizing"
  | "loading"
  | "executing"
  | "proving"
  | "verifying"
  | "encoding"
  | "preflight"
  | "persisting"
  | "wallet"
  | "recording"
  | "recorded"
  | "queued";

export type PendingPayrollSubmission = {
  version: 3;
  organizationId: string;
  runId: string;
  proofBundleId: string;
  settlementId: string;
  walletRequestId: string;
  idempotencyKey: string;
  tokenTotalsCommitment: `0x${string}`;
  settlementEnvelope: EncryptedVaultRecord;
  proofShards: [string[], string[]];
  transactionHash?: string;
  createdAt: string;
};

export type PayrollExecutionResult = PendingPayrollSubmission & {
  settlementId: string;
  transactionHash: string;
  verificationQueued: boolean;
  proofDeliveryWarning?: string;
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
    const dueAt = agreement.agreementVersion === "payo-agreement-v2"
      ? agreement.paymentPlan.kind === "recurring"
        ? BigInt(Math.floor(new Date(agreement.paymentPlan.nextDueAt).getTime() / 1_000))
        : agreement.paymentPlan.kind === "checkpoint_stream"
          ? BigInt(Math.floor(new Date(agreement.paymentPlan.checkpoint.checkpointAt).getTime() / 1_000))
          : agreement.paymentPlan.kind === "milestone"
            ? BigInt(Math.floor(new Date(agreement.paymentPlan.dueAt).getTime() / 1_000))
            : BigInt(Math.floor(new Date(agreement.paymentPlan.releaseAt).getTime() / 1_000))
      : agreement.schedule.kind === "recurring"
      ? BigInt(Math.floor(new Date(agreement.schedule.nextDueAt).getTime() / 1_000))
      : agreement.schedule.kind === "milestone"
        ? BigInt(Math.floor(new Date(agreement.schedule.dueAt).getTime() / 1_000))
        : agreement.schedule.kind === "stream"
          ? BigInt(Math.floor(new Date(agreement.schedule.startsAt).getTime() / 1_000))
          : BigInt(Math.floor(new Date(agreement.schedule.cliffAt).getTime() / 1_000));
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

export function parsePendingPayrollSubmission(input: unknown): PendingPayrollSubmission {
  const parsed = z.union([
    pendingPayrollSubmissionV3Schema,
    pendingPayrollSubmissionV2Schema,
  ]).parse(input);
  return { ...parsed, version: 3 } as PendingPayrollSubmission;
}

type ProvePayroll = (input: {
  encryptedWitness: Parameters<typeof proveEncryptedPayroll>[0]["encryptedWitness"];
  principal: VaultPrincipalKeyPair;
  onProgress?: ProofProgressListener;
}) => Promise<ProofWorkerSuccess>;

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
  authorizeFxRoot?: (input: {
    root: `0x${string}`;
    snapshots: readonly FxSnapshot[];
    publicationWindow: ReturnType<typeof fxCatalogPublicationWindow>;
    publicationTicket: string;
    proof: ProofWorkerSuccess;
  }) => Promise<void>;
  runRevision?: number;
  now?: () => Date;
};

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
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return { ...submitted, verificationQueued: true };
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
export async function executeProofBoundPayroll(
  input: ExecuteProofBoundPayrollInput,
): Promise<PayrollExecutionResult> {
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
  const runId = generateUuidV7(now.getTime());
  const cycleId = derivePayrollCycleId(input.organizationId, input.obligations);
  const revision = input.runRevision ?? 1;
  if (!Number.isInteger(revision) || revision < 1) throw new Error("Payroll run revision must be a positive integer.");
  const usedTokens = [...new Set(input.obligations.map(({ agreement }) => agreement.agreement.settlementToken))];
  const advancedCount = input.obligations.filter(
    ({ agreement }) => agreement.agreement.agreementVersion === "payo-agreement-v2",
  ).length;
  if (advancedCount > 0 && advancedCount !== input.obligations.length) {
    throw new Error("Legacy and advanced obligations must be settled in separate proof-bound runs.");
  }
  const advancedProfile = advancedCount === input.obligations.length;
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
  const medianOnlyTokens = usedTokens.filter((token) => !protectedTokens.includes(token));
  const fxCatalog = await input.client.getPayrollFxCatalog({
    organizationId: input.organizationId,
    protectedTokens,
    medianTokens: medianOnlyTokens,
  });
  const snapshots = fxCatalog.snapshots;
  const precomputedFxRoot = await buildFxCatalogRoot(snapshots);
  if (BigInt(precomputedFxRoot) !== BigInt(fxCatalog.catalogRoot)) {
    throw new Error("The authenticated PAYO FX catalog root does not match its snapshots.");
  }
  const advancedScheduleCommitments = new Map<string, `0x${string}`>(await Promise.all(
    input.obligations.flatMap(({ agreement }) => agreement.agreement.agreementVersion === "payo-agreement-v2"
      ? [advancedPlanProofCommitment(agreement.agreement).then((commitment) => [agreement.agreement.id, commitment] as const)]
      : []),
  ));
  const lines = buildPayrollExecutionLines({
    organizationId: input.organizationId,
    obligations: input.obligations,
    validityStart,
    advancedScheduleCommitments,
  });
  const buildInput = serializePayrollIntegrityBuildRequest({
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
  const proofRequestId = generateUuidV7();
  const encryptedWitness = encryptVaultRecord(
    advancedProfile ? {
      advancedBuildInput: {
        payroll: buildInput,
        agreements: input.obligations.map(({ agreement }) => agreement.agreement),
      },
    } : { buildInput },
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
  // Prove before requesting any registry transaction. A remote prover can be
  // unavailable or reject this origin/session; no user should spend Mainnet
  // fees merely to discover that failure. The proved FX root is authorized
  // immediately afterward and still checked by the deployment preflight.
  if (input.authorizeFxRoot) {
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
  for (const { agreement } of input.obligations) {
    if (BigInt(agreement.agreement.statutoryPolicy.catalogRoot) !== BigInt(policyRoot)) {
      throw new Error(`Agreement ${agreement.agreement.id} is bound to a different policy catalog root.`);
    }
  }

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
    dueAt: new Date(Number(validityStart) * 1_000).toISOString(),
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
    claimProofSource: { buildInput },
    now,
  });
  await input.client.createPayrollRun(preparedRun);
  await input.client.transitionPayrollRun({ runId, state: "calculated" });
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
  const sealed = buildPayoSealedPayroll({
    sealAddress: input.sealAddress,
    chainId: input.chainId,
    shards: proof.shards,
    nowUnixSeconds: nowUnix,
  });
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
    version: 3,
    organizationId: input.organizationId,
    runId,
    proofBundleId,
    settlementId,
    walletRequestId,
    idempotencyKey,
    tokenTotalsCommitment,
    settlementEnvelope,
    proofShards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
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
      envelope: settlementEnvelope,
    }));
    if (returnedId(settlementResponse.settlement, "settlement") !== settlementId) {
      throw new Error("PAYO returned a different settlement identifier for this payroll.");
    }
    await retryDurableWrite(() => input.client.enqueueProofVerification({
      settlementId,
      proofBundleId,
      shards: pendingApproval.proofShards,
    }));
    input.persistPendingSubmission?.(pendingApproval);
  } catch (error) {
    throw new PayrollSubmissionPersistenceError(
      `PAYO could not prepare approval and proof delivery, so Ready was not opened. Recovery run: ${runId}.`,
      pendingApproval,
      { cause: error },
    );
  }

  input.onStage?.("wallet");
  const transactionHash = await awaitWalletOrRecoveredTransaction({
    submit: () => input.submitPayroll(walletRecipients, sealed.invokeAction),
    readRecoveredTransactionHash: () => readRecoveredSettlementTransactionHash(input.client, settlementId),
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
