import type { STRK20_INVOKE_ACTION } from "starknet";
import { z } from "zod";
import { formatTokenAmount, type PayrollTokenSymbol } from "@/app/starknet/tokens";
import { prepareEncryptedPayrollIntegrityBundle } from "@/lib/client/proof-bundle";
import { PayoApiError, PayoClient, prepareEncryptedPayrollRun } from "@/lib/client/payo-client";
import { hashRecipientCommitment } from "@/lib/crypto/commitments";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { toHex } from "@/lib/crypto/encoding";
import {
  encryptVaultRecord,
  encryptedVaultRecordSchema,
  type EncryptedVaultRecord,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import type { PrivatePayrollLine } from "@/lib/domain/payroll";
import { fxCatalogPublicationWindow, type FxSnapshot } from "@/lib/domain/fx";
import { isScheduleDue } from "@/lib/domain/obligations";
import { generateUuidV7, settlementRecordSchema } from "@/lib/domain/records";
import { commitTokenTotals } from "@/lib/domain/settlement";
import { policyPackCommitment } from "@/lib/policy/engine";
import {
  PAYO_NET_INVOICE_POLICY,
  buildFxCatalogRoot,
  buildPayrollAgreementRoot,
  randomCommitmentSalt,
  serializePayrollIntegrityBuildRequest,
  type PayrollIntegrityLineInput,
} from "@/lib/proof/input-builder";
import { proveEncryptedPayroll, type ProofProgressListener } from "@/lib/proof/client";
import type { ProofWorkerSuccess } from "@/lib/proof/protocol";
import { buildPayoSealedPayroll } from "@/lib/starknet/payo-seal";
import { agreementScheduleCommitment, type PayAgreementDirectoryRecord } from "./agreement-directory";
import type { PayeeDirectoryRecord } from "./payee-directory";

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
  | "queued";

export type PendingPayrollSubmission = {
  version: 2;
  organizationId: string;
  runId: string;
  proofBundleId: string;
  settlementId: string;
  walletRequestId: string;
  idempotencyKey: string;
  tokenTotalsCommitment: `0x${string}`;
  settlementEnvelope: EncryptedVaultRecord;
  proofShards: [string[], string[]];
  transactionHash: string;
  createdAt: string;
};

export type PayrollExecutionResult = Omit<PendingPayrollSubmission, "settlementId"> & {
  settlementId: string;
  verificationQueued: true;
};

export function buildPayrollExecutionLines(input: {
  organizationId: string;
  obligations: readonly PayrollExecutionObligation[];
  validityStart: bigint;
  createLineSalt?: () => `0x${string}`;
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
    if (!isScheduleDue(agreement.schedule, new Date(Number(input.validityStart) * 1_000))) {
      throw new Error(`Agreement ${agreement.id} is not due yet.`);
    }
    if (agreement.statutoryPolicy.policyId !== PAYO_NET_INVOICE_POLICY.id) {
      throw new Error(`Agreement ${agreement.id} selects an unavailable local policy implementation.`);
    }
    if (agreement.classification === "employee") {
      throw new Error(`Agreement ${agreement.id} requires an employee deductions policy, not the net-invoice reference policy.`);
    }
    const referenceCurrency = agreement.fxProtection?.referenceCurrency ?? "USD";
    if (referenceCurrency !== "USD" && referenceCurrency !== "GBP") {
      throw new Error(`Agreement ${agreement.id} selects an unsupported proof reference currency.`);
    }
    const dueAt = agreement.schedule.kind === "recurring"
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
      deductionsAtomic: [],
      policyId: agreement.statutoryPolicy.policyId,
      scheduleCommitment: agreementScheduleCommitment(agreement),
      dueAt,
      validUntil,
      classification: { declared: 2 as const, score: 2, employeeThreshold: 5 },
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
  const lines = buildPayrollExecutionLines({
    organizationId: input.organizationId,
    obligations: input.obligations,
    validityStart: BigInt(Math.floor(at.getTime() / 1_000)),
    // Salary-line salts do not enter the agreement root. A fixed value keeps
    // this preflight deterministic and makes accidental coupling testable.
    createLineSalt: () => `0x${"00".repeat(32)}`,
  });
  return {
    root: await buildPayrollAgreementRoot({
      policies: [PAYO_NET_INVOICE_POLICY],
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

const pendingPayrollSubmissionSchema = z.object({
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
    z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(5_000),
    z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(5_000),
  ]),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
  createdAt: z.string().datetime(),
}).strict();

export function parsePendingPayrollSubmission(input: unknown): PendingPayrollSubmission {
  return pendingPayrollSubmissionSchema.parse(input) as PendingPayrollSubmission;
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
  persistPendingSubmission?: (submission: PendingPayrollSubmission | null) => void;
  onStage?: (stage: PayrollExecutionStage) => void;
}): Promise<PayrollExecutionResult> {
  const pending = parsePendingPayrollSubmission(input.pending);
  input.onStage?.("recording");
  try {
    const response = await retryDurableWrite(() => input.client.createSettlementIntent({
      id: pending.settlementId,
      organizationId: pending.organizationId,
      runId: pending.runId,
      walletRequestId: pending.walletRequestId,
      idempotencyKey: pending.idempotencyKey,
      tokenTotalsCommitment: pending.tokenTotalsCommitment,
      envelope: pending.settlementEnvelope,
    }));
    if (returnedId(response.settlement, "settlement") !== pending.settlementId) {
      throw new Error("PAYO returned a different settlement identifier for this idempotent request.");
    }
    await retryDurableWrite(() => input.client.recordSettlementSubmission(
      pending.settlementId,
      pending.transactionHash,
    ));
    await retryDurableWrite(() => input.client.enqueueProofVerification({
      settlementId: pending.settlementId,
      proofBundleId: pending.proofBundleId,
      shards: pending.proofShards,
    }));
  } catch (error) {
    throw new PayrollSubmissionPersistenceError(
      `PAYO could not resume submission recording. Recovery run: ${pending.runId}.`,
      pending,
      { cause: error },
    );
  }
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return { ...pending, verificationQueued: true };
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

  input.onStage?.("fx");
  const { snapshots } = await input.client.getFxSnapshots(usedTokens);
  const precomputedFxRoot = await buildFxCatalogRoot(snapshots);
  const lines = buildPayrollExecutionLines({
    organizationId: input.organizationId,
    obligations: input.obligations,
    validityStart,
  });
  const buildInput = serializePayrollIntegrityBuildRequest({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    organizationSecret: input.organizationSecret,
    cycleId,
    revision,
    validityStart,
    validityExpiry,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: snapshots,
    lines,
  });
  if (input.authorizeFxRoot) {
    input.onStage?.("authorizing");
    await input.authorizeFxRoot({
      root: precomputedFxRoot,
      snapshots,
      publicationWindow: fxCatalogPublicationWindow(snapshots),
    });
  }
  const proofRequestId = generateUuidV7();
  const encryptedWitness = encryptVaultRecord(
    { buildInput },
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
  const publicInputs = proof.shards[0].publicInputs;
  const agreementRoot = rootFromLimbs(publicInputs.agreementRootHigh, publicInputs.agreementRootLow);
  const manifestRoot = rootFromLimbs(publicInputs.manifestRootHigh, publicInputs.manifestRootLow);
  const policyRoot = rootFromLimbs(publicInputs.policyRootHigh, publicInputs.policyRootLow);
  const fxRoot = rootFromLimbs(publicInputs.fxRootHigh, publicInputs.fxRootLow);
  if (BigInt(fxRoot) !== BigInt(precomputedFxRoot)) {
    throw new Error("The proof FX root differs from the root authorized before proving.");
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
      policyCommitment: policyPackCommitment(PAYO_NET_INVOICE_POLICY),
    })),
    organizationSecret: input.organizationSecret,
    principals: [input.principal],
    proofBinding: { agreementRoot, manifestRoot, policyRoot, fxRoot, runNullifier },
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
  input.onStage?.("wallet");
  let transactionHash: string;
  try {
    transactionHash = await input.submitPayroll(walletRecipients, sealed.invokeAction);
  } catch (error) {
    try {
      await retryDurableWrite(() => input.client.transitionPayrollRun({ runId, state: "cancelled" }));
    } catch (cancellationError) {
      throw new Error(
        `The wallet did not submit payroll, and PAYO could not cancel run ${runId}. Refresh before retrying.`,
        { cause: cancellationError },
      );
    }
    throw error;
  }
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
    transactionHash,
    state: "submitted",
    submittedAt: settlementTimestamp,
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
  const pendingSubmission: PendingPayrollSubmission = {
    version: 2,
    organizationId: input.organizationId,
    runId,
    proofBundleId,
    settlementId,
    walletRequestId,
    idempotencyKey,
    tokenTotalsCommitment,
    settlementEnvelope,
    proofShards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
    transactionHash,
    createdAt: new Date().toISOString(),
  };
  input.persistPendingSubmission?.(pendingSubmission);
  input.onStage?.("recording");
  try {
    const settlementResponse = await retryDurableWrite(() => input.client.createSettlementIntent({
      id: settlementId,
      organizationId: input.organizationId,
      runId,
      walletRequestId,
      idempotencyKey,
      tokenTotalsCommitment,
      envelope: settlementEnvelope,
    }));
    if (returnedId(settlementResponse.settlement, "settlement") !== settlementId) {
      throw new Error("PAYO returned a different settlement identifier for this payroll.");
    }
    input.persistPendingSubmission?.(pendingSubmission);
    await retryDurableWrite(() => input.client.recordSettlementSubmission(settlementId, transactionHash));
    await retryDurableWrite(() => input.client.enqueueProofVerification({
      settlementId,
      proofBundleId,
      shards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
    }));
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
