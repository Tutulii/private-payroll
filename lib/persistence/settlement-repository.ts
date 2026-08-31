import "server-only";

import { and, desc, eq, isNull, or, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  assertSettlementTransition,
  settlementWorkflowSchema,
  type SettlementObservation,
  type SettlementWorkflow,
} from "@/lib/domain/settlement";
import { encryptedVaultRecordSchema, type EncryptedVaultRecord } from "@/lib/crypto/vault";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import {
  applyLinkedAgentSettlementObservationWith,
  cancelLinkedAgentExecutionApprovalWith,
  recordLinkedAgentExecutionSubmissionWith,
} from "./agent-execution-approval-repository";
import { getDatabase } from "./db";
import { requireOrganizationRole, requireOrganizationRoleWith } from "./repository";
import {
  auditEvents,
  confirmationJobs,
  idempotencyRequests,
  indexedChainEvents,
  organizations,
  payrollRuns,
  proofBundles,
  proofVerificationJobs,
  settlements,
  vaultRecords,
  wageRemediations,
} from "./schema";

const PAYROLL_SEALED_EVENT_SELECTOR = "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea";
const PRIVATE_ACTION_INVOKED_EVENT_SELECTOR = "0x35aecaf019d9809fd216be64aa8e5f6f6feda13fa33ae33e886585668aaa28f";

type SealRecoveryBinding = {
  eventSelector: typeof PAYROLL_SEALED_EVENT_SELECTOR;
  mode: bigint;
  proofVersion: bigint;
  runNullifierHigh: bigint;
  runNullifierLow: bigint;
  shardCalldataHashes: readonly [bigint, bigint];
};

type PrivateActionRecoveryBinding = {
  eventSelector: typeof PRIVATE_ACTION_INVOKED_EVENT_SELECTOR;
  mode: bigint;
  subjectHigh: bigint;
  subjectLow: bigint;
  factHigh: bigint;
  factLow: bigint;
  actionHigh: bigint;
  actionLow: bigint;
};

type ApprovalRecoveryBinding = SealRecoveryBinding | PrivateActionRecoveryBinding;

type SealRecoveryCandidate = {
  workflowType: SettlementWorkflow;
  subjectRecordId: string;
  proofType: string;
  proofVersion: string;
  proofPackage: unknown;
};

const RECOVERY_PROFILE = {
  payroll: { proofType: "payroll_integrity", mode: 0n, proofVersions: [1n, 2n] },
  wage_claim: { proofType: "wage_claim", mode: 2n, proofVersions: [3n] },
  wage_remediation: { proofType: "wage_remediation", mode: 3n, proofVersions: [4n] },
} as const;

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function bigintValue(value: unknown): bigint | null {
  try {
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "bigint") return null;
    const parsed = BigInt(value);
    return parsed >= 0n ? parsed : null;
  } catch {
    return null;
  }
}

function sealRecoveryBinding(candidate: SealRecoveryCandidate): SealRecoveryBinding | null {
  const profile = RECOVERY_PROFILE[candidate.workflowType];
  const proofVersion = bigintValue(candidate.proofVersion);
  const proofPackage = record(candidate.proofPackage);
  const commonInputs = record(proofPackage?.commonInputs);
  const shardHashes = proofPackage?.shardCalldataHashes;
  if (
    proofVersion === null
    || !profile.proofVersions.some((version) => version === proofVersion)
    || proofPackage?.proofType !== profile.proofType
    || proofPackage.subjectRecordId !== candidate.subjectRecordId
    || proofPackage.proofVersion !== candidate.proofVersion
    || commonInputs?.proofVersion !== candidate.proofVersion
    || !Array.isArray(shardHashes)
    || shardHashes.length !== 2
  ) return null;
  const runNullifierHigh = bigintValue(commonInputs.runNullifierHigh);
  const runNullifierLow = bigintValue(commonInputs.runNullifierLow);
  const shard0Hash = bigintValue(shardHashes[0]);
  const shard1Hash = bigintValue(shardHashes[1]);
  if (
    runNullifierHigh === null
    || runNullifierLow === null
    || shard0Hash === null
    || shard1Hash === null
  ) return null;
  return {
    eventSelector: PAYROLL_SEALED_EVENT_SELECTOR,
    mode: profile.mode,
    proofVersion,
    runNullifierHigh,
    runNullifierLow,
    shardCalldataHashes: [shard0Hash, shard1Hash],
  };
}

function privateActionRecoveryBinding(
  candidate: SealRecoveryCandidate,
): PrivateActionRecoveryBinding | null {
  if (
    candidate.workflowType !== "wage_remediation"
    || candidate.proofType !== "wage_remediation"
    || candidate.proofVersion !== "7"
  ) return null;
  const proofPackage = record(candidate.proofPackage);
  const publicInputs = record(proofPackage?.publicInputs);
  if (
    proofPackage?.schemaVersion !== 2
    || proofPackage.proofType !== "wage_remediation"
    || proofPackage.subjectRecordId !== candidate.subjectRecordId
    || proofPackage.proofVersion !== "7"
    || publicInputs?.proofVersion !== "7"
    || publicInputs.schemaVersion !== "2"
    || publicInputs.shardIndex !== "0"
  ) return null;
  const values = [
    publicInputs.subjectNullifierHigh,
    publicInputs.subjectNullifierLow,
    publicInputs.factCommitmentHigh,
    publicInputs.factCommitmentLow,
    publicInputs.manifestRootHigh,
    publicInputs.manifestRootLow,
  ].map(bigintValue);
  if (values.some((value) => value === null)) return null;
  return {
    eventSelector: PRIVATE_ACTION_INVOKED_EVENT_SELECTOR,
    mode: 3n,
    subjectHigh: values[0]!,
    subjectLow: values[1]!,
    factHigh: values[2]!,
    factLow: values[3]!,
    actionHigh: values[4]!,
    actionLow: values[5]!,
  };
}

function approvalRecoveryBinding(candidate: SealRecoveryCandidate): ApprovalRecoveryBinding | null {
  return privateActionRecoveryBinding(candidate) ?? sealRecoveryBinding(candidate);
}

function payrollSealedEventMatches(payload: unknown, binding: SealRecoveryBinding): boolean {
  const event = record(payload);
  const keys = event?.keys;
  const data = event?.data;
  if (!Array.isArray(keys) || keys.length < 3 || !Array.isArray(data) || data.length < 4) return false;
  const values = [keys[1], keys[2], data[0], data[1], data[2], data[3]].map(bigintValue);
  return values.every((value) => value !== null)
    && values[0] === binding.runNullifierHigh
    && values[1] === binding.runNullifierLow
    && values[2] === binding.mode
    && values[3] === binding.shardCalldataHashes[0]
    && values[4] === binding.shardCalldataHashes[1]
    && values[5] === binding.proofVersion;
}

function privateActionEventMatches(
  payload: unknown,
  binding: PrivateActionRecoveryBinding,
): boolean {
  const event = record(payload);
  const keys = event?.keys;
  const data = event?.data;
  if (!Array.isArray(keys) || keys.length < 4 || !Array.isArray(data) || data.length < 4) return false;
  const values = [keys[0], keys[1], keys[2], keys[3], ...data.slice(0, 4)].map(bigintValue);
  return values.every((value) => value !== null)
    && values[0] === BigInt(binding.eventSelector)
    && values[1] === binding.mode
    && values[2] === binding.subjectHigh
    && values[3] === binding.subjectLow
    && values[4] === binding.factHigh
    && values[5] === binding.factLow
    && values[6] === binding.actionHigh
    && values[7] === binding.actionLow;
}

function approvalEventMatches(payload: unknown, binding: ApprovalRecoveryBinding): boolean {
  return binding.eventSelector === PRIVATE_ACTION_INVOKED_EVENT_SELECTOR
    ? privateActionEventMatches(payload, binding)
    : payrollSealedEventMatches(payload, binding);
}

const IDEMPOTENCY_LOCK_MS = 60_000;
const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CONFIRMATION_ATTEMPTS = 80;
const DELAYED_CONFIRMATION_POLL_MS = 5 * 60_000;

function assertIdempotencyKey(key: string): void {
  if (!/^[A-Za-z0-9._:-]{16,256}$/.test(key)) {
    throw new ApiError(400, "A 16–256 character idempotency key is required.", "IDEMPOTENCY_KEY_INVALID");
  }
}

function assertTransactionHash(hash: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(hash)) {
    throw new ApiError(400, "A valid Starknet transaction hash is required.", "TRANSACTION_HASH_INVALID");
  }
  return hash.toLowerCase();
}

export async function createSettlementIntent(input: {
  id: string;
  organizationId: string;
  runId: string;
  workflowType: SettlementWorkflow;
  subjectRecordId: string;
  walletRequestId: string;
  idempotencyKey: string;
  tokenTotalsCommitment: string;
  agentPlanCommitment?: string;
  envelope: EncryptedVaultRecord;
  principal: AuthenticatedPrincipal;
}) {
  assertIdempotencyKey(input.idempotencyKey);
  const workflowType = settlementWorkflowSchema.parse(input.workflowType);
  if (!/^0x[0-9a-fA-F]{64}$/.test(input.tokenTotalsCommitment)) {
    throw new ApiError(400, "A canonical token-totals commitment is required.", "TOTALS_COMMITMENT_INVALID");
  }
  if (input.agentPlanCommitment && !/^0x[0-9a-fA-F]{64}$/.test(input.agentPlanCommitment)) {
    throw new ApiError(400, "A canonical agent-plan commitment is required.", "AGENT_PLAN_COMMITMENT_INVALID");
  }
  const envelope = encryptedVaultRecordSchema.parse(input.envelope);
  if (
    envelope.aad.organizationId !== input.organizationId
    || envelope.aad.recordId !== input.id
    || envelope.aad.recordType !== "settlement"
    || envelope.aad.revision !== 1
  ) {
    throw new ApiError(400, "Encrypted settlement AAD does not match its storage identity.", "AAD_MISMATCH");
  }
  const envelopeHash = hashCanonicalJson(envelope);
  const database = getDatabase();
  const requestHash = hashCanonicalJson({
    organizationId: input.organizationId,
    settlementId: input.id,
    runId: input.runId,
    workflowType,
    subjectRecordId: input.subjectRecordId,
    walletRequestId: input.walletRequestId,
    tokenTotalsCommitment: input.tokenTotalsCommitment.toLowerCase(),
    agentPlanCommitment: input.agentPlanCommitment?.toLowerCase() ?? null,
    envelopeHash,
  });
  const now = new Date();

  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin", "operator"]);
    const [organization] = await transaction
      .select({ recoveryState: organizations.recoveryState })
      .from(organizations)
      .where(eq(organizations.id, input.organizationId))
      .limit(1);
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    if (organization.recoveryState === "required") {
      throw new ApiError(409, "Configure vault recovery before settlement.", "VAULT_RECOVERY_REQUIRED");
    }

    const [run] = await transaction
      .select({ organizationId: payrollRuns.organizationId, state: payrollRuns.state })
      .from(payrollRuns)
      .where(eq(payrollRuns.id, input.runId))
      .limit(1);
    if (!run || run.organizationId !== input.organizationId) {
      throw new ApiError(404, "Payroll run not found in this organization.", "RUN_NOT_FOUND");
    }

    let routedWageRemediation: typeof wageRemediations.$inferSelect | undefined;
    if (workflowType === "payroll") {
      if (input.subjectRecordId !== input.runId) {
        throw new ApiError(400, "Payroll settlement subject must be the payroll run.", "SETTLEMENT_SUBJECT_INVALID");
      }
    } else if (workflowType === "wage_remediation") {
      const [route] = await transaction.select({
        remediation: wageRemediations,
        proofType: proofBundles.proofType,
        proofVersion: proofBundles.proofVersion,
        verificationState: proofBundles.verificationState,
        verificationTransactionHash: proofBundles.verificationTransactionHash,
        recordType: vaultRecords.recordType,
      }).from(wageRemediations).innerJoin(
        proofBundles,
        eq(proofBundles.id, wageRemediations.proofBundleId),
      ).innerJoin(vaultRecords, and(
        eq(vaultRecords.organizationId, wageRemediations.organizationId),
        eq(vaultRecords.id, wageRemediations.id),
        eq(vaultRecords.recordType, "wage-remediation-v2"),
        isNull(vaultRecords.supersededAt),
      )).where(and(
        eq(wageRemediations.id, input.subjectRecordId),
        eq(wageRemediations.organizationId, input.organizationId),
        eq(wageRemediations.runId, input.runId),
      )).limit(1).for("update");
      if (
        !route
        || !["authorized", "payment_pending"].includes(route.remediation.state)
        || route.remediation.validityExpiresAt.getTime() <= now.getTime()
        || (route.remediation.settlementId
          && route.remediation.settlementId !== input.id)
        || route.proofType !== "wage_remediation"
        || route.proofVersion !== "7"
        || route.verificationState !== "onchain_verified"
        || !route.verificationTransactionHash
        || route.recordType !== "wage-remediation-v2"
      ) {
        throw new ApiError(
          409,
          "Private remediation requires one unexpired on-chain authorized Remediation v7 attempt.",
          "REMEDIATION_AUTHORIZATION_REQUIRED",
        );
      }
      routedWageRemediation = route.remediation;
    } else {
      const expectedProofType = workflowType;
      const expectedRecordType = "wage-claim";
      const [subject] = await transaction
        .select({ id: vaultRecords.id })
        .from(vaultRecords)
        .where(and(
          eq(vaultRecords.organizationId, input.organizationId),
          eq(vaultRecords.id, input.subjectRecordId),
          eq(vaultRecords.recordType, expectedRecordType),
          isNull(vaultRecords.supersededAt),
        ))
        .limit(1);
      if (!subject) {
        throw new ApiError(404, "Encrypted exception subject was not found.", "SETTLEMENT_SUBJECT_NOT_FOUND");
      }
      const [proof] = await transaction
        .select({ id: proofBundles.id, verificationState: proofBundles.verificationState })
        .from(proofBundles)
        .where(and(
          eq(proofBundles.organizationId, input.organizationId),
          eq(proofBundles.runId, input.runId),
          eq(proofBundles.proofType, expectedProofType),
          eq(proofBundles.subjectRecordId, input.subjectRecordId),
        ))
        .limit(1);
      if (!proof || !["locally_verified", "onchain_verified"].includes(proof.verificationState)) {
        throw new ApiError(409, "A locally verified exception proof is required before approval.", "EXCEPTION_PROOF_REQUIRED");
      }
    }


    const [insertedRequest] = await transaction
      .insert(idempotencyRequests)
      .values({
        organizationId: input.organizationId,
        scope: "settlement-intent",
        key: input.idempotencyKey,
        requestHash,
        lockedUntil: new Date(now.getTime() + IDEMPOTENCY_LOCK_MS),
        expiresAt: new Date(now.getTime() + IDEMPOTENCY_TTL_MS),
      })
      .onConflictDoNothing()
      .returning({ key: idempotencyRequests.key });

    if (!insertedRequest) {
      const [request] = await transaction
        .select()
        .from(idempotencyRequests)
        .where(and(
          eq(idempotencyRequests.organizationId, input.organizationId),
          eq(idempotencyRequests.scope, "settlement-intent"),
          eq(idempotencyRequests.key, input.idempotencyKey),
        ))
        .limit(1);
      if (!request) throw new ApiError(409, "Idempotency state was lost; retry later.", "IDEMPOTENCY_STATE_LOST");
      if (request.requestHash !== requestHash) {
        throw new ApiError(409, "This idempotency key was used with different settlement data.", "IDEMPOTENCY_MISMATCH");
      }
      const [existing] = await transaction
        .select()
        .from(settlements)
        .where(and(
          eq(settlements.organizationId, input.organizationId),
          eq(settlements.idempotencyKey, input.idempotencyKey),
        ))
        .limit(1);
      if (existing) return { ...existing, replayed: true };
      if (request.lockedUntil > now && request.state === "started") {
        throw new ApiError(409, "This settlement request is already being processed.", "IDEMPOTENCY_IN_PROGRESS");
      }
      await transaction
        .update(idempotencyRequests)
        .set({
          state: "started",
          errorCode: null,
          lockedUntil: new Date(now.getTime() + IDEMPOTENCY_LOCK_MS),
          updatedAt: now,
        })
        .where(and(
          eq(idempotencyRequests.organizationId, input.organizationId),
          eq(idempotencyRequests.scope, "settlement-intent"),
          eq(idempotencyRequests.key, input.idempotencyKey),
        ));
    }

    const requiredRunState = workflowType === "payroll"
      ? "proven"
      : workflowType === "wage_claim"
        ? "confirmed"
        : "disputed";
    if (!routedWageRemediation && run.state !== requiredRunState) {
      throw new ApiError(
        409,
        `${workflowType} requires a ${requiredRunState} payroll; current state is ${run.state}.`,
        workflowType === "payroll" ? "RUN_NOT_PROVEN" : "EXCEPTION_RUN_STATE_INVALID",
      );
    }

    const id = input.id;
    await transaction.insert(vaultRecords).values({
      id,
      organizationId: input.organizationId,
      recordType: "settlement",
      revision: 1,
      ciphertext: envelope.ciphertext,
      envelope,
      envelopeHash,
      createdBy: input.principal.principalId,
    });
    const [settlement] = await transaction
      .insert(settlements)
      .values({
        id,
        organizationId: input.organizationId,
        runId: input.runId,
        workflowType,
        subjectRecordId: input.subjectRecordId,
        walletRequestId: input.walletRequestId,
        idempotencyKey: input.idempotencyKey,
        tokenTotalsCommitment: input.tokenTotalsCommitment.toLowerCase(),
        agentPlanCommitment: input.agentPlanCommitment?.toLowerCase() ?? null,
      })
      .returning();
    if (routedWageRemediation) {
      const [updatedRemediation] = await transaction.update(wageRemediations).set({
        settlementId: settlement.id,
        state: "payment_pending",
        updatedAt: now,
      }).where(and(
        eq(wageRemediations.id, routedWageRemediation.id),
        eq(wageRemediations.state, "authorized"),
        isNull(wageRemediations.settlementId),
      )).returning({ id: wageRemediations.id });
      if (!updatedRemediation && routedWageRemediation.settlementId !== settlement.id) {
        throw new ApiError(
          409,
          "Remediation state changed before private payment approval.",
          "REMEDIATION_STATE_CONFLICT",
        );
      }
    }
    if (workflowType === "payroll") {
      const [updatedRun] = await transaction
        .update(payrollRuns)
        .set({ state: "approval_pending", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
        .where(and(eq(payrollRuns.id, input.runId), eq(payrollRuns.state, "proven")))
        .returning({ id: payrollRuns.id });
      if (!updatedRun) throw new ApiError(409, "Payroll state changed; refresh before approval.", "RUN_STATE_CONFLICT");
    }
    await transaction
      .update(idempotencyRequests)
      .set({ state: "succeeded", response: { settlementId: id }, lockedUntil: now, updatedAt: now })
      .where(and(
        eq(idempotencyRequests.organizationId, input.organizationId),
        eq(idempotencyRequests.scope, "settlement-intent"),
        eq(idempotencyRequests.key, input.idempotencyKey),
      ));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "settlement.approval_requested",
      subjectId: id,
      metadata: { runId: input.runId, workflowType, subjectRecordId: input.subjectRecordId, requestHash },
    });
    return { ...settlement, replayed: false };
  });
}

export async function recordSettlementSubmission(input: {
  settlementId: string;
  transactionHash: string;
  principal: AuthenticatedPrincipal;
}) {
  const transactionHash = assertTransactionHash(input.transactionHash);
  const database = getDatabase();
  const now = new Date();
  return database.transaction(async (transaction) => {
    const [existing] = await transaction
      .select()
      .from(settlements)
      .where(eq(settlements.id, input.settlementId))
      .limit(1)
      .for("update");
    if (!existing) throw new ApiError(404, "Settlement not found.", "SETTLEMENT_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, existing.organizationId, input.principal, ["admin", "operator"]);
    if (existing.transactionHash) {
      if (existing.transactionHash.toLowerCase() !== transactionHash) {
        throw new ApiError(409, "Settlement already has a different transaction hash.", "TRANSACTION_HASH_CONFLICT");
      }
      return {
        ...existing,
        blockNumber: existing.blockNumber === null ? null : existing.blockNumber.toString(),
        replayed: true,
      };
    }
    assertSettlementTransition(existing.state, "submitted");
    const [settlement] = await transaction
      .update(settlements)
      .set({ state: "submitted", transactionHash, submittedAt: now, updatedAt: now })
      .where(and(eq(settlements.id, input.settlementId), eq(settlements.state, "approval_pending")))
      .returning();
    if (!settlement) throw new ApiError(409, "Settlement state changed; refresh and retry.", "SETTLEMENT_STATE_CONFLICT");
    if (existing.workflowType === "payroll") {
      const [run] = await transaction
        .update(payrollRuns)
        .set({ state: "submitted", transactionHash, updatedAt: now, version: sql`${payrollRuns.version} + 1` })
        .where(and(eq(payrollRuns.id, existing.runId), eq(payrollRuns.state, "approval_pending")))
        .returning({ id: payrollRuns.id });
      if (!run) throw new ApiError(409, "Payroll state changed during submission.", "RUN_STATE_CONFLICT");
    }
    await recordLinkedAgentExecutionSubmissionWith(transaction, {
      settlementId: existing.id,
      transactionHash,
      actorId: input.principal.principalId,
      now,
    });
    await transaction
      .insert(confirmationJobs)
      .values({ id: generateUuidV7(), settlementId: input.settlementId })
      .onConflictDoNothing();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: existing.organizationId,
      actorId: input.principal.principalId,
      action: "settlement.submitted",
      subjectId: input.settlementId,
      metadata: { transactionHash, workflowType: existing.workflowType, subjectRecordId: existing.subjectRecordId },
    });
    return {
      ...settlement,
      blockNumber: settlement.blockNumber === null ? null : settlement.blockNumber.toString(),
      replayed: false,
    };
  });
}

/**
 * Recovers a wallet submission when Ready executed the atomic STRK20 request
 * but did not resolve `wallet_strk20InvokeTransaction` with its transaction
 * hash. Legacy workflows require their exact canonical PayrollSealed binding;
 * Remediation v7 requires the canonical PrivateActionInvoked mode, subject,
 * fact, and action commitments. Salary, token totals, and recipients are
 * neither indexed nor inspected.
 */
export async function recoverApprovalSubmissionsFromSealEvents(input: {
  chainId: string;
  sealAddress: string;
  limit?: number;
}) {
  const limit = input.limit ?? 100;
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
    throw new Error("Approval recovery limit must be 1–500.");
  }
  const database = getDatabase();
  const candidates = await database
    .select({
      settlementId: settlements.id,
      runId: settlements.runId,
      organizationId: settlements.organizationId,
      workflowType: settlements.workflowType,
      subjectRecordId: settlements.subjectRecordId,
      proofBundleId: proofBundles.id,
      proofType: proofBundles.proofType,
      proofVersion: proofBundles.proofVersion,
      proofPackage: proofBundles.proofPackage,
    })
    .from(settlements)
    .innerJoin(proofBundles, and(
      eq(proofBundles.organizationId, settlements.organizationId),
      eq(proofBundles.runId, settlements.runId),
      eq(proofBundles.subjectRecordId, settlements.subjectRecordId),
      or(
        and(eq(settlements.workflowType, "payroll"), eq(proofBundles.proofType, "payroll_integrity")),
        and(eq(settlements.workflowType, "wage_claim"), eq(proofBundles.proofType, "wage_claim")),
        and(eq(settlements.workflowType, "wage_remediation"), eq(proofBundles.proofType, "wage_remediation")),
      ),
    ))
    .where(and(
      or(
        eq(settlements.workflowType, "payroll"),
        eq(settlements.workflowType, "wage_claim"),
        eq(settlements.workflowType, "wage_remediation"),
      ),
      eq(settlements.state, "approval_pending"),
      isNull(settlements.transactionHash),
    ));
  if (candidates.length === 0) return { recovered: 0 };

  let normalizedSeal: string;
  try {
    normalizedSeal = `0x${BigInt(input.sealAddress).toString(16)}`;
  } catch {
    throw new Error("A valid PAYO seal address is required for approval recovery.");
  }
  const events = await database
    .select({
      transactionHash: indexedChainEvents.transactionHash,
      eventIndex: indexedChainEvents.eventIndex,
      blockNumber: indexedChainEvents.blockNumber,
      payload: indexedChainEvents.payload,
    })
    .from(indexedChainEvents)
    .where(and(
      eq(indexedChainEvents.chainId, input.chainId),
      eq(indexedChainEvents.contractAddress, normalizedSeal),
      or(
        eq(indexedChainEvents.eventName, PAYROLL_SEALED_EVENT_SELECTOR),
        eq(indexedChainEvents.eventName, PRIVATE_ACTION_INVOKED_EVENT_SELECTOR),
      ),
      eq(indexedChainEvents.canonical, true),
    ))
    .orderBy(desc(indexedChainEvents.blockNumber))
    .limit(1_000);

  let recovered = 0;
  const matches = candidates.flatMap((candidate) => {
    const workflowType = settlementWorkflowSchema.safeParse(candidate.workflowType);
    if (!workflowType.success) return [];
    const binding = approvalRecoveryBinding({ ...candidate, workflowType: workflowType.data });
    if (!binding) return [];
    return events
      .filter(({ payload }) => approvalEventMatches(payload, binding))
      .map((event) => ({ candidate: { ...candidate, workflowType: workflowType.data }, event }));
  });
  const settlementMatchCounts = new Map<string, number>();
  const eventMatchCounts = new Map<string, number>();
  for (const match of matches) {
    settlementMatchCounts.set(
      match.candidate.settlementId,
      (settlementMatchCounts.get(match.candidate.settlementId) ?? 0) + 1,
    );
    const eventIdentity = `${match.event.transactionHash}:${match.event.eventIndex}`;
    eventMatchCounts.set(eventIdentity, (eventMatchCounts.get(eventIdentity) ?? 0) + 1);
  }
  for (const { candidate, event } of matches) {
    if (recovered >= limit) break;
    const eventIdentity = `${event.transactionHash}:${event.eventIndex}`;
    if (
      settlementMatchCounts.get(candidate.settlementId) !== 1
      || eventMatchCounts.get(eventIdentity) !== 1
    ) continue;

    const now = new Date();
    const didRecover = await database.transaction(async (transaction) => {
      const [current] = await transaction
        .select({ state: settlements.state, transactionHash: settlements.transactionHash })
        .from(settlements)
        .where(eq(settlements.id, candidate.settlementId))
        .limit(1)
        .for("update");
      if (!current || current.state !== "approval_pending" || current.transactionHash) return false;
      const [existingTransaction] = await transaction
        .select({ id: settlements.id })
        .from(settlements)
        .where(eq(settlements.transactionHash, event.transactionHash))
        .limit(1);
      if (existingTransaction && existingTransaction.id !== candidate.settlementId) return false;
      const [settlement] = await transaction
        .update(settlements)
        .set({
          state: "submitted",
          transactionHash: event.transactionHash,
          submittedAt: now,
          updatedAt: now,
        })
        .where(and(
          eq(settlements.id, candidate.settlementId),
          eq(settlements.state, "approval_pending"),
          isNull(settlements.transactionHash),
        ))
        .returning({ id: settlements.id });
      if (!settlement) return false;
      if (candidate.workflowType === "payroll") {
        const [run] = await transaction
          .update(payrollRuns)
          .set({
            state: "submitted",
            transactionHash: event.transactionHash,
            updatedAt: now,
            version: sql`${payrollRuns.version} + 1`,
          })
          .where(and(eq(payrollRuns.id, candidate.runId), eq(payrollRuns.state, "approval_pending")))
          .returning({ id: payrollRuns.id });
        if (!run) throw new Error("Payroll state changed during seal-event recovery.");
      }
      await recordLinkedAgentExecutionSubmissionWith(transaction, {
        settlementId: candidate.settlementId,
        transactionHash: event.transactionHash,
        actorId: "system:seal-indexer",
        now,
      });
      await transaction
        .insert(confirmationJobs)
        .values({ id: generateUuidV7(), settlementId: candidate.settlementId })
        .onConflictDoNothing();
      await transaction.insert(auditEvents).values({
        id: generateUuidV7(),
        organizationId: candidate.organizationId,
        actorId: "system:seal-indexer",
        action: "settlement.submission_recovered",
        subjectId: candidate.settlementId,
        metadata: {
          transactionHash: event.transactionHash,
          blockNumber: event.blockNumber.toString(),
          evidence: "canonical_proof_bound_sealed_event",
          proofBundleId: candidate.proofBundleId,
          workflowType: candidate.workflowType,
        },
      });
      return true;
    });
    if (didRecover) recovered += 1;
  }
  return { recovered };
}

export async function getSealedRunRecoveryEvidence(input: {
  runId: string;
  chainId: string;
  sealAddress: string;
  principal: AuthenticatedPrincipal;
}) {
  const database = getDatabase();
  const [run] = await database
    .select({
      id: payrollRuns.id,
      organizationId: payrollRuns.organizationId,
      state: payrollRuns.state,
      transactionHash: payrollRuns.transactionHash,
      runNullifier: payrollRuns.runNullifier,
    })
    .from(payrollRuns)
    .where(eq(payrollRuns.id, input.runId))
    .limit(1);
  if (!run) throw new ApiError(404, "Payroll run not found.", "RUN_NOT_FOUND");
  await requireOrganizationRole(run.organizationId, input.principal, ["admin", "operator"]);
  const [bundle] = await database
    .select({
      id: proofBundles.id,
      proofType: proofBundles.proofType,
      proofVersion: proofBundles.proofVersion,
      subjectRecordId: proofBundles.subjectRecordId,
      proofPackage: proofBundles.proofPackage,
    })
    .from(proofBundles)
    .where(and(
      eq(proofBundles.runId, run.id),
      eq(proofBundles.organizationId, run.organizationId),
      eq(proofBundles.proofType, "payroll_integrity"),
      eq(proofBundles.subjectRecordId, run.id),
    ))
    .orderBy(desc(proofBundles.createdAt))
    .limit(1);
  if (!bundle) throw new ApiError(409, "The encrypted proof bundle is missing.", "PROOF_BUNDLE_MISSING");

  // A finalized private transfer can outlive the browser request that was
  // supposed to enqueue its on-chain proof verification. The proof calldata
  // remains encrypted in the organization's vault, so return only the public
  // settlement binding and let an authorized browser decrypt and enqueue it.
  if (run.transactionHash && ["submitted", "confirmed", "reconciled"].includes(run.state)) {
    const [settlement] = await database
      .select({
        id: settlements.id,
        transactionHash: settlements.transactionHash,
        blockNumber: settlements.blockNumber,
      })
      .from(settlements)
      .where(and(
        eq(settlements.runId, run.id),
        eq(settlements.workflowType, "payroll"),
      ))
      .orderBy(desc(settlements.createdAt))
      .limit(1);
    if (
      !settlement?.transactionHash
      || BigInt(settlement.transactionHash) !== BigInt(run.transactionHash)
    ) {
      throw new ApiError(
        409,
        "The confirmed payroll has no matching durable settlement.",
        "PAYROLL_SETTLEMENT_MISMATCH",
      );
    }
    return {
      recoveryKind: "verification" as const,
      runId: run.id,
      proofBundleId: bundle.id,
      settlementId: settlement.id,
      transactionHash: run.transactionHash,
      blockNumber: settlement.blockNumber?.toString() ?? "0",
    };
  }

  if (run.state !== "proven" || run.transactionHash || !run.runNullifier) {
    throw new ApiError(409, "This payroll has no recoverable sealed submission.", "RUN_NOT_RECOVERABLE");
  }
  let normalizedSeal: string;
  try {
    normalizedSeal = `0x${BigInt(input.sealAddress).toString(16)}`;
  } catch {
    throw new Error("A valid PAYO seal address is required for run recovery.");
  }
  const events = await database
    .select({
      transactionHash: indexedChainEvents.transactionHash,
      blockNumber: indexedChainEvents.blockNumber,
      payload: indexedChainEvents.payload,
    })
    .from(indexedChainEvents)
    .where(and(
      eq(indexedChainEvents.chainId, input.chainId),
      eq(indexedChainEvents.contractAddress, normalizedSeal),
      eq(indexedChainEvents.eventName, PAYROLL_SEALED_EVENT_SELECTOR),
      eq(indexedChainEvents.canonical, true),
    ))
    .orderBy(desc(indexedChainEvents.blockNumber))
    .limit(1_000);
  const binding = sealRecoveryBinding({
    workflowType: "payroll",
    subjectRecordId: run.id,
    proofType: bundle.proofType,
    proofVersion: bundle.proofVersion,
    proofPackage: bundle.proofPackage,
  });
  const evidence = binding
    ? events.find(({ payload }) => payrollSealedEventMatches(payload, binding))
    : undefined;
  if (!evidence) {
    throw new ApiError(404, "No canonical PayrollSealed event matches this run.", "SEALED_SUBMISSION_NOT_FOUND");
  }
  return {
    recoveryKind: "submission" as const,
    runId: run.id,
    proofBundleId: bundle.id,
    transactionHash: evidence.transactionHash,
    blockNumber: evidence.blockNumber.toString(),
  };
}

export async function cancelSettlementApproval(input: {
  settlementId: string;
  principal: AuthenticatedPrincipal;
}) {
  const database = getDatabase();
  const now = new Date();
  return database.transaction(async (transaction) => {
    const [existing] = await transaction
      .select()
      .from(settlements)
      .where(eq(settlements.id, input.settlementId))
      .limit(1)
      .for("update");
    if (!existing) throw new ApiError(404, "Settlement not found.", "SETTLEMENT_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, existing.organizationId, input.principal, ["admin", "operator"]);
    if (existing.transactionHash || existing.state !== "approval_pending") {
      throw new ApiError(
        409,
        "Only an approval with no recorded transaction hash can be cancelled.",
        "SETTLEMENT_CANCELLATION_UNSAFE",
      );
    }
    assertSettlementTransition(existing.state, "failed");
    const [settlement] = await transaction
      .update(settlements)
      .set({
        state: "failed",
        lastErrorCode: "WALLET_APPROVAL_CANCELLED",
        lastErrorMessage: "The operator confirmed that Ready did not submit a transaction.",
        updatedAt: now,
      })
      .where(and(
        eq(settlements.id, input.settlementId),
        eq(settlements.state, "approval_pending"),
        isNull(settlements.transactionHash),
      ))
      .returning();
    if (!settlement) throw new ApiError(409, "Settlement state changed; refresh before cancelling.", "SETTLEMENT_STATE_CONFLICT");
    if (existing.workflowType === "payroll") {
      const [run] = await transaction
        .update(payrollRuns)
        .set({ state: "cancelled", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
        .where(and(eq(payrollRuns.id, existing.runId), eq(payrollRuns.state, "approval_pending")))
        .returning({ id: payrollRuns.id });
      if (!run) throw new ApiError(409, "Payroll state changed during cancellation.", "RUN_STATE_CONFLICT");
    } else if (existing.workflowType === "wage_remediation") {
      const [remediation] = await transaction
        .select({ id: wageRemediations.id, state: wageRemediations.state })
        .from(wageRemediations)
        .where(and(
          eq(wageRemediations.id, existing.subjectRecordId),
          eq(wageRemediations.settlementId, existing.id),
        ))
        .limit(1)
        .for("update");
      if (remediation) {
        const [released] = await transaction
          .update(wageRemediations)
          .set({
            state: sql`CASE
              WHEN ${wageRemediations.validityExpiresAt} <= ${now.toISOString()}::timestamptz
                THEN 'expired'::wage_remediation_state
              ELSE 'authorized'::wage_remediation_state
            END`,
            settlementId: null,
            paymentConfirmedAt: null,
            lastErrorCode: "WALLET_APPROVAL_CANCELLED",
            lastErrorMessage: "Ready approval was cancelled before PAYO recorded a transaction hash.",
            updatedAt: now,
          })
          .where(and(
            eq(wageRemediations.id, remediation.id),
            eq(wageRemediations.state, "payment_pending"),
            eq(wageRemediations.settlementId, existing.id),
          ))
          .returning({ id: wageRemediations.id });
        if (!released) {
          throw new ApiError(
            409,
            "Remediation state changed during cancellation.",
            "REMEDIATION_STATE_CONFLICT",
          );
        }
      }
    }
    await cancelLinkedAgentExecutionApprovalWith(transaction, {
      settlementId: existing.id,
      actorId: input.principal.principalId,
      now,
    });
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: existing.organizationId,
      actorId: input.principal.principalId,
      action: "settlement.approval_cancelled",
      subjectId: existing.id,
      metadata: { runId: existing.runId, workflowType: existing.workflowType, subjectRecordId: existing.subjectRecordId },
    });
    return settlement;
  });
}

export async function getSettlement(settlementId: string, principal: AuthenticatedPrincipal) {
  const [settlement] = await getDatabase().select().from(settlements).where(eq(settlements.id, settlementId)).limit(1);
  if (!settlement) throw new ApiError(404, "Settlement not found.", "SETTLEMENT_NOT_FOUND");
  await requireOrganizationRole(settlement.organizationId, principal, ["admin", "operator", "reviewer"]);
  return {
    ...settlement,
    blockNumber: settlement.blockNumber === null ? null : settlement.blockNumber.toString(),
  };
}

export async function listSettlements(
  organizationId: string,
  principal: AuthenticatedPrincipal,
  limit = 50,
) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new ApiError(400, "Settlement list limit must be 1–100.", "LIMIT_INVALID");
  }
  await requireOrganizationRole(organizationId, principal, ["admin", "operator", "reviewer"]);
  const rows = await getDatabase()
    .select({
      id: settlements.id,
      runId: settlements.runId,
      workflowType: settlements.workflowType,
      subjectRecordId: settlements.subjectRecordId,
      state: settlements.state,
      tokenTotalsCommitment: settlements.tokenTotalsCommitment,
      transactionHash: settlements.transactionHash,
      submittedAt: settlements.submittedAt,
      confirmedAt: settlements.confirmedAt,
      finalizedAt: settlements.finalizedAt,
      blockNumber: settlements.blockNumber,
      confirmationDepth: settlements.confirmationDepth,
      lastErrorCode: settlements.lastErrorCode,
      proofPackage: proofBundles.proofPackage,
      proofVerificationState: proofVerificationJobs.state,
      proofVerificationLastErrorCode: proofVerificationJobs.lastErrorCode,
      createdAt: settlements.createdAt,
      updatedAt: settlements.updatedAt,
    })
    .from(settlements)
    .leftJoin(proofBundles, and(
      eq(proofBundles.organizationId, settlements.organizationId),
      eq(proofBundles.runId, settlements.runId),
      eq(proofBundles.subjectRecordId, settlements.subjectRecordId),
      or(
        and(eq(settlements.workflowType, "payroll"), eq(proofBundles.proofType, "payroll_integrity")),
        and(eq(settlements.workflowType, "wage_claim"), eq(proofBundles.proofType, "wage_claim")),
        and(eq(settlements.workflowType, "wage_remediation"), eq(proofBundles.proofType, "wage_remediation")),
      ),
    ))
    .leftJoin(proofVerificationJobs, eq(proofVerificationJobs.settlementId, settlements.id))
    .where(eq(settlements.organizationId, organizationId))
    .orderBy(desc(settlements.updatedAt))
    .limit(limit);
  return rows.map(({ proofPackage, ...row }) => {
    const commonInputs = record(record(proofPackage)?.commonInputs);
    const validityExpiry = bigintValue(commonInputs?.validityExpiry);
    return {
      ...row,
      blockNumber: row.blockNumber === null ? null : row.blockNumber.toString(),
      proofValidityExpiry: validityExpiry?.toString() ?? null,
    };
  });
}

export type LeasedConfirmationJob = {
  id: string;
  settlementId: string;
  attempts: number;
  transactionHash: string;
};

export async function leaseConfirmationJobs(
  workerId: string,
  limit = 10,
  now = new Date(),
): Promise<LeasedConfirmationJob[]> {
  if (!workerId.trim()) throw new Error("A confirmation worker ID is required.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("Confirmation job limit must be 1–100.");
  const database = getDatabase();
  const leaseExpiresAt = new Date(now.getTime() + 60_000);
  return database.transaction(async (transaction) => {
    const leased = await transaction
      .update(confirmationJobs)
      .set({ state: "leased", leaseOwner: workerId, leaseExpiresAt, updatedAt: now })
      .where(sql`${confirmationJobs.id} IN (
        SELECT ${confirmationJobs.id}
        FROM ${confirmationJobs}
        WHERE (
          (${confirmationJobs.state} = 'pending' AND ${confirmationJobs.availableAt} <= ${now.toISOString()}::timestamptz)
          OR (${confirmationJobs.state} = 'leased' AND ${confirmationJobs.leaseExpiresAt} <= ${now.toISOString()}::timestamptz)
        )
        ORDER BY ${confirmationJobs.availableAt}
        FOR UPDATE SKIP LOCKED
        LIMIT ${limit}
      )`)
      .returning({
        id: confirmationJobs.id,
        settlementId: confirmationJobs.settlementId,
        attempts: confirmationJobs.attempts,
      });
    const jobs: LeasedConfirmationJob[] = [];
    for (const job of leased) {
      const [settlement] = await transaction
        .select({ transactionHash: settlements.transactionHash })
        .from(settlements)
        .where(eq(settlements.id, job.settlementId))
        .limit(1);
      if (!settlement?.transactionHash) {
        await transaction
          .update(confirmationJobs)
          .set({ state: "dead", lastErrorCode: "TRANSACTION_HASH_MISSING", updatedAt: now })
          .where(eq(confirmationJobs.id, job.id));
        continue;
      }
      jobs.push({ ...job, transactionHash: settlement.transactionHash });
    }
    return jobs;
  });
}

function retryDelayMs(attempts: number): number {
  return Math.min(60_000, 1_500 * 2 ** Math.min(attempts, 5));
}

export async function applySettlementObservation(
  job: LeasedConfirmationJob,
  observation: SettlementObservation,
  now = new Date(),
) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [current] = await transaction.select().from(settlements).where(eq(settlements.id, job.settlementId)).limit(1);
    if (!current) throw new Error("Confirmation job references a missing settlement.");
    const nextAttempts = job.attempts + 1;

    if (observation.state === "pending") {
      const delayed = nextAttempts >= MAX_CONFIRMATION_ATTEMPTS;
      await transaction
        .update(confirmationJobs)
        .set({
          // Receipt absence is not proof of failure. Keep monitoring the durable
          // hash at a slower rate after the normal retry window.
          state: "pending",
          attempts: Math.min(nextAttempts, MAX_CONFIRMATION_ATTEMPTS),
          availableAt: new Date(now.getTime() + (
            delayed ? DELAYED_CONFIRMATION_POLL_MS : retryDelayMs(nextAttempts)
          )),
          leaseOwner: null,
          leaseExpiresAt: null,
          lastErrorCode: delayed ? "CONFIRMATION_DELAYED" : observation.errorCode ?? null,
          updatedAt: now,
        })
        .where(eq(confirmationJobs.id, job.id));
      if (delayed) {
        await transaction
          .update(settlements)
          .set({
            lastErrorCode: "CONFIRMATION_DELAYED",
            lastErrorMessage: "The transaction hash is still being monitored; it was not classified as failed.",
            updatedAt: now,
          })
          .where(eq(settlements.id, job.settlementId));
        if (nextAttempts === MAX_CONFIRMATION_ATTEMPTS) {
          await transaction.insert(auditEvents).values({
            id: generateUuidV7(),
            organizationId: current.organizationId,
            actorId: "system:confirmation-worker",
            action: "settlement.confirmation_delayed",
            subjectId: current.id,
            metadata: { transactionHash: current.transactionHash, attempts: nextAttempts },
          });
        }
      }
      return { state: "pending", delayed };
    }

    const settlementState = observation.state;
    // A worker may first observe a transaction only after it already has the
    // final confirmation depth. Preserve the strict state machine while
    // accepting that valid monotonic fast-forward instead of requiring the RPC
    // to have exposed an earlier, shallower receipt to this worker.
    const skippedConfirmedState = current.state === "submitted" && settlementState === "finalized";
    if (skippedConfirmedState) {
      assertSettlementTransition("submitted", "confirmed");
      assertSettlementTransition("confirmed", "finalized");
    } else if (settlementState !== current.state) {
      assertSettlementTransition(current.state, settlementState);
    }
    await transaction
      .update(settlements)
      .set({
        state: settlementState,
        blockNumber: observation.blockNumber,
        blockHash: observation.blockHash,
        confirmationDepth: observation.confirmationDepth,
        confirmedAt: settlementState === "confirmed" || settlementState === "finalized" ? current.confirmedAt ?? now : current.confirmedAt,
        finalizedAt: settlementState === "finalized" ? now : null,
        lastErrorCode: observation.errorCode ?? null,
        lastErrorMessage: observation.errorMessage ?? null,
        updatedAt: now,
      })
      .where(eq(settlements.id, job.settlementId));

    if (
      current.workflowType === "payroll"
      && (settlementState === "confirmed" || settlementState === "finalized")
      && current.state === "submitted"
    ) {
      await transaction
        .update(payrollRuns)
        .set({ state: "confirmed", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
        .where(and(eq(payrollRuns.id, current.runId), eq(payrollRuns.state, "submitted")));
    } else if (current.workflowType === "payroll" && settlementState === "failed") {
      await transaction
        .update(payrollRuns)
        .set({ state: "failed", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
        .where(and(eq(payrollRuns.id, current.runId), eq(payrollRuns.state, "submitted")));
    } else if (current.workflowType === "payroll" && settlementState === "reorged") {
      await transaction
        .update(payrollRuns)
        .set({
          state: current.state === "submitted" ? "failed" : "disputed",
          updatedAt: now,
          version: sql`${payrollRuns.version} + 1`,
        })
        .where(and(
          eq(payrollRuns.id, current.runId),
          or(eq(payrollRuns.state, "submitted"), eq(payrollRuns.state, "confirmed")),
        ));
    }

    if (current.workflowType === "wage_remediation") {
      if (settlementState === "confirmed" || settlementState === "finalized") {
        await transaction.update(wageRemediations).set({
          state: "payment_confirmed",
          paymentConfirmedAt: now,
          lastErrorCode: null,
          lastErrorMessage: null,
          updatedAt: now,
        }).where(and(
          eq(wageRemediations.id, current.subjectRecordId),
          eq(wageRemediations.settlementId, current.id),
        ));
      } else if (settlementState === "failed" || settlementState === "reorged") {
        await transaction.update(wageRemediations).set({
          state: sql`CASE
            WHEN ${wageRemediations.validityExpiresAt} <= ${now.toISOString()}::timestamptz
              THEN 'expired'::wage_remediation_state
            ELSE 'authorized'::wage_remediation_state
          END`,
          settlementId: null,
          paymentConfirmedAt: null,
          lastErrorCode: observation.errorCode ?? settlementState.toUpperCase(),
          lastErrorMessage: observation.errorMessage ?? null,
          updatedAt: now,
        }).where(and(
          eq(wageRemediations.id, current.subjectRecordId),
          eq(wageRemediations.settlementId, current.id),
        ));
      }
    }

    await applyLinkedAgentSettlementObservationWith(transaction, {
      settlementId: current.id,
      settlementState,
      transactionHash: current.transactionHash,
      errorCode: observation.errorCode,
      now,
    });

    const terminal = settlementState === "finalized" || settlementState === "failed";
    await transaction
      .update(confirmationJobs)
      .set({
        state: terminal ? (settlementState === "failed" ? "dead" : "complete") : "pending",
        attempts: nextAttempts,
        availableAt: new Date(now.getTime() + retryDelayMs(nextAttempts)),
        leaseOwner: null,
        leaseExpiresAt: null,
        lastErrorCode: observation.errorCode ?? null,
        updatedAt: now,
      })
      .where(eq(confirmationJobs.id, job.id));
    await transaction.insert(auditEvents).values([
      ...(skippedConfirmedState ? [{
        id: generateUuidV7(),
        organizationId: current.organizationId,
        actorId: "system:confirmation-worker",
        action: "settlement.confirmed",
        subjectId: current.id,
        metadata: {
          transactionHash: current.transactionHash,
          confirmationDepth: observation.confirmationDepth,
          evidence: "finalized_receipt_fast_forward",
        },
      }] : []),
      {
        id: generateUuidV7(),
        organizationId: current.organizationId,
        actorId: "system:confirmation-worker",
        action: `settlement.${settlementState}`,
        subjectId: current.id,
        metadata: {
          transactionHash: current.transactionHash,
          confirmationDepth: observation.confirmationDepth,
          errorCode: observation.errorCode ?? null,
        },
      },
    ]);
    return { state: settlementState };
  });
}
