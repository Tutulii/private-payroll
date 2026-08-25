import "server-only";

import { and, desc, eq, or, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  assertSettlementTransition,
  type SettlementObservation,
} from "@/lib/domain/settlement";
import { encryptedVaultRecordSchema, type EncryptedVaultRecord } from "@/lib/crypto/vault";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole, requireOrganizationRoleWith } from "./repository";
import {
  auditEvents,
  confirmationJobs,
  idempotencyRequests,
  organizations,
  payrollRuns,
  settlements,
  vaultRecords,
} from "./schema";

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
  walletRequestId: string;
  idempotencyKey: string;
  tokenTotalsCommitment: string;
  envelope: EncryptedVaultRecord;
  principal: AuthenticatedPrincipal;
}) {
  assertIdempotencyKey(input.idempotencyKey);
  if (!/^0x[0-9a-fA-F]{64}$/.test(input.tokenTotalsCommitment)) {
    throw new ApiError(400, "A canonical token-totals commitment is required.", "TOTALS_COMMITMENT_INVALID");
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
    walletRequestId: input.walletRequestId,
    tokenTotalsCommitment: input.tokenTotalsCommitment.toLowerCase(),
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

    if (run.state !== "proven") {
      throw new ApiError(409, `Payroll must be proven before approval; current state is ${run.state}.`, "RUN_NOT_PROVEN");
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
        walletRequestId: input.walletRequestId,
        idempotencyKey: input.idempotencyKey,
        tokenTotalsCommitment: input.tokenTotalsCommitment.toLowerCase(),
      })
      .returning();
    const [updatedRun] = await transaction
      .update(payrollRuns)
      .set({ state: "approval_pending", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
      .where(and(eq(payrollRuns.id, input.runId), eq(payrollRuns.state, "proven")))
      .returning({ id: payrollRuns.id });
    if (!updatedRun) throw new ApiError(409, "Payroll state changed; refresh before approval.", "RUN_STATE_CONFLICT");
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
      metadata: { runId: input.runId, requestHash },
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
      return { ...existing, replayed: true };
    }
    assertSettlementTransition(existing.state, "submitted");
    const [settlement] = await transaction
      .update(settlements)
      .set({ state: "submitted", transactionHash, submittedAt: now, updatedAt: now })
      .where(and(eq(settlements.id, input.settlementId), eq(settlements.state, "approval_pending")))
      .returning();
    if (!settlement) throw new ApiError(409, "Settlement state changed; refresh and retry.", "SETTLEMENT_STATE_CONFLICT");
    const [run] = await transaction
      .update(payrollRuns)
      .set({ state: "submitted", transactionHash, updatedAt: now, version: sql`${payrollRuns.version} + 1` })
      .where(and(eq(payrollRuns.id, existing.runId), eq(payrollRuns.state, "approval_pending")))
      .returning({ id: payrollRuns.id });
    if (!run) throw new ApiError(409, "Payroll state changed during submission.", "RUN_STATE_CONFLICT");
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
      metadata: { transactionHash },
    });
    return { ...settlement, replayed: false };
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
      state: settlements.state,
      tokenTotalsCommitment: settlements.tokenTotalsCommitment,
      transactionHash: settlements.transactionHash,
      submittedAt: settlements.submittedAt,
      confirmedAt: settlements.confirmedAt,
      finalizedAt: settlements.finalizedAt,
      blockNumber: settlements.blockNumber,
      confirmationDepth: settlements.confirmationDepth,
      lastErrorCode: settlements.lastErrorCode,
      createdAt: settlements.createdAt,
      updatedAt: settlements.updatedAt,
    })
    .from(settlements)
    .where(eq(settlements.organizationId, organizationId))
    .orderBy(desc(settlements.updatedAt))
    .limit(limit);
  return rows.map((row) => ({
    ...row,
    blockNumber: row.blockNumber === null ? null : row.blockNumber.toString(),
  }));
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
    if (settlementState !== current.state) {
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

    if ((settlementState === "confirmed" || settlementState === "finalized") && current.state === "submitted") {
      await transaction
        .update(payrollRuns)
        .set({ state: "confirmed", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
        .where(and(eq(payrollRuns.id, current.runId), eq(payrollRuns.state, "submitted")));
    } else if (settlementState === "failed") {
      await transaction
        .update(payrollRuns)
        .set({ state: "failed", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
        .where(and(eq(payrollRuns.id, current.runId), eq(payrollRuns.state, "submitted")));
    } else if (settlementState === "reorged") {
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
    await transaction.insert(auditEvents).values({
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
    });
    return { state: settlementState };
  });
}
