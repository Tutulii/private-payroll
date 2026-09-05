import "server-only";

import { and, eq, sql } from "drizzle-orm";
import {
  authorizePaymentBatch,
  type AgentExecutionRequest,
} from "@/lib/domain/capability";
import { commitAgentExecutionRequest, type AgentExecutionState } from "@/lib/domain/agent-execution";
import { generateUuidV7 } from "@/lib/domain/records";
import { decryptAgentExecutionRequest } from "@/lib/server/agent-execution-crypto";
import { decryptCapabilityPolicy } from "@/lib/server/capability-policy-crypto";
import { getDatabase } from "./db";
import {
  agentCapabilities,
  agentExecutions,
  auditEvents,
  capabilityReservations,
  payrollRuns,
} from "./schema";

const LEASE_MS = 10 * 60_000;
const RETRY_MS = 5_000;
const HASH_PATTERN = /^0x[0-9a-fA-F]{1,64}$/;
const COMMITMENT_PATTERN = /^0x[0-9a-fA-F]{64}$/;

export type LeasedAgentExecution = {
  id: string;
  capabilityId: string;
  reservationId: string;
  organizationId: string;
  runId: string;
  state: Extract<AgentExecutionState, "reserved" | "preparing" | "submitting" | "submitted">;
  attempts: number;
  runVersion: number;
  requestCommitment: string;
  request: AgentExecutionRequest;
  submissionCommitment: string | null;
  transactionHash: string | null;
  leaseOwner: string;
};

type Transaction = Parameters<Parameters<ReturnType<typeof getDatabase>["transaction"]>[0]>[0];

function errorCode(value: string): string {
  const normalized = value.trim().toUpperCase().replace(/[^A-Z0-9_]/g, "_").slice(0, 80);
  return normalized || "AGENT_EXECUTION_FAILED";
}

async function failInvalidLease(
  transaction: Transaction,
  execution: typeof agentExecutions.$inferSelect,
  code: string,
  now: Date,
): Promise<void> {
  const terminalErrorCode = errorCode(code);
  const preSubmission = ["reserved", "preparing"].includes(execution.state);
  // Preparation retries retain their last safe driver code. If the request
  // later expires during lease reauthorization, surface the actionable root
  // failure rather than replacing it with the secondary expiry symptom.
  const effectiveErrorCode = preSubmission
    ? execution.errorCode ?? terminalErrorCode
    : terminalErrorCode;
  if (preSubmission) {
    await transaction.update(capabilityReservations).set({ state: "released", updatedAt: now }).where(and(
      eq(capabilityReservations.id, execution.reservationId),
      eq(capabilityReservations.state, "reserved"),
    ));
  }
  await transaction.update(agentExecutions).set({
    state: "failed",
    errorCode: effectiveErrorCode,
    lastErrorAt: now,
    leaseOwner: null,
    leaseExpiresAt: null,
    updatedAt: now,
  }).where(eq(agentExecutions.id, execution.id));
  await transaction.insert(auditEvents).values({
    id: generateUuidV7(),
    organizationId: execution.organizationId,
    actorId: "system:agent-execution-worker",
    action: "agent_execution.failed_closed",
    subjectId: execution.id,
    metadata: {
      errorCode: effectiveErrorCode,
      terminalErrorCode,
      requestCommitment: execution.requestCommitment,
    },
  });
}

export async function leaseAgentExecutions(
  workerId: string,
  limit = 2,
  now = new Date(),
): Promise<LeasedAgentExecution[]> {
  if (!/^[A-Za-z0-9._:-]{3,128}$/.test(workerId)) throw new Error("A valid agent-execution worker ID is required.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 10) throw new Error("Agent-execution lease limit must be 1–10.");
  const leaseExpiresAt = new Date(now.getTime() + LEASE_MS);
  return getDatabase().transaction(async (transaction) => {
    const leased = await transaction.update(agentExecutions).set({
      leaseOwner: workerId,
      leaseExpiresAt,
      attempts: sql`${agentExecutions.attempts} + 1`,
      updatedAt: now,
    }).where(sql`${agentExecutions.id} IN (
      SELECT executions.id
      FROM agent_executions AS executions
      WHERE executions.requires_approval = false
        AND executions.state IN ('reserved', 'preparing', 'submitting', 'submitted')
        AND executions.available_at <= ${now.toISOString()}::timestamptz
        AND (executions.lease_owner IS NULL OR executions.lease_expires_at <= ${now.toISOString()}::timestamptz)
      ORDER BY executions.available_at, executions.created_at
      FOR UPDATE OF executions SKIP LOCKED
      LIMIT ${limit}
    )`).returning();

    const output: LeasedAgentExecution[] = [];
    for (const execution of leased) {
      try {
        if (!(["reserved", "preparing", "submitting", "submitted"] as string[]).includes(execution.state)) {
          throw new Error("AGENT_EXECUTION_STATE_INVALID");
        }
        const [[capability], [reservation], [run]] = await Promise.all([
          transaction.select().from(agentCapabilities)
            .where(eq(agentCapabilities.id, execution.capabilityId)).limit(1),
          transaction.select().from(capabilityReservations)
            .where(eq(capabilityReservations.id, execution.reservationId)).limit(1),
          transaction.select().from(payrollRuns)
            .where(eq(payrollRuns.id, execution.runId)).limit(1),
        ]);
        if (!capability || !reservation || !run) throw new Error("AGENT_EXECUTION_REFERENCE_MISSING");
        if (
          capability.organizationId !== execution.organizationId
          || reservation.organizationId !== execution.organizationId
          || run.organizationId !== execution.organizationId
        ) throw new Error("AGENT_EXECUTION_TENANT_MISMATCH");
        if (capability.revokedAt || capability.expiresAt <= now) throw new Error("CAPABILITY_INACTIVE");
        const preSubmission = execution.state === "reserved" || execution.state === "preparing";
        if (preSubmission && (reservation.state !== "reserved" || reservation.expiresAt <= now)) {
          throw new Error("RESERVATION_INACTIVE");
        }
        if (reservation.createdAt > now) throw new Error("RESERVATION_TIME_INVALID");
        if (!preSubmission && reservation.state !== "committed") {
          throw new Error("RESERVATION_NOT_COMMITTED");
        }
        if (preSubmission && run.version !== execution.runVersion) throw new Error("AGENT_RUN_VERSION_CHANGED");
        const request = decryptAgentExecutionRequest(execution.requestPayload, {
          executionId: execution.id,
          capabilityId: execution.capabilityId,
          organizationId: execution.organizationId,
          requestCommitment: execution.requestCommitment,
        });
        if (
          request.runId !== execution.runId
          || commitAgentExecutionRequest(request) !== execution.requestCommitment
        ) throw new Error("AGENT_EXECUTION_REQUEST_TAMPERED");
        if (preSubmission) {
          const signedCapability = decryptCapabilityPolicy(capability.policy, {
            capabilityId: capability.id,
            organizationId: capability.organizationId,
            principalId: capability.principalId,
            capabilityHash: capability.capabilityHash,
          });
          // Intent expiry is an admission boundary, not a proof-runtime
          // deadline. The request already passed an atomic, serialized policy
          // check when this reservation was created; replay that exact decision
          // at its admission timestamp. Current capability revocation/expiry,
          // reservation expiry, and run-version drift are checked above. Using
          // `now` here killed valid Mainnet jobs whenever proof generation took
          // longer than the intent's five-minute anti-replay window.
          const authorization = authorizePaymentBatch(
            signedCapability.capability,
            request.intents,
            reservation.createdAt,
          );
          if (!authorization.allowed || authorization.requiresApproval) {
            throw new Error("AGENT_EXECUTION_REAUTHORIZATION_DENIED");
          }
        }
        output.push({
          id: execution.id,
          capabilityId: execution.capabilityId,
          reservationId: execution.reservationId,
          organizationId: execution.organizationId,
          runId: execution.runId,
          state: execution.state as LeasedAgentExecution["state"],
          attempts: execution.attempts,
          runVersion: execution.runVersion,
          requestCommitment: execution.requestCommitment,
          request,
          submissionCommitment: execution.submissionCommitment,
          transactionHash: execution.transactionHash,
          leaseOwner: workerId,
        });
      } catch (error) {
        await failInvalidLease(
          transaction,
          execution,
          error instanceof Error ? error.message : "AGENT_EXECUTION_DATA_INVALID",
          now,
        );
      }
    }
    return output;
  });
}

async function assertLease(transaction: Transaction, job: LeasedAgentExecution, now: Date) {
  const [execution] = await transaction.select().from(agentExecutions).where(and(
    eq(agentExecutions.id, job.id),
    eq(agentExecutions.leaseOwner, job.leaseOwner),
  )).limit(1).for("update");
  if (!execution || !execution.leaseExpiresAt || execution.leaseExpiresAt <= now) {
    throw new Error("Agent execution lease is stale.");
  }
  return execution;
}

export async function markAgentExecutionPreparing(job: LeasedAgentExecution, now = new Date()) {
  return getDatabase().transaction(async (transaction) => {
    const execution = await assertLease(transaction, job, now);
    if (execution.state !== "reserved" && execution.state !== "preparing") {
      throw new Error("Only a pre-submission execution can be prepared.");
    }
    const [updated] = await transaction.update(agentExecutions).set({
      state: "preparing",
      updatedAt: now,
    }).where(eq(agentExecutions.id, job.id)).returning();
    return updated;
  });
}

/** Point of no return: the limit reservation becomes spent before signing. */
export async function commitAgentExecutionForSubmission(
  job: LeasedAgentExecution,
  submissionCommitment: string,
  now = new Date(),
) {
  if (!COMMITMENT_PATTERN.test(submissionCommitment)) throw new Error("A canonical submission commitment is required.");
  return getDatabase().transaction(async (transaction) => {
    const execution = await assertLease(transaction, job, now);
    if (execution.state !== "preparing") throw new Error("Agent execution is not ready for submission.");
    const [reservation] = await transaction.select().from(capabilityReservations).where(
      eq(capabilityReservations.id, execution.reservationId),
    ).limit(1).for("update");
    if (!reservation || reservation.state !== "reserved" || reservation.expiresAt <= now) {
      throw new Error("Agent execution reservation expired before signing.");
    }
    await transaction.update(capabilityReservations).set({ state: "committed", updatedAt: now })
      .where(eq(capabilityReservations.id, reservation.id));
    const [updated] = await transaction.update(agentExecutions).set({
      state: "submitting",
      submissionCommitment: submissionCommitment.toLowerCase(),
      errorCode: null,
      updatedAt: now,
    }).where(eq(agentExecutions.id, execution.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: execution.organizationId,
      actorId: "system:agent-execution-worker",
      action: "agent_execution.submission_committed",
      subjectId: execution.id,
      metadata: {
        requestCommitment: execution.requestCommitment,
        submissionCommitment: submissionCommitment.toLowerCase(),
      },
    });
    return updated;
  });
}

export async function recordAgentExecutionSubmission(
  job: LeasedAgentExecution,
  transactionHash: string,
  now = new Date(),
) {
  if (!HASH_PATTERN.test(transactionHash)) throw new Error("A valid Starknet transaction hash is required.");
  return getDatabase().transaction(async (transaction) => {
    const execution = await assertLease(transaction, job, now);
    if (execution.state !== "submitting") throw new Error("Agent execution is not awaiting a submission hash.");
    const [updated] = await transaction.update(agentExecutions).set({
      state: "submitted",
      transactionHash: transactionHash.toLowerCase(),
      availableAt: new Date(now.getTime() + 2_000),
      leaseOwner: null,
      leaseExpiresAt: null,
      errorCode: null,
      updatedAt: now,
    }).where(eq(agentExecutions.id, execution.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: execution.organizationId,
      actorId: "system:agent-execution-worker",
      action: "agent_execution.submitted",
      subjectId: execution.id,
      metadata: { transactionHash: transactionHash.toLowerCase() },
    });
    return updated;
  });
}

export async function completeAgentExecution(job: LeasedAgentExecution, now = new Date()) {
  return getDatabase().transaction(async (transaction) => {
    const execution = await assertLease(transaction, job, now);
    if (execution.state !== "submitted" || !execution.transactionHash) {
      throw new Error("Only a submitted agent execution can be confirmed.");
    }
    const [updated] = await transaction.update(agentExecutions).set({
      state: "confirmed",
      leaseOwner: null,
      leaseExpiresAt: null,
      errorCode: null,
      updatedAt: now,
    }).where(eq(agentExecutions.id, execution.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: execution.organizationId,
      actorId: "system:agent-execution-worker",
      action: "agent_execution.confirmed",
      subjectId: execution.id,
      metadata: { transactionHash: execution.transactionHash },
    });
    return updated;
  });
}

export async function reconcileAgentExecution(job: LeasedAgentExecution, now = new Date()) {
  return getDatabase().transaction(async (transaction) => {
    const execution = await assertLease(transaction, job, now);
    if (execution.state !== "submitted" || !execution.transactionHash) {
      throw new Error("Only a submitted agent execution can be reconciled.");
    }
    const [updated] = await transaction.update(agentExecutions).set({
      state: "reconciled",
      leaseOwner: null,
      leaseExpiresAt: null,
      errorCode: null,
      updatedAt: now,
    }).where(eq(agentExecutions.id, execution.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: execution.organizationId,
      actorId: "system:agent-execution-worker",
      action: "agent_execution.reconciled",
      subjectId: execution.id,
      metadata: { transactionHash: execution.transactionHash },
    });
    return updated;
  });
}

export async function deferAgentExecution(
  job: LeasedAgentExecution,
  input: { errorCode: string; permanent?: boolean; preSubmission?: boolean },
  now = new Date(),
) {
  return getDatabase().transaction(async (transaction) => {
    const execution = await assertLease(transaction, job, now);
    const canRelease = input.preSubmission === true
      && (execution.state === "reserved" || execution.state === "preparing");
    if (canRelease && input.permanent) {
      await transaction.update(capabilityReservations).set({ state: "released", updatedAt: now }).where(and(
        eq(capabilityReservations.id, execution.reservationId),
        eq(capabilityReservations.state, "reserved"),
      ));
    }
    const nextState = input.permanent ? "failed" : execution.state;
    const [updated] = await transaction.update(agentExecutions).set({
      state: nextState,
      errorCode: errorCode(input.errorCode),
      lastErrorAt: now,
      availableAt: new Date(now.getTime() + RETRY_MS),
      leaseOwner: null,
      leaseExpiresAt: null,
      updatedAt: now,
    }).where(eq(agentExecutions.id, execution.id)).returning();
    if (input.permanent) {
      await transaction.insert(auditEvents).values({
        id: generateUuidV7(),
        organizationId: execution.organizationId,
        actorId: "system:agent-execution-worker",
        action: "agent_execution.failed",
        subjectId: execution.id,
        metadata: { errorCode: errorCode(input.errorCode), preSubmission: canRelease },
      });
    }
    return updated;
  });
}
