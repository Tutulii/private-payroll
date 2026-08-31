import "server-only";

import { and, desc, eq, inArray } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { commitAgentExecutionRequest } from "@/lib/domain/agent-execution";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  commitAgentSettlementPlan,
  commitTokenTotals,
  tokenTotalsSchema,
} from "@/lib/domain/settlement";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { decryptAgentExecutionRequest } from "@/lib/server/agent-execution-crypto";
import { getDatabase } from "./db";
import { agentExecutionReceipt } from "./agent-execution-repository";
import { requireOrganizationRoleWith } from "./repository";
import {
  agentCapabilities,
  agentExecutions,
  auditEvents,
  capabilityReservations,
  payrollRuns,
  proofBundles,
  settlements,
} from "./schema";

type Transaction = Parameters<Parameters<ReturnType<typeof getDatabase>["transaction"]>[0]>[0];

const HASH_PATTERN = /^0x[0-9a-fA-F]{1,64}$/;

function totalsForRequest(request: ReturnType<typeof decryptAgentExecutionRequest>) {
  const totals = { STRK: 0n, USDC: 0n };
  for (const intent of request.intents) totals[intent.token] += BigInt(intent.amountAtomic);
  return tokenTotalsSchema.parse({
    STRK: totals.STRK.toString(),
    USDC: totals.USDC.toString(),
  });
}

function humanSubmissionCommitment(input: {
  executionId: string;
  settlementId: string;
  requestCommitment: string;
  tokenTotalsCommitment: string;
}) {
  return hashCanonicalJson({
    domain: "PAYO_HUMAN_APPROVED_AGENT_SETTLEMENT_V1",
    ...input,
  });
}

/**
 * Binds a human-reviewed Ready settlement to one approval-pending execution.
 * The browser supplies only durable record IDs. PAYO reloads and locks every
 * authoritative row, decrypts the original request server-side, and checks its
 * exact token totals against the settlement commitment before linking it.
 */
export async function linkAgentExecutionToHumanSettlement(input: {
  capabilityId: string;
  executionId: string;
  settlementId: string;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    // All Ready lifecycle paths lock settlement -> execution. Keep that order
    // here as well so a simultaneous wallet submission cannot deadlock linking.
    const [settlement] = await transaction.select().from(settlements)
      .where(eq(settlements.id, input.settlementId)).limit(1).for("update");
    if (!settlement) throw new ApiError(404, "Settlement not found.", "SETTLEMENT_NOT_FOUND");
    const [execution] = await transaction.select().from(agentExecutions).where(and(
      eq(agentExecutions.id, input.executionId),
      eq(agentExecutions.capabilityId, input.capabilityId),
    )).limit(1).for("update");
    if (!execution) throw new ApiError(404, "Agent execution not found.", "AGENT_EXECUTION_NOT_FOUND");
    await requireOrganizationRoleWith(
      transaction,
      execution.organizationId,
      input.principal,
      ["admin", "operator"],
    );
    if (!execution.requiresApproval) {
      throw new ApiError(409, "Autonomous executions cannot use Ready approval.", "AGENT_APPROVAL_NOT_REQUIRED");
    }
    if (execution.settlementId) {
      if (execution.settlementId !== input.settlementId) {
        throw new ApiError(409, "This execution is linked to another settlement.", "AGENT_SETTLEMENT_CONFLICT");
      }
      return agentExecutionReceipt(execution, true);
    }
    if (execution.state !== "approval_pending") {
      throw new ApiError(409, `A ${execution.state} execution cannot be linked.`, "AGENT_APPROVAL_STATE_CONFLICT");
    }

    const [capability] = await transaction.select().from(agentCapabilities)
      .where(eq(agentCapabilities.id, execution.capabilityId)).limit(1).for("update");
    const [reservation] = await transaction.select().from(capabilityReservations)
      .where(eq(capabilityReservations.id, execution.reservationId)).limit(1).for("update");
    const [run] = await transaction.select().from(payrollRuns)
      .where(eq(payrollRuns.id, execution.runId)).limit(1).for("update");
    const [proof] = await transaction
      .select({ id: proofBundles.id, verificationState: proofBundles.verificationState })
      .from(proofBundles).where(and(
        eq(proofBundles.organizationId, execution.organizationId),
        eq(proofBundles.runId, execution.runId),
        eq(proofBundles.proofType, "payroll_integrity"),
        eq(proofBundles.subjectRecordId, execution.runId),
      )).limit(1).for("update");
    if (!capability || capability.organizationId !== execution.organizationId) {
      throw new ApiError(409, "The execution capability is unavailable.", "CAPABILITY_NOT_FOUND");
    }
    if (capability.revokedAt || capability.expiresAt <= now) {
      throw new ApiError(409, "The execution capability is no longer active.", "CAPABILITY_INACTIVE");
    }
    if (
      !reservation
      || reservation.capabilityId !== execution.capabilityId
      || reservation.organizationId !== execution.organizationId
      || !reservation.requiresApproval
      || reservation.state !== "reserved"
      || reservation.expiresAt <= now
    ) {
      throw new ApiError(409, "The human-approval reservation is no longer active.", "RESERVATION_INACTIVE");
    }
    if (
      settlement.organizationId !== execution.organizationId
      || settlement.runId !== execution.runId
      || settlement.workflowType !== "payroll"
      || settlement.subjectRecordId !== execution.runId
      || settlement.state !== "approval_pending"
      || settlement.transactionHash
    ) {
      throw new ApiError(409, "Ready approval must use the exact unsigned payroll settlement.", "AGENT_SETTLEMENT_INVALID");
    }
    if (
      !run
      || run.organizationId !== execution.organizationId
      || run.state !== "approval_pending"
      || run.transactionHash
    ) {
      throw new ApiError(409, "The authoritative payroll run is not awaiting Ready approval.", "AGENT_RUN_STATE_INVALID");
    }
    if (!proof || !["locally_verified", "onchain_verified"].includes(proof.verificationState)) {
      throw new ApiError(409, "A verified PayrollIntegrity proof is required.", "AGENT_PAYROLL_PROOF_REQUIRED");
    }

    const request = decryptAgentExecutionRequest(execution.requestPayload, {
      executionId: execution.id,
      capabilityId: execution.capabilityId,
      organizationId: execution.organizationId,
      requestCommitment: execution.requestCommitment,
    });
    if (
      request.runId !== execution.runId
      || commitAgentExecutionRequest(request) !== execution.requestCommitment
    ) {
      throw new ApiError(409, "The stored agent request failed commitment verification.", "AGENT_EXECUTION_TAMPERED");
    }
    const expectedTotalsCommitment = commitTokenTotals({
      organizationId: execution.organizationId,
      runId: execution.runId,
      totals: totalsForRequest(request),
    });
    if (expectedTotalsCommitment !== settlement.tokenTotalsCommitment.toLowerCase()) {
      throw new ApiError(409, "The Ready settlement totals do not match the agent request.", "AGENT_SETTLEMENT_TOTALS_MISMATCH");
    }
    const expectedPlanCommitment = commitAgentSettlementPlan({
      organizationId: execution.organizationId,
      runId: execution.runId,
      payments: request.intents.map((intent) => ({
        recipientAddress: intent.recipientAddress,
        token: intent.token,
        amountAtomic: intent.amountAtomic,
        purposeCode: intent.purposeCode,
      })),
    });
    if (
      !settlement.agentPlanCommitment
      || expectedPlanCommitment !== settlement.agentPlanCommitment.toLowerCase()
    ) {
      throw new ApiError(
        409,
        "The Ready settlement recipients or payment terms do not match the agent request.",
        "AGENT_SETTLEMENT_PLAN_MISMATCH",
      );
    }

    const [linkedReservation] = await transaction.update(capabilityReservations).set({
      state: "approval_linked",
      updatedAt: now,
    }).where(and(
      eq(capabilityReservations.id, reservation.id),
      eq(capabilityReservations.state, "reserved"),
    )).returning({ id: capabilityReservations.id });
    if (!linkedReservation) {
      throw new ApiError(409, "The approval reservation changed; refresh and retry.", "RESERVATION_STATE_CONFLICT");
    }
    const [linked] = await transaction.update(agentExecutions).set({
      settlementId: settlement.id,
      errorCode: null,
      updatedAt: now,
    }).where(and(
      eq(agentExecutions.id, execution.id),
      eq(agentExecutions.state, "approval_pending"),
    )).returning();
    if (!linked) throw new ApiError(409, "The execution changed; refresh and retry.", "AGENT_APPROVAL_STATE_CONFLICT");
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: execution.organizationId,
      actorId: input.principal.principalId,
      action: "agent_execution.human_settlement_linked",
      subjectId: execution.id,
      metadata: {
        settlementId: settlement.id,
        runId: execution.runId,
        requestCommitment: execution.requestCommitment,
        tokenTotalsCommitment: settlement.tokenTotalsCommitment,
        agentPlanCommitment: settlement.agentPlanCommitment,
        proofBundleId: proof.id,
      },
    });
    return agentExecutionReceipt(linked, false);
  });
}

export async function listHumanApprovalExecutions(input: {
  organizationId: string;
  principal: AuthenticatedPrincipal;
  limit?: number;
}) {
  const limit = input.limit ?? 50;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new ApiError(400, "Approval list limit must be 1–100.", "LIMIT_INVALID");
  }
  return getDatabase().transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin", "operator"]);
    const rows = await transaction.select().from(agentExecutions).where(and(
      eq(agentExecutions.organizationId, input.organizationId),
      eq(agentExecutions.requiresApproval, true),
      inArray(agentExecutions.state, ["approval_pending", "submitted", "confirmed", "failed", "released"]),
    )).orderBy(desc(agentExecutions.updatedAt)).limit(limit);
    return rows.map((row) => agentExecutionReceipt(row, false));
  });
}

export async function cancelUnlinkedAgentExecutionApproval(input: {
  capabilityId: string;
  executionId: string;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    const [execution] = await transaction.select().from(agentExecutions).where(and(
      eq(agentExecutions.id, input.executionId),
      eq(agentExecutions.capabilityId, input.capabilityId),
    )).limit(1).for("update");
    if (!execution) throw new ApiError(404, "Agent execution not found.", "AGENT_EXECUTION_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, execution.organizationId, input.principal, ["admin", "operator"]);
    if (execution.state === "released") return agentExecutionReceipt(execution, true);
    if (!execution.requiresApproval || execution.state !== "approval_pending") {
      throw new ApiError(409, "Only a pending human approval can be cancelled.", "AGENT_APPROVAL_STATE_CONFLICT");
    }
    if (execution.settlementId) {
      throw new ApiError(
        409,
        "Cancel the linked Ready settlement; PAYO will release this approval atomically.",
        "AGENT_APPROVAL_SETTLEMENT_LINKED",
      );
    }
    await transaction.update(capabilityReservations).set({ state: "released", updatedAt: now }).where(and(
      eq(capabilityReservations.id, execution.reservationId),
      inArray(capabilityReservations.state, ["reserved", "expired"]),
    ));
    const [released] = await transaction.update(agentExecutions).set({
      state: "released",
      errorCode: "HUMAN_APPROVAL_CANCELLED",
      updatedAt: now,
    }).where(and(
      eq(agentExecutions.id, execution.id),
      eq(agentExecutions.state, "approval_pending"),
    )).returning();
    if (!released) throw new ApiError(409, "The approval changed; refresh and retry.", "AGENT_APPROVAL_STATE_CONFLICT");
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: execution.organizationId,
      actorId: input.principal.principalId,
      action: "agent_execution.human_approval_cancelled",
      subjectId: execution.id,
      metadata: { requestCommitment: execution.requestCommitment },
    });
    return agentExecutionReceipt(released, false);
  });
}

export async function recordLinkedAgentExecutionSubmissionWith(
  transaction: Transaction,
  input: { settlementId: string; transactionHash: string; actorId: string; now: Date },
): Promise<void> {
  if (!HASH_PATTERN.test(input.transactionHash)) throw new Error("A valid Starknet transaction hash is required.");
  const transactionHash = input.transactionHash.toLowerCase();
  const [execution] = await transaction.select().from(agentExecutions)
    .where(eq(agentExecutions.settlementId, input.settlementId)).limit(1).for("update");
  if (!execution) return;
  if (execution.transactionHash) {
    if (execution.transactionHash.toLowerCase() !== transactionHash) {
      throw new Error("Linked agent execution has a different transaction hash.");
    }
    if (["submitted", "confirmed"].includes(execution.state)) return;
  }
  if (!execution.requiresApproval || execution.state !== "approval_pending") {
    throw new Error(`Linked agent execution cannot record submission from ${execution.state}.`);
  }
  const [[reservation], [settlement]] = await Promise.all([
    transaction.select().from(capabilityReservations)
      .where(eq(capabilityReservations.id, execution.reservationId)).limit(1).for("update"),
    transaction.select({ tokenTotalsCommitment: settlements.tokenTotalsCommitment }).from(settlements)
      .where(eq(settlements.id, input.settlementId)).limit(1),
  ]);
  if (!reservation || reservation.state !== "approval_linked" || !settlement) {
    throw new Error("Linked human-approval reservation is not active.");
  }
  await transaction.update(capabilityReservations).set({ state: "committed", updatedAt: input.now })
    .where(and(
      eq(capabilityReservations.id, reservation.id),
      eq(capabilityReservations.state, "approval_linked"),
    ));
  const submissionCommitment = humanSubmissionCommitment({
    executionId: execution.id,
    settlementId: input.settlementId,
    requestCommitment: execution.requestCommitment,
    tokenTotalsCommitment: settlement.tokenTotalsCommitment,
  });
  const [submitted] = await transaction.update(agentExecutions).set({
    state: "submitted",
    transactionHash,
    submissionCommitment,
    errorCode: null,
    updatedAt: input.now,
  }).where(and(
    eq(agentExecutions.id, execution.id),
    eq(agentExecutions.state, "approval_pending"),
  )).returning({ id: agentExecutions.id });
  if (!submitted) throw new Error("Linked agent execution changed during settlement submission.");
  await transaction.insert(auditEvents).values({
    id: generateUuidV7(),
    organizationId: execution.organizationId,
    actorId: input.actorId,
    action: "agent_execution.human_approval_submitted",
    subjectId: execution.id,
    metadata: {
      settlementId: input.settlementId,
      transactionHash,
      submissionCommitment,
    },
  });
}

export async function cancelLinkedAgentExecutionApprovalWith(
  transaction: Transaction,
  input: { settlementId: string; actorId: string; now: Date },
): Promise<void> {
  const [execution] = await transaction.select().from(agentExecutions)
    .where(eq(agentExecutions.settlementId, input.settlementId)).limit(1).for("update");
  if (!execution || execution.state === "released") return;
  if (!execution.requiresApproval || execution.state !== "approval_pending" || execution.transactionHash) {
    throw new Error("A submitted agent approval cannot be released.");
  }
  const [releasedReservation] = await transaction.update(capabilityReservations).set({
    state: "released",
    updatedAt: input.now,
  }).where(and(
    eq(capabilityReservations.id, execution.reservationId),
    eq(capabilityReservations.state, "approval_linked"),
  )).returning({ id: capabilityReservations.id });
  if (!releasedReservation) throw new Error("Linked agent approval reservation changed during cancellation.");
  await transaction.update(agentExecutions).set({
    state: "released",
    errorCode: "HUMAN_APPROVAL_CANCELLED",
    updatedAt: input.now,
  }).where(eq(agentExecutions.id, execution.id));
  await transaction.insert(auditEvents).values({
    id: generateUuidV7(),
    organizationId: execution.organizationId,
    actorId: input.actorId,
    action: "agent_execution.human_approval_cancelled",
    subjectId: execution.id,
    metadata: { settlementId: input.settlementId },
  });
}

export async function applyLinkedAgentSettlementObservationWith(
  transaction: Transaction,
  input: {
    settlementId: string;
    settlementState: "confirmed" | "finalized" | "reorged" | "failed";
    transactionHash: string | null;
    errorCode?: string;
    now: Date;
  },
): Promise<void> {
  const [execution] = await transaction.select().from(agentExecutions)
    .where(eq(agentExecutions.settlementId, input.settlementId)).limit(1).for("update");
  if (!execution) return;
  if (
    execution.transactionHash
    && input.transactionHash
    && execution.transactionHash.toLowerCase() !== input.transactionHash.toLowerCase()
  ) throw new Error("Linked agent execution observation has a different transaction hash.");

  if (input.settlementState === "finalized") {
    if (execution.state === "confirmed") return;
    if (execution.state !== "submitted" || !execution.transactionHash) {
      throw new Error(`Linked agent execution cannot finalize from ${execution.state}.`);
    }
    await transaction.update(agentExecutions).set({
      state: "confirmed",
      errorCode: null,
      updatedAt: input.now,
    }).where(eq(agentExecutions.id, execution.id));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: execution.organizationId,
      actorId: "system:confirmation-worker",
      action: "agent_execution.human_approval_confirmed",
      subjectId: execution.id,
      metadata: { settlementId: input.settlementId, transactionHash: execution.transactionHash },
    });
    return;
  }
  if (input.settlementState === "failed") {
    if (execution.state === "failed") return;
    if (execution.state !== "submitted") {
      throw new Error(`Linked agent execution cannot fail from ${execution.state}.`);
    }
    await transaction.update(agentExecutions).set({
      state: "failed",
      errorCode: input.errorCode ?? "HUMAN_SETTLEMENT_FAILED",
      lastErrorAt: input.now,
      updatedAt: input.now,
    }).where(eq(agentExecutions.id, execution.id));
    return;
  }
  if (input.settlementState === "reorged" && execution.state === "submitted") {
    await transaction.update(agentExecutions).set({
      errorCode: "HUMAN_SETTLEMENT_REORGED",
      lastErrorAt: input.now,
      updatedAt: input.now,
    }).where(eq(agentExecutions.id, execution.id));
  }
  // `confirmed` is intentionally not terminal for the agent receipt. Human
  // approvals become confirmed only when the shared settlement worker reaches
  // PAYO's configured finality depth.
}
