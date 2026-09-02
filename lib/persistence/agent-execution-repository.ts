import "server-only";

import { and, desc, eq, or } from "drizzle-orm";
import {
  agentExecutionRequestSchema,
  type AgentExecutionRequest,
} from "@/lib/domain/capability";
import {
  agentExecutionReceiptSchema,
  commitAgentExecutionRequest,
  type AgentExecutionReceipt,
} from "@/lib/domain/agent-execution";
import {
  commitDirectPrivacyRunMaterial,
  directPrivacyRunMaterialSchema,
} from "@/lib/domain/direct-privacy";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import {
  decryptAgentExecutionRequest,
  encryptAgentExecutionRequest,
} from "@/lib/server/agent-execution-crypto";
import { encryptDirectPrivacyPayload } from "@/lib/server/direct-privacy-crypto";
import { getDatabase } from "./db";
import {
  reserveCapabilityPayment,
  transitionCapabilityReservation,
} from "./capability-reservations";
import { requireOrganizationRoleWith } from "./repository";
import {
  agentCapabilities,
  agentExecutions,
  auditEvents,
  directPrivacyAccounts,
  capabilityReservations,
  directPrivacyAuthorizedRuns,
  directPrivacyRunMaterials,
  directPrivacyPayrollAuthorizations,
  directPrivacyPreparations,
  directPrivacyReconciliations,
  payrollRuns,
  directPrivacySubmissions,
} from "./schema";

const PREPARABLE_RUN_STATES = new Set(["draft", "calculated", "proven", "failed"]);

function authorizedSiblings(value: unknown): `0x${string}`[] {
  if (
    !Array.isArray(value)
    || value.length !== 8
    || value.some((entry) => typeof entry !== "string" || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/.test(entry))
  ) throw new Error("DIRECT_AUTHORIZED_RUN_PATH_INVALID");
  return value as `0x${string}`[];
}

export function agentExecutionReceipt(
  execution: typeof agentExecutions.$inferSelect,
  replayed: boolean,
): AgentExecutionReceipt {
  return agentExecutionReceiptSchema.parse({
    executionId: execution.id,
    capabilityId: execution.capabilityId,
    runId: execution.runId,
    settlementId: execution.settlementId,
    state: execution.state,
    requiresApproval: execution.requiresApproval,
    requestCommitment: execution.requestCommitment,
    transactionHash: execution.transactionHash,
    errorCode: execution.errorCode,
    replayed,
    createdAt: execution.createdAt.toISOString(),
    updatedAt: execution.updatedAt.toISOString(),
  });
}

/**
 * Atomically reserves capability limits, binds one current payroll-run
 * revision and stores only an authenticated ciphertext of the intents.
 * The public response and audit trail contain commitments, never pay data.
 */
export async function requestAgentExecution(input: {
  capabilityId: string;
  idempotencyKey: string;
  request: AgentExecutionRequest;
  principal: AuthenticatedPrincipal;
  now?: Date;
}): Promise<AgentExecutionReceipt> {
  const request = agentExecutionRequestSchema.parse(input.request);
  const now = input.now ?? new Date();
  const organizationId = request.intents[0].organizationId;
  const requestCommitment = commitAgentExecutionRequest(request);
  const reservation = await reserveCapabilityPayment({
    capabilityId: input.capabilityId,
    idempotencyKey: input.idempotencyKey,
    intents: request.intents,
    principal: input.principal,
    now,
  });

  try {
    return await getDatabase().transaction(async (transaction) => {
      const [existing] = await transaction
        .select()
        .from(agentExecutions)
        .where(or(
          eq(agentExecutions.reservationId, reservation.id),
          and(
            eq(agentExecutions.capabilityId, input.capabilityId),
            eq(agentExecutions.requestCommitment, requestCommitment),
          ),
        ))
        .limit(1)
        .for("update");
      if (existing) {
        if (
          existing.reservationId !== reservation.id
          || existing.organizationId !== organizationId
          || existing.runId !== request.runId
        ) {
          throw new ApiError(409, "Execution commitment collides with another request.", "AGENT_EXECUTION_CONFLICT");
        }
        // Authentication also proves that this replay resolves to the exact
        // original canonical request rather than only the same public row.
        const canonical = decryptAgentExecutionRequest(existing.requestPayload, {
          executionId: existing.id,
          capabilityId: existing.capabilityId,
          organizationId: existing.organizationId,
          requestCommitment: existing.requestCommitment,
        });
        if (commitAgentExecutionRequest(canonical) !== requestCommitment) {
          throw new ApiError(409, "Stored execution request failed commitment verification.", "AGENT_EXECUTION_TAMPERED");
        }
        return agentExecutionReceipt(existing, true);
      }

      const [run] = await transaction
        .select()
        .from(payrollRuns)
        .where(eq(payrollRuns.id, request.runId))
        .limit(1)
        .for("update");
      if (!run || run.organizationId !== organizationId || reservation.organizationId !== organizationId) {
        throw new ApiError(404, "The authoritative payroll run was not found in this organization.", "RUN_NOT_FOUND");
      }
      if (!PREPARABLE_RUN_STATES.has(run.state)) {
        throw new ApiError(
          409,
          `Payroll run ${request.runId} cannot start agent execution from ${run.state}.`,
          "AGENT_RUN_NOT_PREPARABLE",
        );
      }

      const id = generateUuidV7(now.getTime());
      const requestPayload = encryptAgentExecutionRequest(request, {
        executionId: id,
        capabilityId: input.capabilityId,
        organizationId,
        requestCommitment,
      });
      const state = reservation.requiresApproval ? "approval_pending" : "reserved";
      const [created] = await transaction
        .insert(agentExecutions)
        .values({
          id,
          capabilityId: input.capabilityId,
          reservationId: reservation.id,
          organizationId,
          runId: request.runId,
          requestCommitment,
          requestPayload,
          state,
          requiresApproval: reservation.requiresApproval,
          runVersion: run.version,
          createdAt: now,
          availableAt: now,
          updatedAt: now,
        })
        .returning();
      if (!reservation.requiresApproval) {
        const [directAccount] = await transaction.select().from(directPrivacyAccounts).where(and(
          eq(directPrivacyAccounts.capabilityId, input.capabilityId),
          eq(directPrivacyAccounts.organizationId, organizationId),
        )).limit(1).for("update");
        if (!directAccount || directAccount.revokedAt || directAccount.activationState !== "active") {
          throw new ApiError(
            409,
            "Bounded autonomy requires an active reviewed policy account.",
            "DIRECT_ACCOUNT_INACTIVE",
          );
        }
        const [authorization] = await transaction.select().from(directPrivacyAuthorizedRuns).where(and(
          eq(directPrivacyAuthorizedRuns.accountId, directAccount.id),
          eq(directPrivacyAuthorizedRuns.runId, run.id),
          eq(directPrivacyAuthorizedRuns.runVersion, run.version),
        )).limit(1).for("update");
        if (!authorization?.encryptedWitness) {
          throw new ApiError(
            409,
            "The owner has not staged an encrypted witness for this authorized run.",
            "DIRECT_WITNESS_NOT_STAGED",
          );
        }
        const encryptedWitness = encryptedVaultRecordSchema.parse(authorization.encryptedWitness);
        const material = directPrivacyRunMaterialSchema.parse({
          version: "payo-direct-privacy-run-v1",
          organizationId,
          capabilityId: input.capabilityId,
          runId: run.id,
          runVersion: run.version,
          requestCommitment,
          authoritativeRequest: request,
          encryptedWitness,
          policyRun: {
            agreementRoot: authorization.agreementRoot,
            manifestRoot: authorization.manifestRoot,
            runNullifier: authorization.runNullifier,
            pathBits: authorization.pathBits,
            siblings: authorizedSiblings(authorization.siblings),
          },
        });
        const materialCommitment = commitDirectPrivacyRunMaterial(material);
        const materialId = generateUuidV7(now.getTime() + 1);
        const encryptedMaterial = encryptDirectPrivacyPayload(material, {
          accountId: directAccount.id,
          organizationId,
          capabilityId: input.capabilityId,
          purpose: "run",
          runId: run.id,
          runVersion: run.version,
          materialCommitment,
        });
        const [existingMaterial] = await transaction.select().from(directPrivacyRunMaterials).where(and(
          eq(directPrivacyRunMaterials.accountId, directAccount.id),
          eq(directPrivacyRunMaterials.runId, run.id),
          eq(directPrivacyRunMaterials.runVersion, run.version),
        )).limit(1).for("update");
        if (existingMaterial) {
          const [previousExecution] = await transaction.select().from(agentExecutions).where(and(
            eq(agentExecutions.capabilityId, input.capabilityId),
            eq(agentExecutions.runId, run.id),
            eq(agentExecutions.runVersion, run.version),
            eq(agentExecutions.requestCommitment, existingMaterial.requestCommitment),
          )).limit(1).for("update");
          const [previousReservation] = previousExecution
            ? await transaction.select().from(capabilityReservations).where(
                eq(capabilityReservations.id, previousExecution.reservationId),
              ).limit(1).for("update")
            : [];
          const downstreamRows = previousExecution
            ? await Promise.all([
                transaction.select({ executionId: directPrivacyPayrollAuthorizations.executionId })
                  .from(directPrivacyPayrollAuthorizations)
                  .where(eq(directPrivacyPayrollAuthorizations.executionId, previousExecution.id)).limit(1),
                transaction.select({ executionId: directPrivacyPreparations.executionId })
                  .from(directPrivacyPreparations)
                  .where(eq(directPrivacyPreparations.executionId, previousExecution.id)).limit(1),
                transaction.select({ executionId: directPrivacySubmissions.executionId })
                  .from(directPrivacySubmissions)
                  .where(eq(directPrivacySubmissions.executionId, previousExecution.id)).limit(1),
                transaction.select({ executionId: directPrivacyReconciliations.executionId })
                  .from(directPrivacyReconciliations)
                  .where(eq(directPrivacyReconciliations.executionId, previousExecution.id)).limit(1),
              ])
            : [];
          const safePreSigningRetry = previousExecution
            && ["failed", "released"].includes(previousExecution.state)
            && previousExecution.submissionCommitment === null
            && previousExecution.transactionHash === null
            && previousReservation
            && ["released", "expired"].includes(previousReservation.state)
            && downstreamRows.length === 4
            && downstreamRows.every((rows) => rows.length === 0);
          if (!safePreSigningRetry) {
            throw new ApiError(
              409,
              "This authorized run has an earlier execution that cannot be safely replaced.",
              "DIRECT_MATERIAL_RETRY_UNSAFE",
            );
          }
          await transaction.update(directPrivacyRunMaterials).set({
            requestCommitment,
            materialCommitment,
            encryptedMaterial,
            updatedAt: now,
          }).where(eq(directPrivacyRunMaterials.id, existingMaterial.id));
        }
        if (!existingMaterial) await transaction.insert(directPrivacyRunMaterials).values({
          id: materialId,
          accountId: directAccount.id,
          organizationId,
          capabilityId: input.capabilityId,
          runId: run.id,
          runVersion: run.version,
          requestCommitment,
          materialCommitment,
          encryptedMaterial,
          createdAt: now,
          updatedAt: now,
        });
        await transaction.insert(auditEvents).values({
          id: generateUuidV7(now.getTime() + 2),
          organizationId,
          actorId: input.principal.principalId,
          action: existingMaterial ? "direct_privacy_run.rebound" : "direct_privacy_run.bound",
          subjectId: existingMaterial?.id ?? materialId,
          metadata: {
            accountId: directAccount.id,
            capabilityId: input.capabilityId,
            runId: run.id,
            runVersion: run.version,
            requestCommitment,
            materialCommitment,
          },
        });
      }
      await transaction.insert(auditEvents).values({
        id: generateUuidV7(),
        organizationId,
        actorId: input.principal.principalId,
        action: reservation.requiresApproval
          ? "agent_execution.approval_requested"
          : "agent_execution.reserved",
        subjectId: id,
        metadata: {
          capabilityId: input.capabilityId,
          requestCommitment,
          runId: request.runId,
          runVersion: run.version,
          callCount: request.intents.length,
        },
      });
      return agentExecutionReceipt(created, false);
    });
  } catch (error) {
    // No signature or submission can exist before an execution row is created.
    // Return the unused reservation to the capability budget.
    try {
      await transitionCapabilityReservation({
        capabilityId: input.capabilityId,
        reservationId: reservation.id,
        state: "released",
        principal: input.principal,
        now,
      });
    } catch {
      // Preserve the original error. A concurrent replay may have created or
      // transitioned the execution after this request lost its race.
    }
    throw error;
  }
}

export async function getAgentExecution(input: {
  capabilityId: string;
  executionId: string;
  principal: AuthenticatedPrincipal;
}): Promise<AgentExecutionReceipt> {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [row] = await transaction
      .select({ execution: agentExecutions, capabilityPrincipalId: agentCapabilities.principalId })
      .from(agentExecutions)
      .innerJoin(agentCapabilities, eq(agentCapabilities.id, agentExecutions.capabilityId))
      .where(and(
        eq(agentExecutions.id, input.executionId),
        eq(agentExecutions.capabilityId, input.capabilityId),
      ))
      .limit(1);
    if (!row) throw new ApiError(404, "Agent execution not found.", "AGENT_EXECUTION_NOT_FOUND");
    await requireOrganizationRoleWith(
      transaction,
      row.execution.organizationId,
      input.principal,
      ["admin", "operator", "reviewer"],
    );
    if (row.capabilityPrincipalId !== input.principal.principalId) {
      throw new ApiError(403, "Only the capability principal can read this execution.", "CAPABILITY_PRINCIPAL_MISMATCH");
    }
    return agentExecutionReceipt(row.execution, false);
  });
}

/** Redacted operational history for human review; encrypted intents never leave storage. */
export async function listAgentExecutions(input: {
  organizationId: string;
  principal: AuthenticatedPrincipal;
  limit?: number;
}): Promise<AgentExecutionReceipt[]> {
  const limit = input.limit ?? 50;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new ApiError(400, "Agent execution list limit must be 1–100.", "LIMIT_INVALID");
  }
  return getDatabase().transaction(async (transaction) => {
    await requireOrganizationRoleWith(
      transaction,
      input.organizationId,
      input.principal,
      ["admin", "operator", "reviewer"],
    );
    const rows = await transaction.select().from(agentExecutions).where(
      eq(agentExecutions.organizationId, input.organizationId),
    ).orderBy(desc(agentExecutions.updatedAt)).limit(limit);
    return rows.map((row) => agentExecutionReceipt(row, false));
  });
}
