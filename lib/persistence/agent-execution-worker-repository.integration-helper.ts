import { eq, sql } from "drizzle-orm";
import { expect, it } from "vitest";
import { requestAgentExecution } from "./agent-execution-repository";
import {
  commitAgentExecutionForSubmission,
  completeAgentExecution,
  deferAgentExecution,
  leaseAgentExecutions,
  markAgentExecutionPreparing,
  recordAgentExecutionSubmission,
} from "./agent-execution-worker-repository";
import { stageDirectPrivacyRunWitness } from "./direct-privacy-repository";
import {
  fixture as directPrivacyFixture,
  now as start,
  principal,
} from "./direct-privacy-repository.integration-helper";
import { getDatabase } from "./db";
import {
  agentCapabilities,
  agentExecutions,
  auditEvents,
  capabilityReservations,
  payrollRuns,
} from "./schema";

async function fixture() {
  const input = await directPrivacyFixture();
  await stageDirectPrivacyRunWitness({
    accountId: input.account.id,
    encryptedWitness: input.material.encryptedWitness,
    principal,
    now: start,
  });
  const execution = await requestAgentExecution({
    capabilityId: input.capability.id,
    idempotencyKey: `agent-worker-repository:${input.runId}`,
    request: input.request,
    principal,
    now: start,
  });
  return {
    capability: input.capability,
    execution,
    request: input.request,
    runId: input.runId,
  };
}

export function registerAgentExecutionWorkerRepositoryIntegrationTests(): void {
  it("leases once, commits before signing, recovers after lease expiry, and confirms idempotently", async () => {
    const input = await fixture();
    const firstLeases = await Promise.all([
      leaseAgentExecutions("agent-worker-a", 1, start),
      leaseAgentExecutions("agent-worker-b", 1, start),
    ]);
    expect(firstLeases.flat()).toHaveLength(1);
    const first = firstLeases.flat()[0];
    expect(first.id).toBe(input.execution.executionId);
    await markAgentExecutionPreparing(first, new Date(start.getTime() + 1_000));
    await commitAgentExecutionForSubmission(
      first,
      `0x${"77".repeat(32)}`,
      new Date(start.getTime() + 2_000),
    );
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("committed");
    expect((await getDatabase().select().from(agentExecutions))[0].state).toBe("submitting");

    const restartAt = new Date(start.getTime() + 11 * 60_000);
    const restartedLeases = await Promise.all([
      leaseAgentExecutions("agent-worker-restart-a", 1, restartAt),
      leaseAgentExecutions("agent-worker-restart-b", 1, restartAt),
    ]);
    expect(restartedLeases.flat()).toHaveLength(1);
    const restarted = restartedLeases.flat()[0];
    expect(restarted).toMatchObject({ state: "submitting", submissionCommitment: `0x${"77".repeat(32)}` });
    await recordAgentExecutionSubmission(restarted, "0xabc123", restartAt);

    const confirmationAt = new Date(restartAt.getTime() + 3_000);
    const [confirmation] = await leaseAgentExecutions("agent-worker-confirm", 1, confirmationAt);
    expect(confirmation).toMatchObject({ state: "submitted", transactionHash: "0xabc123" });
    await completeAgentExecution(confirmation, confirmationAt);
    expect((await getDatabase().select().from(agentExecutions))[0]).toMatchObject({
      state: "confirmed",
      transactionHash: "0xabc123",
      leaseOwner: null,
    });
    const metadata = JSON.stringify((await getDatabase().select().from(auditEvents)).map(({ metadata }) => metadata));
    expect(metadata).not.toMatch(/recipientAddress|amountAtomic|0x456/);
  });

  it("fails closed and releases capacity when a run changes after reservation", async () => {
    const input = await fixture();
    await getDatabase().update(payrollRuns).set({
      version: sql`${payrollRuns.version} + 1`,
    }).where(eq(payrollRuns.id, input.runId));
    await expect(leaseAgentExecutions("agent-worker-toctou", 1, start)).resolves.toEqual([]);
    expect((await getDatabase().select().from(agentExecutions))[0]).toMatchObject({
      state: "failed",
      errorCode: "AGENT_RUN_VERSION_CHANGED",
    });
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("released");
  });

  it("releases pre-submission capacity on a permanent preparation failure", async () => {
    await fixture();
    const [job] = await leaseAgentExecutions("agent-worker-proof-failure", 1, start);
    await markAgentExecutionPreparing(job, start);
    await deferAgentExecution(job, {
      errorCode: "AGENT_PROOF_INVALID",
      permanent: true,
      preSubmission: true,
    }, start);
    expect((await getDatabase().select().from(agentExecutions))[0].state).toBe("failed");
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("released");
  });

  it("fails closed when a capability is revoked between reservation and proving", async () => {
    const input = await fixture();
    await getDatabase().update(agentCapabilities).set({ revokedAt: start })
      .where(eq(agentCapabilities.id, input.capability.id));
    await expect(leaseAgentExecutions("agent-worker-revoked", 1, start)).resolves.toEqual([]);
    expect((await getDatabase().select().from(agentExecutions))[0].errorCode).toBe("CAPABILITY_INACTIVE");
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("released");
  });
}
