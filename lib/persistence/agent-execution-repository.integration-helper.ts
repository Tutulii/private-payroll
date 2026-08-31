import { ed25519 } from "@noble/curves/ed25519.js";
import { expect, it } from "vitest";
import {
  hashCapability,
  signCapability,
  type AgentCapability,
  type AgentExecutionRequest,
} from "@/lib/domain/capability";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { encryptCapabilityPolicy } from "@/lib/server/capability-policy-crypto";
import { listAgentExecutions, requestAgentExecution } from "./agent-execution-repository";
import { getDatabase } from "./db";
import {
  agentCapabilities,
  agentExecutions,
  auditEvents,
  capabilityReservations,
  organizationMembers,
  organizations,
  payrollRuns,
} from "./schema";

const principal: AuthenticatedPrincipal = {
  principalId: "agent:execution-integration",
  sessionId: "session:execution-integration",
};
const now = new Date("2026-08-30T10:00:00.000Z");

async function seed(input: { executionMode?: AgentCapability["executionMode"]; withRun?: boolean } = {}) {
  const database = getDatabase();
  const organizationId = generateUuidV7();
  const runId = generateUuidV7();
  await database.insert(organizations).values({
    id: organizationId,
    encryptedProfile: { ciphertext: "agent-execution-test" },
    recoveryState: "package_downloaded",
  });
  await database.insert(organizationMembers).values({
    organizationId,
    principalId: principal.principalId,
    role: "operator",
    vaultPublicKey: "agent-execution-test-public-key",
  });
  if (input.withRun !== false) {
    await database.insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: `agent-cycle:${runId}`,
      revision: 1,
      state: "draft",
      dueAt: now,
    });
  }
  const capability: AgentCapability = {
    capabilityVersion: "payo-agent-capability-v1",
    id: generateUuidV7(),
    organizationId,
    principalId: principal.principalId,
    allowedActions: ["request_execution"],
    allowedTokens: ["STRK"],
    recipientScope: { mode: "allowlist", addresses: ["0x123"] },
    purposeCodes: ["private_payroll"],
    limits: [{
      token: "STRK",
      maxPerPaymentAtomic: "1000",
      maxPerPeriodAtomic: "5000",
      spentThisPeriodAtomic: "0",
      periodStartsAt: "2026-08-30T00:00:00.000Z",
      periodEndsAt: "2026-08-31T00:00:00.000Z",
      approvalThresholdAtomic: "800",
    }],
    executionMode: input.executionMode ?? "autonomous_bounded",
    maxCallCount: 5,
    usedCallCount: 0,
    validAfter: "2026-08-30T00:00:00.000Z",
    expiresAt: "2026-08-31T00:00:00.000Z",
    nonce: "agent-execution-capability-nonce-0001",
  };
  const capabilityHash = hashCapability(capability);
  const signed = signCapability(capability, ed25519.keygen().secretKey);
  await database.insert(agentCapabilities).values({
    id: capability.id,
    organizationId,
    principalId: principal.principalId,
    capabilityHash,
    policy: encryptCapabilityPolicy(signed, {
      capabilityId: capability.id,
      organizationId,
      principalId: principal.principalId,
      capabilityHash,
    }),
    expiresAt: new Date(capability.expiresAt),
  });
  return { organizationId, runId, capability };
}

function request(input: Awaited<ReturnType<typeof seed>>, suffix = "0001"): AgentExecutionRequest {
  return {
    requestVersion: "payo-agent-execution-v1",
    runId: input.runId,
    intents: [{
      intentVersion: "payo-payment-intent-v1",
      intentId: `agent-payment-intent-${suffix}`,
      organizationId: input.organizationId,
      runId: input.runId,
      action: "request_execution",
      token: "STRK",
      recipientAddress: "0x123",
      amountAtomic: "500",
      purposeCode: "private_payroll",
      capabilityNonce: input.capability.nonce,
      createdAt: now.toISOString(),
      validUntil: "2026-08-30T10:05:00.000Z",
    }],
  };
}

export function registerAgentExecutionRepositoryIntegrationTests(): void {
  it("stores an idempotent approval request encrypted and returns only a redacted receipt", async () => {
    const fixture = await seed({ executionMode: "request_approval" });
    const executionRequest = request(fixture);
    const first = await requestAgentExecution({
      capabilityId: fixture.capability.id,
      idempotencyKey: "agent-execution-idempotency-0001",
      request: executionRequest,
      principal,
      now,
    });
    const replay = await requestAgentExecution({
      capabilityId: fixture.capability.id,
      idempotencyKey: "agent-execution-idempotency-0001",
      request: executionRequest,
      principal,
      now,
    });
    expect(first).toMatchObject({ state: "approval_pending", requiresApproval: true, replayed: false });
    expect(replay).toMatchObject({ executionId: first.executionId, replayed: true });
    expect(JSON.stringify(first)).not.toMatch(/recipient|amountAtomic|0x123/);

    const [stored] = await getDatabase().select().from(agentExecutions);
    expect(JSON.stringify(stored.requestPayload)).not.toMatch(/recipientAddress|amountAtomic|0x123/);
    expect((await getDatabase().select().from(capabilityReservations))).toHaveLength(1);
    const history = await listAgentExecutions({
      organizationId: fixture.organizationId,
      principal,
    });
    expect(history).toEqual([expect.objectContaining({
      executionId: first.executionId,
      state: "approval_pending",
      requiresApproval: true,
    })]);
    expect(JSON.stringify(history)).not.toMatch(/recipient|amountAtomic|0x123/);
    const executionAudits = (await getDatabase().select().from(auditEvents))
      .filter(({ action }) => action.startsWith("agent_execution."));
    expect(executionAudits).toHaveLength(1);
    expect(JSON.stringify(executionAudits[0].metadata)).not.toMatch(/recipient|amountAtomic|tokenTotals|0x123/);
  });

  it("routes non-autonomous capabilities to human approval by default", async () => {
    const fixture = await seed({ executionMode: "request_approval" });
    await expect(requestAgentExecution({
      capabilityId: fixture.capability.id,
      idempotencyKey: "agent-execution-approval-0001",
      request: request(fixture),
      principal,
      now,
    })).resolves.toMatchObject({ state: "approval_pending", requiresApproval: true });
  });

  it("fails closed and releases capacity when autonomy has no active reviewed policy account", async () => {
    const fixture = await seed();
    await expect(requestAgentExecution({
      capabilityId: fixture.capability.id,
      idempotencyKey: "agent-execution-no-policy-account-0001",
      request: request(fixture),
      principal,
      now,
    })).rejects.toMatchObject({ code: "DIRECT_ACCOUNT_INACTIVE" });
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("released");
    expect(await getDatabase().select().from(agentExecutions)).toHaveLength(0);
  });

  it("releases an unused reservation when authoritative run loading fails", async () => {
    const fixture = await seed({ withRun: false });
    await expect(requestAgentExecution({
      capabilityId: fixture.capability.id,
      idempotencyKey: "agent-execution-release-0001",
      request: request(fixture),
      principal,
      now,
    })).rejects.toMatchObject({ code: "RUN_NOT_FOUND" });
    const [reservation] = await getDatabase().select().from(capabilityReservations);
    expect(reservation.state).toBe("released");
    expect(await getDatabase().select().from(agentExecutions)).toHaveLength(0);
  });

  it("rejects cross-tenant substitution before reserving limits", async () => {
    const fixture = await seed();
    const otherOrganizationId = generateUuidV7();
    await getDatabase().insert(organizations).values({
      id: otherOrganizationId,
      encryptedProfile: { ciphertext: "other-tenant" },
      recoveryState: "package_downloaded",
    });
    const substituted = request(fixture);
    substituted.intents[0].organizationId = otherOrganizationId;
    await expect(requestAgentExecution({
      capabilityId: fixture.capability.id,
      idempotencyKey: "agent-execution-tenant-0001",
      request: substituted,
      principal,
      now,
    })).rejects.toMatchObject({ code: "CAPABILITY_MISMATCH" });
    expect(await getDatabase().select().from(capabilityReservations)).toHaveLength(0);
    expect(await getDatabase().select().from(agentExecutions)).toHaveLength(0);
    await expect(listAgentExecutions({
      organizationId: fixture.organizationId,
      principal: { principalId: "agent:outsider", sessionId: "session:outsider" },
    })).rejects.toMatchObject({ code: "ORG_FORBIDDEN" });
  });

  it("rejects idempotency-key reuse with a mutated request", async () => {
    const fixture = await seed({ executionMode: "request_approval" });
    const original = request(fixture);
    await requestAgentExecution({
      capabilityId: fixture.capability.id,
      idempotencyKey: "agent-execution-mutation-0001",
      request: original,
      principal,
      now,
    });
    const mutated = request(fixture, "0002");
    await expect(requestAgentExecution({
      capabilityId: fixture.capability.id,
      idempotencyKey: "agent-execution-mutation-0001",
      request: mutated,
      principal,
      now,
    })).rejects.toMatchObject({ code: "IDEMPOTENCY_MISMATCH" });
    expect(await getDatabase().select().from(agentExecutions)).toHaveLength(1);
    expect((await getDatabase().select().from(capabilityReservations))).toHaveLength(1);
  });
}
