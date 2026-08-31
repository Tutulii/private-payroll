import { ed25519 } from "@noble/curves/ed25519.js";
import { eq } from "drizzle-orm";
import { expect, it } from "vitest";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  hashCapability,
  signCapability,
  type AgentCapability,
  type AgentExecutionRequest,
} from "@/lib/domain/capability";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  commitAgentSettlementPlan,
  commitTokenTotals,
  type AgentSettlementPayment,
  type TokenTotals,
} from "@/lib/domain/settlement";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { encryptCapabilityPolicy } from "@/lib/server/capability-policy-crypto";
import {
  cancelUnlinkedAgentExecutionApproval,
  linkAgentExecutionToHumanSettlement,
  listHumanApprovalExecutions,
} from "./agent-execution-approval-repository";
import { requestAgentExecution } from "./agent-execution-repository";
import { getDatabase } from "./db";
import {
  agentCapabilities,
  agentExecutions,
  auditEvents,
  capabilityReservations,
  organizationMembers,
  organizations,
  payrollRuns,
  proofBundles,
} from "./schema";
import {
  applySettlementObservation,
  cancelSettlementApproval,
  createSettlementIntent,
  leaseConfirmationJobs,
  recordSettlementSubmission,
} from "./settlement-repository";

const human: AuthenticatedPrincipal = {
  principalId: "human:agent-approval-integration",
  sessionId: "session:human-agent-approval",
};
const agent: AuthenticatedPrincipal = {
  principalId: "agent:approval-integration",
  sessionId: "session:agent-approval",
};

async function fixture(input: {
  settlementTotals?: TokenTotals;
  settlementPayments?: AgentSettlementPayment[];
  createSettlement?: boolean;
} = {}) {
  const now = new Date();
  const organizationId = generateUuidV7();
  const runId = generateUuidV7();
  const capabilityId = generateUuidV7();
  const database = getDatabase();
  await database.insert(organizations).values({
    id: organizationId,
    encryptedProfile: { ciphertext: "agent-approval-integration" },
    recoveryState: "package_downloaded",
  });
  await database.insert(organizationMembers).values([
    {
      organizationId,
      principalId: human.principalId,
      role: "admin",
      vaultPublicKey: "human-agent-approval-public-key",
    },
    {
      organizationId,
      principalId: agent.principalId,
      role: "operator",
      vaultPublicKey: "agent-approval-public-key",
    },
  ]);
  await database.insert(payrollRuns).values({
    id: runId,
    organizationId,
    cycleId: `agent-approval:${runId}`,
    revision: 1,
    state: "proven",
    dueAt: now,
  });
  await database.insert(proofBundles).values({
    id: generateUuidV7(),
    runId,
    organizationId,
    proofType: "payroll_integrity",
    proofVersion: "2",
    subjectRecordId: runId,
    proofPackage: { version: "payo-payroll-proof-test-v2" },
    proofHash: `0x${"51".repeat(32)}`,
    verificationState: "locally_verified",
  });

  const periodStartsAt = new Date(now.getTime() - 60_000).toISOString();
  const periodEndsAt = new Date(now.getTime() + 24 * 60 * 60_000).toISOString();
  const capability: AgentCapability = {
    capabilityVersion: "payo-agent-capability-v1",
    id: capabilityId,
    organizationId,
    principalId: agent.principalId,
    allowedActions: ["request_execution"],
    allowedTokens: ["STRK", "USDC"],
    recipientScope: { mode: "allowlist", addresses: ["0x123", "0x456"] },
    purposeCodes: ["private_payroll"],
    limits: [
      {
        token: "STRK",
        maxPerPaymentAtomic: "1000",
        maxPerPeriodAtomic: "1000",
        spentThisPeriodAtomic: "0",
        periodStartsAt,
        periodEndsAt,
        approvalThresholdAtomic: "1000",
      },
      {
        token: "USDC",
        maxPerPaymentAtomic: "1000",
        maxPerPeriodAtomic: "1000",
        spentThisPeriodAtomic: "0",
        periodStartsAt,
        periodEndsAt,
        approvalThresholdAtomic: "1000",
      },
    ],
    executionMode: "request_approval",
    maxCallCount: 10,
    usedCallCount: 0,
    validAfter: periodStartsAt,
    expiresAt: periodEndsAt,
    nonce: "agent-human-approval-capability-nonce-0001",
  };
  const capabilityHash = hashCapability(capability);
  await database.insert(agentCapabilities).values({
    id: capabilityId,
    organizationId,
    principalId: agent.principalId,
    capabilityHash,
    policy: encryptCapabilityPolicy(signCapability(capability, ed25519.keygen().secretKey), {
      capabilityId,
      organizationId,
      principalId: agent.principalId,
      capabilityHash,
    }),
    expiresAt: new Date(periodEndsAt),
  });
  const request: AgentExecutionRequest = {
    requestVersion: "payo-agent-execution-v1",
    runId,
    intents: [
      {
        intentVersion: "payo-payment-intent-v1",
        intentId: `agent-approval-strk:${runId}`,
        organizationId,
        runId,
        action: "request_execution",
        token: "STRK",
        recipientAddress: "0x123",
        amountAtomic: "100",
        purposeCode: "private_payroll",
        capabilityNonce: capability.nonce,
        createdAt: now.toISOString(),
        validUntil: new Date(now.getTime() + 5 * 60_000).toISOString(),
      },
      {
        intentVersion: "payo-payment-intent-v1",
        intentId: `agent-approval-usdc:${runId}`,
        organizationId,
        runId,
        action: "request_execution",
        token: "USDC",
        recipientAddress: "0x456",
        amountAtomic: "25",
        purposeCode: "private_payroll",
        capabilityNonce: capability.nonce,
        createdAt: now.toISOString(),
        validUntil: new Date(now.getTime() + 5 * 60_000).toISOString(),
      },
    ],
  };
  const execution = await requestAgentExecution({
    capabilityId,
    idempotencyKey: `agent-human-approval:${runId}`,
    request,
    principal: agent,
    now,
  });

  let settlement: Awaited<ReturnType<typeof createSettlementIntent>> | undefined;
  if (input.createSettlement !== false) {
    const totals = input.settlementTotals ?? { STRK: "100", USDC: "25" };
    const payments = input.settlementPayments ?? request.intents.map((intent) => ({
      recipientAddress: intent.recipientAddress,
      token: intent.token,
      amountAtomic: intent.amountAtomic,
      purposeCode: intent.purposeCode,
    }));
    const settlementId = generateUuidV7();
    const tokenTotalsCommitment = commitTokenTotals({ organizationId, runId, totals });
    const agentPlanCommitment = commitAgentSettlementPlan({ organizationId, runId, payments });
    const vaultPrincipal = generateVaultPrincipal(human.principalId);
    settlement = await createSettlementIntent({
      id: settlementId,
      organizationId,
      runId,
      workflowType: "payroll",
      subjectRecordId: runId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: `human-ready-settlement:${settlementId}`,
      tokenTotalsCommitment,
      agentPlanCommitment,
      envelope: encryptVaultRecord(
        { tokenTotals: totals, tokenTotalsCommitment, agentPlanCommitment },
        {
          schemaVersion: 1,
          organizationId,
          recordType: "settlement",
          recordId: settlementId,
          revision: 1,
        },
        [vaultPrincipal],
      ),
      principal: human,
    });
  }
  return { now, organizationId, runId, capability, request, execution, settlement };
}

export function registerAgentExecutionApprovalRepositoryIntegrationTests(): void {
  it("binds an exact Ready settlement and follows shared submission finality atomically", async () => {
    const input = await fixture();
    const settlementId = input.settlement!.id;
    const linked = await linkAgentExecutionToHumanSettlement({
      capabilityId: input.capability.id,
      executionId: input.execution.executionId,
      settlementId,
      principal: human,
      now: input.now,
    });
    expect(linked).toMatchObject({
      state: "approval_pending",
      settlementId,
      requiresApproval: true,
      replayed: false,
    });
    await expect(linkAgentExecutionToHumanSettlement({
      capabilityId: input.capability.id,
      executionId: input.execution.executionId,
      settlementId,
      principal: human,
      now: input.now,
    })).resolves.toMatchObject({ replayed: true });
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("approval_linked");

    await recordSettlementSubmission({ settlementId, transactionHash: "0xa11ce", principal: human });
    expect((await getDatabase().select().from(agentExecutions))[0]).toMatchObject({
      state: "submitted",
      settlementId,
      transactionHash: "0xa11ce",
    });
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("committed");

    const firstAt = new Date(Date.now() + 1_000);
    const [confirmedJob] = await leaseConfirmationJobs("agent-human-approval-confirm", 1, firstAt);
    await applySettlementObservation(confirmedJob, {
      state: "confirmed",
      confirmationDepth: 1,
      blockNumber: 123n,
      blockHash: "0xabc",
    }, firstAt);
    expect((await getDatabase().select().from(agentExecutions))[0].state).toBe("submitted");

    const finalAt = new Date(firstAt.getTime() + 10_000);
    const [finalJob] = await leaseConfirmationJobs("agent-human-approval-final", 1, finalAt);
    await applySettlementObservation(finalJob, {
      state: "finalized",
      confirmationDepth: 3,
      blockNumber: 123n,
      blockHash: "0xabc",
    }, finalAt);
    expect((await getDatabase().select().from(agentExecutions))[0].state).toBe("confirmed");
    await expect(listHumanApprovalExecutions({
      organizationId: input.organizationId,
      principal: human,
    })).resolves.toEqual([expect.objectContaining({ state: "confirmed", settlementId })]);
    const auditJson = JSON.stringify(await getDatabase().select().from(auditEvents));
    expect(auditJson).not.toMatch(/recipientAddress|amountAtomic|0x123|0x456/);
  });

  it("rejects totals substitution without consuming or linking the reservation", async () => {
    const input = await fixture({ settlementTotals: { STRK: "99", USDC: "25" } });
    await expect(linkAgentExecutionToHumanSettlement({
      capabilityId: input.capability.id,
      executionId: input.execution.executionId,
      settlementId: input.settlement!.id,
      principal: human,
      now: input.now,
    })).rejects.toMatchObject({ code: "AGENT_SETTLEMENT_TOTALS_MISMATCH" });
    expect((await getDatabase().select().from(agentExecutions))[0]).toMatchObject({ settlementId: null });
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("reserved");
  });

  it("rejects same-total recipient substitution before Ready can be linked", async () => {
    const input = await fixture({
      settlementPayments: [
        { recipientAddress: "0x999", token: "STRK", amountAtomic: "100", purposeCode: "private_payroll" },
        { recipientAddress: "0x456", token: "USDC", amountAtomic: "25", purposeCode: "private_payroll" },
      ],
    });
    await expect(linkAgentExecutionToHumanSettlement({
      capabilityId: input.capability.id,
      executionId: input.execution.executionId,
      settlementId: input.settlement!.id,
      principal: human,
      now: input.now,
    })).rejects.toMatchObject({ code: "AGENT_SETTLEMENT_PLAN_MISMATCH" });
    expect((await getDatabase().select().from(agentExecutions))[0]).toMatchObject({ settlementId: null });
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("reserved");
  });

  it("releases a linked approval only through atomic Ready cancellation", async () => {
    const input = await fixture();
    await linkAgentExecutionToHumanSettlement({
      capabilityId: input.capability.id,
      executionId: input.execution.executionId,
      settlementId: input.settlement!.id,
      principal: human,
      now: input.now,
    });
    await expect(cancelUnlinkedAgentExecutionApproval({
      capabilityId: input.capability.id,
      executionId: input.execution.executionId,
      principal: human,
    })).rejects.toMatchObject({ code: "AGENT_APPROVAL_SETTLEMENT_LINKED" });
    await cancelSettlementApproval({ settlementId: input.settlement!.id, principal: human });
    expect((await getDatabase().select().from(agentExecutions))[0].state).toBe("released");
    expect((await getDatabase().select().from(capabilityReservations))[0].state).toBe("released");
  });

  it("lets an administrator release an unlinked request and blocks revoked linking", async () => {
    const unlinked = await fixture({ createSettlement: false });
    await expect(cancelUnlinkedAgentExecutionApproval({
      capabilityId: unlinked.capability.id,
      executionId: unlinked.execution.executionId,
      principal: human,
    })).resolves.toMatchObject({ state: "released", replayed: false });

    // beforeEach isolation applies per test, so use a second fixture only after
    // the first records remain valid and address it by exact IDs.
    const revoked = await fixture();
    await getDatabase().update(agentCapabilities).set({ revokedAt: revoked.now })
      .where(eq(agentCapabilities.id, revoked.capability.id));
    await expect(linkAgentExecutionToHumanSettlement({
      capabilityId: revoked.capability.id,
      executionId: revoked.execution.executionId,
      settlementId: revoked.settlement!.id,
      principal: human,
      now: revoked.now,
    })).rejects.toMatchObject({ code: "CAPABILITY_INACTIVE" });
  });
}
