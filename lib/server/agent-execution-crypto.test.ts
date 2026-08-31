import { describe, expect, it } from "vitest";
import type { AgentExecutionRequest } from "@/lib/domain/capability";
import {
  decryptAgentExecutionRequest,
  encryptAgentExecutionRequest,
  type AgentExecutionCryptoContext,
} from "./agent-execution-crypto";

const key = `0x${"55".repeat(32)}`;
const request: AgentExecutionRequest = {
  requestVersion: "payo-agent-execution-v1",
  runId: "payroll-run-crypto-001",
  intents: [{
    intentVersion: "payo-payment-intent-v1",
    intentId: "payment-intent-crypto-001",
    organizationId: "organization-crypto-001",
    runId: "payroll-run-crypto-001",
    action: "request_execution",
    token: "STRK",
    recipientAddress: "0x123",
    amountAtomic: "10",
    purposeCode: "private_payroll",
    capabilityNonce: "agent-execution-nonce-001",
    createdAt: "2026-08-30T10:00:00.000Z",
    validUntil: "2026-08-30T10:05:00.000Z",
  }],
};
const context: AgentExecutionCryptoContext = {
  executionId: "agent-execution-crypto-001",
  capabilityId: "capability-crypto-001",
  organizationId: "organization-crypto-001",
  requestCommitment: `0x${"11".repeat(32)}`,
};

describe("agent execution encryption", () => {
  it("round-trips without exposing payment plaintext", () => {
    const encrypted = encryptAgentExecutionRequest(request, context, key);
    const serialized = JSON.stringify(encrypted);
    expect(serialized).not.toContain(
      `"recipientAddress":"${request.intents[0].recipientAddress}"`,
    );
    expect(serialized).not.toContain(
      `"amountAtomic":"${request.intents[0].amountAtomic}"`,
    );
    expect(decryptAgentExecutionRequest(encrypted, context, key)).toEqual(request);
  });

  it("rejects record substitution and the wrong key", () => {
    const encrypted = encryptAgentExecutionRequest(request, context, key);
    expect(() => decryptAgentExecutionRequest(encrypted, { ...context, executionId: "other-execution" }, key))
      .toThrow(/authenticated/);
    expect(() => decryptAgentExecutionRequest(encrypted, context, `0x${"44".repeat(32)}`))
      .toThrow(/key/);
  });
});
