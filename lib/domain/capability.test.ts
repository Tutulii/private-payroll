import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import {
  agentExecutionRequestSchema,
  authorizePaymentIntent,
  authorizePaymentBatch,
  paymentIntentSchema,
  signCapability,
  verifySignedCapability,
  type AgentCapability,
  type PaymentIntent,
} from "./capability";

const now = new Date("2026-08-23T10:00:00.000Z");

const capability: AgentCapability = {
  capabilityVersion: "payo-agent-capability-v1",
  id: "capability-001",
  organizationId: "organization-001",
  principalId: "agent:treasury",
  allowedActions: ["draft_run", "request_execution"],
  allowedTokens: ["STRK"],
  recipientScope: { mode: "allowlist", addresses: ["0x123"] },
  purposeCodes: ["monthly-payroll"],
  limits: [{
    token: "STRK",
    maxPerPaymentAtomic: "1000",
    maxPerPeriodAtomic: "5000",
    spentThisPeriodAtomic: "2000",
    periodStartsAt: "2026-08-01T00:00:00.000Z",
    periodEndsAt: "2026-09-01T00:00:00.000Z",
    approvalThresholdAtomic: "800",
  }],
  executionMode: "autonomous_bounded",
  maxCallCount: 10,
  usedCallCount: 0,
  validAfter: "2026-08-01T00:00:00.000Z",
  expiresAt: "2026-09-01T00:00:00.000Z",
  nonce: "nonce-0000000001",
};

const intent: PaymentIntent = {
  intentVersion: "payo-payment-intent-v1",
  intentId: "intent-001",
  organizationId: "organization-001",
  runId: "payroll-run-001",
  action: "request_execution",
  token: "STRK",
  recipientAddress: "0x123",
  amountAtomic: "500",
  purposeCode: "monthly-payroll",
  capabilityNonce: "nonce-0000000001",
  createdAt: now.toISOString(),
  validUntil: "2026-08-23T10:05:00.000Z",
};

describe("agent capabilities", () => {
  it("signs and verifies an immutable capability", () => {
    const key = ed25519.keygen();
    const signed = signCapability(capability, key.secretKey);
    expect(verifySignedCapability(signed).capability.id).toBe(capability.id);
    expect(() => verifySignedCapability({
      ...signed,
      capability: { ...signed.capability, maxCallCount: signed.capability.maxCallCount + 1 },
    })).toThrow("signature");
  });

  it("allows an in-policy payment without approval", () => {
    expect(authorizePaymentIntent(capability, intent, now)).toMatchObject({
      allowed: true,
      requiresApproval: false,
      reasonCode: "ALLOWED",
    });
  });

  it.each([
    [{ ...intent, token: "USDC" }, "TOKEN_DENIED"],
    [{ ...intent, recipientAddress: "0x456" }, "RECIPIENT_DENIED"],
    [{ ...intent, purposeCode: "trading" }, "PURPOSE_DENIED"],
    [{ ...intent, amountAtomic: "1001" }, "PAYMENT_LIMIT_EXCEEDED"],
    [{ ...intent, amountAtomic: "3500" }, "PAYMENT_LIMIT_EXCEEDED"],
    [{ ...intent, capabilityNonce: "nonce-9999999999" }, "CAPABILITY_MISMATCH"],
  ] as const)("denies an out-of-policy intent", (candidate, reason) => {
    expect(authorizePaymentIntent(capability, candidate, now)).toMatchObject({
      allowed: false,
      reasonCode: reason,
    });
  });

  it("enforces the cumulative period limit", () => {
    const constrained = {
      ...capability,
      limits: [{ ...capability.limits[0], maxPerPaymentAtomic: "5000" }],
    };
    expect(authorizePaymentIntent(constrained, { ...intent, amountAtomic: "3001" }, now).reasonCode)
      .toBe("PERIOD_LIMIT_EXCEEDED");
  });

  it("enforces a period limit across an entire batch", () => {
    const batchCapability = {
      ...capability,
      limits: [{ ...capability.limits[0], maxPerPaymentAtomic: "5000" }],
    };
    const result = authorizePaymentBatch(
      batchCapability,
      [intent, { ...intent, intentId: "intent-002", amountAtomic: "2600" }],
      now,
    );
    expect(result.allowed).toBe(false);
    expect(result.decisions[1].reasonCode).toBe("PERIOD_LIMIT_EXCEEDED");
  });

  it("routes threshold payments to human approval", () => {
    expect(authorizePaymentIntent(capability, { ...intent, amountAtomic: "800" }, now))
      .toMatchObject({ allowed: true, requiresApproval: true, reasonCode: "APPROVAL_REQUIRED" });
  });

  it("rejects future and expired payment intents", () => {
    expect(authorizePaymentIntent(capability, { ...intent, createdAt: "2026-08-23T10:01:00.000Z" }, now).reasonCode)
      .toBe("INTENT_NOT_YET_VALID");
    expect(authorizePaymentIntent(capability, {
      ...intent,
      createdAt: "2026-08-23T09:59:00.000Z",
      validUntil: now.toISOString(),
    }, now).reasonCode)
      .toBe("INTENT_EXPIRED");
  });

  it("enforces the signed call count across a batch", () => {
    const result = authorizePaymentBatch(
      { ...capability, maxCallCount: 1 },
      [intent, { ...intent, intentId: "intent-002" }],
      now,
    );
    expect(result.allowed).toBe(false);
    expect(result.decisions[1].reasonCode).toBe("CALL_LIMIT_EXCEEDED");
  });

  it("rejects payment-intent validity windows longer than five minutes", () => {
    expect(() => paymentIntentSchema.parse({
      ...intent,
      validUntil: "2026-08-23T10:05:01.000Z",
    })).toThrow("five minutes");
  });

  it("rejects arbitrary calldata and contract targets at the schema boundary", () => {
    expect(() => paymentIntentSchema.parse({ ...intent, contractAddress: "0xdead", calldata: ["0x1"] }))
      .toThrow();
  });

  it("binds every versioned intent to one run and organization", () => {
    expect(agentExecutionRequestSchema.parse({
      requestVersion: "payo-agent-execution-v1",
      runId: intent.runId,
      intents: [intent],
    }).runId).toBe(intent.runId);
    expect(() => agentExecutionRequestSchema.parse({
      requestVersion: "payo-agent-execution-v1",
      runId: "another-run-001",
      intents: [intent],
    })).toThrow(/bind the execution run/);
  });
});
