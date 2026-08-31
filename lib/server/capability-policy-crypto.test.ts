import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { signCapability, type AgentCapability } from "@/lib/domain/capability";
import {
  decryptCapabilityPolicy,
  encryptCapabilityPolicy,
  type CapabilityPolicyContext,
} from "./capability-policy-crypto";

const rawKey = `0x${"42".repeat(32)}`;
const capability: AgentCapability = {
  capabilityVersion: "payo-agent-capability-v1",
  id: "capability-crypto-001",
  organizationId: "organization-crypto-001",
  principalId: "agent:crypto",
  allowedActions: ["request_execution"],
  allowedTokens: ["STRK"],
  recipientScope: { mode: "allowlist", addresses: ["0x123"] },
  purposeCodes: ["private_payroll"],
  limits: [{
    token: "STRK",
    maxPerPaymentAtomic: "100",
    maxPerPeriodAtomic: "1000",
    spentThisPeriodAtomic: "0",
    periodStartsAt: "2026-08-01T00:00:00.000Z",
    periodEndsAt: "2026-09-01T00:00:00.000Z",
    approvalThresholdAtomic: "100",
  }],
  executionMode: "request_approval",
  maxCallCount: 10,
  usedCallCount: 0,
  validAfter: "2026-08-01T00:00:00.000Z",
  expiresAt: "2026-09-01T00:00:00.000Z",
  nonce: "capability-crypto-nonce-001",
};
const signed = signCapability(capability, ed25519.keygen().secretKey);
const context: CapabilityPolicyContext = {
  capabilityId: capability.id,
  organizationId: capability.organizationId,
  principalId: capability.principalId,
  capabilityHash: "0x1234",
};

describe("authoritative capability policy encryption", () => {
  it("round-trips an authenticated signed policy without storing plaintext", () => {
    const encrypted = encryptCapabilityPolicy(signed, context, rawKey);
    expect(JSON.stringify(encrypted)).not.toContain(capability.principalId);
    expect(decryptCapabilityPolicy(encrypted, context, rawKey)).toEqual(signed);
  });

  it("rejects wrong keys and record substitution", () => {
    const encrypted = encryptCapabilityPolicy(signed, context, rawKey);
    expect(() => decryptCapabilityPolicy(encrypted, context, `0x${"24".repeat(32)}`)).toThrow("key");
    expect(() => decryptCapabilityPolicy(encrypted, { ...context, capabilityId: "capability-other" }, rawKey))
      .toThrow("authenticated");
  });

  it("fails closed when no production key is configured", () => {
    const previous = process.env.PAYO_CAPABILITY_ENCRYPTION_KEY;
    delete process.env.PAYO_CAPABILITY_ENCRYPTION_KEY;
    try {
      expect(() => encryptCapabilityPolicy(signed, context)).toThrow("PAYO_CAPABILITY_ENCRYPTION_KEY");
    } finally {
      if (previous) process.env.PAYO_CAPABILITY_ENCRYPTION_KEY = previous;
    }
  });
});
