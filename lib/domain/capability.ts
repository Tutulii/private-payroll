import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import { fromBase64, stableJson, toBase64, toHex, utf8 } from "@/lib/crypto/encoding";
import { atomicAmountSchema, payrollTokenSchema } from "./payroll";

export const agentActionSchema = z.enum([
  "list_due_obligations",
  "draft_run",
  "validate_run",
  "request_execution",
  "get_run_status",
  "get_receipt",
  "create_disclosure",
]);
export type AgentAction = z.infer<typeof agentActionSchema>;

const starknetAddressSchema = z.string().regex(/^0x[0-9a-fA-F]+$/);

export const capabilityLimitSchema = z
  .object({
    token: payrollTokenSchema,
    maxPerPaymentAtomic: atomicAmountSchema,
    maxPerPeriodAtomic: atomicAmountSchema,
    spentThisPeriodAtomic: atomicAmountSchema,
    periodStartsAt: z.string().datetime(),
    periodEndsAt: z.string().datetime(),
    approvalThresholdAtomic: atomicAmountSchema,
  })
  .strict();

export const agentCapabilitySchema = z
  .object({
    capabilityVersion: z.literal("payo-agent-capability-v1"),
    id: z.string().min(8).max(128),
    organizationId: z.string().min(8).max(128),
    principalId: z.string().min(1).max(256),
    allowedActions: z.array(agentActionSchema).min(1),
    allowedTokens: z.array(payrollTokenSchema).min(1),
    recipientScope: z.discriminatedUnion("mode", [
      z.object({ mode: z.literal("any") }).strict(),
      z.object({ mode: z.literal("allowlist"), addresses: z.array(starknetAddressSchema).min(1) }).strict(),
    ]),
    purposeCodes: z.array(z.string().min(1).max(80)).min(1),
    limits: z.array(capabilityLimitSchema).min(1),
    executionMode: z.enum(["draft_only", "request_approval", "autonomous_bounded"]),
    validAfter: z.string().datetime(),
    expiresAt: z.string().datetime(),
    nonce: z.string().min(16).max(256),
  })
  .strict()
  .superRefine((capability, context) => {
    const uniqueActions = new Set(capability.allowedActions);
    const uniqueTokens = new Set(capability.allowedTokens);
    const uniqueLimits = new Set(capability.limits.map((limit) => limit.token));
    if (uniqueActions.size !== capability.allowedActions.length) {
      context.addIssue({ code: "custom", path: ["allowedActions"], message: "Actions must be unique." });
    }
    if (uniqueTokens.size !== capability.allowedTokens.length) {
      context.addIssue({ code: "custom", path: ["allowedTokens"], message: "Tokens must be unique." });
    }
    if (uniqueLimits.size !== capability.limits.length) {
      context.addIssue({ code: "custom", path: ["limits"], message: "Each token may have one limit." });
    }
    for (const token of capability.allowedTokens) {
      if (!uniqueLimits.has(token)) {
        context.addIssue({ code: "custom", path: ["limits"], message: `Missing limit for ${token}.` });
      }
    }
    if (new Date(capability.validAfter) >= new Date(capability.expiresAt)) {
      context.addIssue({ code: "custom", path: ["expiresAt"], message: "Expiry must follow activation." });
    }
  });
export type AgentCapability = z.infer<typeof agentCapabilitySchema>;

export const signedCapabilitySchema = z
  .object({
    capability: agentCapabilitySchema,
    issuerPublicKey: z.string().min(1),
    signature: z.string().min(1),
  })
  .strict();
export type SignedCapability = z.infer<typeof signedCapabilitySchema>;

export const paymentIntentSchema = z
  .object({
    intentId: z.string().min(8).max(128),
    organizationId: z.string().min(8).max(128),
    action: agentActionSchema,
    token: payrollTokenSchema,
    recipientAddress: starknetAddressSchema,
    amountAtomic: atomicAmountSchema,
    purposeCode: z.string().min(1).max(80),
    capabilityNonce: z.string().min(16).max(256),
    createdAt: z.string().datetime(),
  })
  .strict();
export type PaymentIntent = z.infer<typeof paymentIntentSchema>;

export const paymentIntentBatchSchema = z.array(paymentIntentSchema).min(1).max(50);

export type CapabilityDecision = {
  allowed: boolean;
  requiresApproval: boolean;
  reasonCode:
    | "ALLOWED"
    | "APPROVAL_REQUIRED"
    | "NOT_YET_VALID"
    | "EXPIRED"
    | "ACTION_DENIED"
    | "TOKEN_DENIED"
    | "RECIPIENT_DENIED"
    | "PURPOSE_DENIED"
    | "PAYMENT_LIMIT_EXCEEDED"
    | "PERIOD_LIMIT_EXCEEDED"
    | "PERIOD_INACTIVE"
    | "CAPABILITY_MISMATCH";
  capabilityHash: `0x${string}`;
};

function capabilityPayload(capability: AgentCapability): Uint8Array {
  return utf8(stableJson(agentCapabilitySchema.parse(capability)));
}

export function hashCapability(capability: AgentCapability): `0x${string}` {
  return toHex(sha256(capabilityPayload(capability)));
}

export function signCapability(capability: AgentCapability, issuerSecretKey: Uint8Array): SignedCapability {
  const parsed = agentCapabilitySchema.parse(capability);
  return {
    capability: parsed,
    issuerPublicKey: toBase64(ed25519.getPublicKey(issuerSecretKey)),
    signature: toBase64(ed25519.sign(capabilityPayload(parsed), issuerSecretKey)),
  };
}

export function verifySignedCapability(value: unknown): SignedCapability {
  const signed = signedCapabilitySchema.parse(value);
  const publicKey = fromBase64(signed.issuerPublicKey);
  const signature = fromBase64(signed.signature);
  if (
    publicKey.length !== 32 ||
    signature.length !== 64 ||
    !ed25519.verify(signature, capabilityPayload(signed.capability), publicKey, { zip215: false })
  ) {
    throw new Error("Capability signature is invalid.");
  }
  return signed;
}

function deny(capability: AgentCapability, reasonCode: CapabilityDecision["reasonCode"]): CapabilityDecision {
  return { allowed: false, requiresApproval: false, reasonCode, capabilityHash: hashCapability(capability) };
}

export function authorizeAgentAction(
  capabilityInput: AgentCapability,
  action: AgentAction,
  now = new Date(),
): CapabilityDecision {
  const capability = agentCapabilitySchema.parse(capabilityInput);
  const timestamp = now.getTime();
  if (timestamp < new Date(capability.validAfter).getTime()) return deny(capability, "NOT_YET_VALID");
  if (timestamp >= new Date(capability.expiresAt).getTime()) return deny(capability, "EXPIRED");
  if (!capability.allowedActions.includes(action)) return deny(capability, "ACTION_DENIED");
  return {
    allowed: true,
    requiresApproval: false,
    reasonCode: "ALLOWED",
    capabilityHash: hashCapability(capability),
  };
}

export function authorizePaymentIntent(
  capabilityInput: AgentCapability,
  intentInput: PaymentIntent,
  now = new Date(),
): CapabilityDecision {
  const capability = agentCapabilitySchema.parse(capabilityInput);
  const intent = paymentIntentSchema.parse(intentInput);
  const timestamp = now.getTime();

  if (
    intent.organizationId !== capability.organizationId ||
    intent.capabilityNonce !== capability.nonce
  ) return deny(capability, "CAPABILITY_MISMATCH");
  if (timestamp < new Date(capability.validAfter).getTime()) return deny(capability, "NOT_YET_VALID");
  if (timestamp >= new Date(capability.expiresAt).getTime()) return deny(capability, "EXPIRED");
  if (!capability.allowedActions.includes(intent.action)) return deny(capability, "ACTION_DENIED");
  if (!capability.allowedTokens.includes(intent.token)) return deny(capability, "TOKEN_DENIED");
  if (
    capability.recipientScope.mode === "allowlist" &&
    !capability.recipientScope.addresses.some(
      (address) => address.toLowerCase() === intent.recipientAddress.toLowerCase(),
    )
  ) return deny(capability, "RECIPIENT_DENIED");
  if (!capability.purposeCodes.includes(intent.purposeCode)) return deny(capability, "PURPOSE_DENIED");

  const limit = capability.limits.find((entry) => entry.token === intent.token);
  if (!limit) return deny(capability, "TOKEN_DENIED");
  if (
    timestamp < new Date(limit.periodStartsAt).getTime() ||
    timestamp >= new Date(limit.periodEndsAt).getTime()
  ) return deny(capability, "PERIOD_INACTIVE");

  const amount = BigInt(intent.amountAtomic);
  if (amount > BigInt(limit.maxPerPaymentAtomic)) return deny(capability, "PAYMENT_LIMIT_EXCEEDED");
  if (BigInt(limit.spentThisPeriodAtomic) + amount > BigInt(limit.maxPerPeriodAtomic)) {
    return deny(capability, "PERIOD_LIMIT_EXCEEDED");
  }

  const requiresApproval =
    capability.executionMode !== "autonomous_bounded" ||
    amount >= BigInt(limit.approvalThresholdAtomic);
  return {
    allowed: true,
    requiresApproval,
    reasonCode: requiresApproval ? "APPROVAL_REQUIRED" : "ALLOWED",
    capabilityHash: hashCapability(capability),
  };
}

export function authorizePaymentBatch(
  capabilityInput: AgentCapability,
  intentInputs: readonly PaymentIntent[],
  now = new Date(),
): { decisions: CapabilityDecision[]; allowed: boolean; requiresApproval: boolean } {
  let workingCapability = agentCapabilitySchema.parse(capabilityInput);
  const intents = paymentIntentBatchSchema.parse(intentInputs);
  const intentIds = new Set<string>();
  const decisions: CapabilityDecision[] = [];

  for (const intent of intents) {
    if (intentIds.has(intent.intentId)) {
      decisions.push(deny(workingCapability, "CAPABILITY_MISMATCH"));
      continue;
    }
    intentIds.add(intent.intentId);
    const decision = authorizePaymentIntent(workingCapability, intent, now);
    decisions.push(decision);
    if (decision.allowed) {
      workingCapability = {
        ...workingCapability,
        limits: workingCapability.limits.map((limit) =>
          limit.token === intent.token
            ? {
                ...limit,
                spentThisPeriodAtomic: (
                  BigInt(limit.spentThisPeriodAtomic) + BigInt(intent.amountAtomic)
                ).toString(),
              }
            : limit,
        ),
      };
    }
  }

  return {
    decisions,
    allowed: decisions.every((decision) => decision.allowed),
    requiresApproval: decisions.some((decision) => decision.requiresApproval),
  };
}
