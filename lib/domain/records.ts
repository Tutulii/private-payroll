import { z } from "zod";
import { vaultRecoveryPackageSchema } from "@/lib/crypto/vault";
import { signedCapabilitySchema } from "./capability";
import { employmentAgreementSchema, offboardingPaySchema } from "./obligations";
import {
  atomicAmountSchema,
  payrollRunStateSchema,
  payrollTokenSchema,
  proofPackageSchema,
} from "./payroll";
import { settlementStateSchema } from "./settlement";

export { vaultRecoveryPackageSchema };

export const uuidV7Schema = z
  .string()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    "Expected an RFC 9562 UUIDv7 identifier.",
  );

// Vault wrapping identities predate the canonical record model and may be a
// Ready `starknet:...` principal, a DID, or a legacy UUID. They are stable
// cryptographic recipient identifiers, not persistent record IDs.
export const vaultPrincipalIdSchema = z
  .string()
  .min(1)
  .max(160)
  .refine((value) => value.trim() === value, "A vault principal ID cannot contain surrounding whitespace.");

export const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
export const starknetAddressSchema = z.string().regex(/^0x[0-9a-fA-F]+$/);

export function generateUuidV7(
  timestamp = Date.now(),
  random = crypto.getRandomValues(new Uint8Array(10)),
): string {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp > 0xffffffffffff) {
    throw new Error("UUIDv7 timestamp must fit in 48 unsigned bits.");
  }
  if (random.length !== 10) throw new Error("UUIDv7 requires exactly 10 random bytes.");

  const bytes = new Uint8Array(16);
  let remaining = BigInt(timestamp);
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  bytes.set(random, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
}

const recordHeaderSchema = z.object({
  schemaVersion: z.literal(1),
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  revision: z.number().int().positive(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export const organizationRecordSchema = z.object({
  schemaVersion: z.literal(1),
  id: uuidV7Schema,
  name: z.string().min(1).max(160),
  enabledTokens: z.array(payrollTokenSchema).min(1).max(2),
  policyCatalogRoot: commitmentSchema.optional(),
  fxCatalogRoot: commitmentSchema.optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
}).strict();

export const principalRecordSchema = recordHeaderSchema.extend({
  kind: z.enum(["admin", "operator", "reviewer", "worker", "agent", "auditor", "signer"]),
  displayName: z.string().min(1).max(160),
  accessState: z.enum(["directory_only", "vault_grantee"]),
  vaultPrincipalId: z.string().min(1).max(256).optional(),
  vaultPublicKey: z.string().min(16).optional(),
  status: z.enum(["active", "revoked"]),
}).strict().superRefine((principal, context) => {
  if (principal.accessState === "vault_grantee" && (!principal.vaultPrincipalId || !principal.vaultPublicKey)) {
    context.addIssue({ code: "custom", path: ["vaultPublicKey"], message: "A vault grantee requires its wrapping identity and public key." });
  }
  if (principal.accessState === "directory_only" && (principal.vaultPrincipalId || principal.vaultPublicKey)) {
    context.addIssue({ code: "custom", path: ["accessState"], message: "A directory-only principal cannot claim vault access." });
  }
});

export const payeeRecordSchema = recordHeaderSchema.extend({
  principalId: uuidV7Schema,
  principalKind: z.enum(["human", "agent"]),
  legalName: z.string().min(1).max(240).optional(),
  displayName: z.string().min(1).max(160),
  recipientAddress: starknetAddressSchema,
  tokenPreference: payrollTokenSchema,
  jurisdictionCode: z.string().regex(/^[A-Z]{2}(-[A-Z0-9]{1,3})?$/),
  claimIdentityPrincipalId: vaultPrincipalIdSchema.optional(),
  claimIdentityPublicKey: z.string().min(16).max(160).optional(),
  claimCapabilityCommitment: commitmentSchema.optional(),
  status: z.enum(["active", "offboarding", "inactive"]),
}).strict().superRefine((record, context) => {
  const fields = [
    record.claimIdentityPrincipalId,
    record.claimIdentityPublicKey,
    record.claimCapabilityCommitment,
  ];
  const configured = fields.filter(Boolean).length;
  if (configured !== 0 && configured !== fields.length) {
    context.addIssue({
      code: "custom",
      path: ["claimCapabilityCommitment"],
      message: "A claim identity requires its principal, public key and capability commitment together.",
    });
  }
});

export const payAgreementRecordSchema = recordHeaderSchema.extend({
  payeeId: uuidV7Schema,
  agreement: employmentAgreementSchema,
  recipientCommitment: commitmentSchema,
  recipientSalt: commitmentSchema,
  agreementSalt: commitmentSchema,
  agreementCommitment: commitmentSchema,
  // Optional only for pre-vNext legacy records. New claim-enabled agreements
  // copy the worker-owned public capability commitment from the payee record.
  claimCapabilityCommitment: commitmentSchema.optional(),
  // The v2 circuit uses a Poseidon plan commitment while the externally
  // disclosed agreement commitment remains Keccak. Persist the exact proof
  // schedule binding so durable-run locking never compares different domains.
  proofScheduleCommitment: commitmentSchema.optional(),
  supersedesAgreementId: uuidV7Schema.optional(),
  effectiveFrom: z.string().datetime(),
  effectiveUntil: z.string().datetime().optional(),
  offboardingTerms: offboardingPaySchema.optional(),
}).strict().superRefine((record, context) => {
  if (
    record.agreement.classificationAssessment
    && record.agreementSalt.toLowerCase() !== record.agreement.classificationFactsCommitment.toLowerCase()
  ) {
    context.addIssue({
      code: "custom",
      path: ["agreementSalt"],
      message: "The proved agreement salt must bind the versioned classification-facts commitment.",
    });
  }
});

export const payrollLineRecordSchema = recordHeaderSchema.extend({
  runId: uuidV7Schema,
  agreementId: uuidV7Schema,
  payeeId: uuidV7Schema,
  token: payrollTokenSchema,
  grossAtomic: atomicAmountSchema,
  deductionsAtomic: z.array(atomicAmountSchema).max(8),
  netAtomic: atomicAmountSchema,
  recipientCommitment: commitmentSchema,
  policyCommitment: commitmentSchema,
  scheduleCommitment: commitmentSchema,
  leafCommitment: commitmentSchema,
}).strict();

export const payrollRunRecordSchema = recordHeaderSchema.extend({
  cycleId: z.string().min(1).max(160),
  state: payrollRunStateSchema,
  dueAt: z.string().datetime(),
  agreementRoot: commitmentSchema.optional(),
  manifestRoot: commitmentSchema.optional(),
  policyCatalogRoot: commitmentSchema.optional(),
  fxCatalogRoot: commitmentSchema.optional(),
  runNullifier: commitmentSchema.optional(),
  proofBundleId: uuidV7Schema.optional(),
  settlementId: uuidV7Schema.optional(),
}).strict();

export const proofBundleRecordSchema = recordHeaderSchema.extend({
  runId: uuidV7Schema,
  proofPackage: proofPackageSchema,
  verificationState: z.enum(["unverified", "verified", "rejected"]),
  verificationTransactionHash: starknetAddressSchema.optional(),
}).strict();

export const settlementRecordSchema = recordHeaderSchema.extend({
  runId: uuidV7Schema,
  workflowType: z.enum(["payroll", "wage_claim", "wage_remediation"]).optional(),
  subjectRecordId: uuidV7Schema.optional(),
  walletRequestId: z.string().min(1).max(256),
  idempotencyKey: z.string().min(16).max(256),
  tokenTotals: z.object({
    STRK: atomicAmountSchema,
    USDC: atomicAmountSchema,
  }).strict(),
  tokenTotalsCommitment: commitmentSchema,
  transactionHash: starknetAddressSchema.optional(),
  state: settlementStateSchema,
  submittedAt: z.string().datetime().optional(),
  confirmedAt: z.string().datetime().optional(),
  settlementRoot: commitmentSchema.optional(),
  noteEvidenceState: z.enum(["unavailable", "pending", "available", "proved"]),
}).strict();

export const receiptRecordSchema = recordHeaderSchema.extend({
  runId: uuidV7Schema,
  settlementId: uuidV7Schema,
  scope: z.enum(["employer", "worker", "auditor", "tax"]),
  granteePrincipalId: vaultPrincipalIdSchema,
  packageCommitment: commitmentSchema,
  evidence: z.object({
    settlementState: settlementStateSchema,
    transactionHash: starknetAddressSchema,
    tokenTotals: z.object({
      STRK: atomicAmountSchema,
      USDC: atomicAmountSchema,
    }).strict(),
    tokenTotalsCommitment: commitmentSchema,
    confirmationDepth: z.number().int().nonnegative(),
    blockNumber: atomicAmountSchema.optional(),
    issuedAt: z.string().datetime(),
  }).strict(),
  expiresAt: z.string().datetime().optional(),
  revokedAt: z.string().datetime().optional(),
}).strict();

export const disclosureGrantRecordSchema = recordHeaderSchema.extend({
  runId: uuidV7Schema,
  granteePrincipalId: vaultPrincipalIdSchema,
  fieldScope: z.array(z.enum([
    "identity",
    "gross",
    "deductions",
    "net",
    "token",
    "schedule",
    "classification",
    "aggregate",
    "settlement",
    "exception",
  ])).min(1),
  recipientEncryptionKey: z.string().min(16),
  validAfter: z.string().datetime(),
  expiresAt: z.string().datetime(),
  revokedAt: z.string().datetime().optional(),
}).strict();

export const agentCapabilityRecordSchema = recordHeaderSchema.extend({
  principalId: uuidV7Schema,
  signedCapability: signedCapabilitySchema,
  capabilityHash: commitmentSchema,
  revokedAt: z.string().datetime().optional(),
}).strict().superRefine((record, context) => {
  if (record.signedCapability.capability.id !== record.id) {
    context.addIssue({ code: "custom", path: ["signedCapability", "capability", "id"], message: "The signed capability must use the encrypted record identifier." });
  }
  if (record.signedCapability.capability.organizationId !== record.organizationId) {
    context.addIssue({ code: "custom", path: ["signedCapability", "capability", "organizationId"], message: "The signed capability belongs to another organization." });
  }
  if (record.signedCapability.capability.principalId !== record.principalId) {
    context.addIssue({ code: "custom", path: ["signedCapability", "capability", "principalId"], message: "The signed capability belongs to another principal." });
  }
});

export const wageClaimRecordSchema = recordHeaderSchema.extend({
  agreementId: uuidV7Schema,
  runId: uuidV7Schema,
  claimNullifier: commitmentSchema.optional(),
  claimSalt: commitmentSchema,
  claimKind: z.enum(["missing_obligation", "below_committed_floor", "incomplete_final_pay"]),
  disputedReferenceValueAtomic: atomicAmountSchema.optional(),
  disputedFinalIncludedMask: z.number().int().min(0).max(31).optional(),
  shortfallAtomic: atomicAmountSchema.optional(),
  token: payrollTokenSchema.optional(),
  proofBundleId: uuidV7Schema.optional(),
  settlementId: uuidV7Schema.optional(),
  state: z.enum(["draft", "proven", "submitted", "accepted", "remediated", "rejected"]),
}).strict().superRefine((claim, context) => {
  if (claim.claimKind === "below_committed_floor" && claim.disputedReferenceValueAtomic === undefined) {
    context.addIssue({ code: "custom", path: ["disputedReferenceValueAtomic"], message: "A below-floor claim requires the disputed reference value." });
  }
  if (claim.claimKind === "incomplete_final_pay" && claim.disputedFinalIncludedMask === undefined) {
    context.addIssue({ code: "custom", path: ["disputedFinalIncludedMask"], message: "A final-pay claim requires the disputed included-component mask." });
  }
  if (claim.state !== "draft") {
    for (const field of ["claimNullifier", "shortfallAtomic", "token", "proofBundleId"] as const) {
      if (claim[field] === undefined) {
        const label = field === "proofBundleId" ? "its proof bundle" : field;
        context.addIssue({ code: "custom", path: [field], message: `A non-draft claim requires ${label}.` });
      }
    }
  }
  if (["submitted", "accepted", "remediated"].includes(claim.state) && !claim.settlementId) {
    context.addIssue({ code: "custom", path: ["settlementId"], message: "A submitted claim requires its settlement." });
  }
});

export const remediationRecordSchema = recordHeaderSchema.extend({
  claimId: uuidV7Schema,
  runId: uuidV7Schema.optional(),
  agreementId: uuidV7Schema.optional(),
  claimNullifier: commitmentSchema.optional(),
  amountAtomic: atomicAmountSchema.optional(),
  token: payrollTokenSchema.optional(),
  settlementId: uuidV7Schema.optional(),
  proofBundleId: uuidV7Schema.optional(),
  remediationNullifier: commitmentSchema.optional(),
  remediationSalt: commitmentSchema,
  state: z.enum(["draft", "proven", "approval_pending", "submitted", "confirmed", "proved"]),
}).strict().superRefine((remediation, context) => {
  if (remediation.state !== "draft") {
    for (const field of ["runId", "agreementId", "claimNullifier", "amountAtomic", "token", "proofBundleId"] as const) {
      if (remediation[field] === undefined) {
        context.addIssue({ code: "custom", path: [field], message: `A non-draft remediation requires ${field}.` });
      }
    }
  }
  if (["approval_pending", "submitted", "confirmed", "proved"].includes(remediation.state) && !remediation.settlementId) {
    context.addIssue({ code: "custom", path: ["settlementId"], message: "Submitted remediation requires a settlement." });
  }
});

export const auditEventRecordSchema = z.object({
  schemaVersion: z.literal(1),
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  actorPrincipalId: uuidV7Schema,
  action: z.string().min(1).max(160),
  subjectId: uuidV7Schema.optional(),
  result: z.enum(["allowed", "denied", "failed"]),
  reasonCode: z.string().min(1).max(120).optional(),
  metadata: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])),
  createdAt: z.string().datetime(),
}).strict();

export const canonicalRecordSchemas = {
  organization: organizationRecordSchema,
  principal: principalRecordSchema,
  payee: payeeRecordSchema,
  payAgreement: payAgreementRecordSchema,
  payrollRun: payrollRunRecordSchema,
  payrollLine: payrollLineRecordSchema,
  proofBundle: proofBundleRecordSchema,
  settlement: settlementRecordSchema,
  receipt: receiptRecordSchema,
  disclosureGrant: disclosureGrantRecordSchema,
  agentCapability: agentCapabilityRecordSchema,
  wageClaim: wageClaimRecordSchema,
  remediation: remediationRecordSchema,
  auditEvent: auditEventRecordSchema,
  vaultRecoveryPackage: vaultRecoveryPackageSchema,
} as const;
