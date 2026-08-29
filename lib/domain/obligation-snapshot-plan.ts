import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import {
  obligationSnapshotCommitmentV2,
  obligationSnapshotV2Schema,
} from "./exception-protocol";
import {
  commitmentSchema,
  starknetAddressSchema,
  uuidV7Schema,
} from "./records";
import { atomicAmountSchema, privatePayrollLineSchema } from "./payroll";

const transactionHashSchema = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const decimalSchema = z.string().regex(/^(0|[1-9][0-9]*)$/);
const byteArraySchema = z.array(z.number().int().min(0).max(255)).length(32);
export const merkleWitnessSchema = z.object({
  siblings: z.array(decimalSchema).length(6),
  path_bits: z.array(z.boolean()).length(6),
}).strict();
const calculatedLineSchema = privatePayrollLineSchema.extend({
  grossAtomic: atomicAmountSchema,
  deductionsTotalAtomic: atomicAmountSchema,
  netAtomic: atomicAmountSchema,
}).strict();
export const agreementWitnessSchema = z.object({
  enabled: z.literal(true),
  id_commitment: byteArraySchema,
  recipient_commitment: byteArraySchema,
  earnings: z.array(atomicAmountSchema).length(8),
  earnings_count: decimalSchema,
  token: z.enum(["0", "1"]),
  policy_commitment: byteArraySchema,
  schedule_commitment: byteArraySchema,
  due_at: decimalSchema,
  valid_until: decimalSchema,
  classification_declared: decimalSchema,
  classification_score: decimalSchema,
  classification_employee_threshold: decimalSchema,
  final_pay_mode: z.boolean(),
  final_required_mask: decimalSchema,
  final_components: z.array(atomicAmountSchema).length(5),
  fx_floor_atomic: atomicAmountSchema,
  reference_currency: z.enum(["0", "1"]),
  salt: byteArraySchema,
}).strict();
export const snapshotClaimWitnessLineSchema = z.object({
  index: z.number().int().min(0).max(49),
  agreementId: z.string().min(1).max(160),
  calculated: calculatedLineSchema,
  agreementLeaf: commitmentSchema,
  agreement: agreementWitnessSchema,
  claimCapabilityCommitment: commitmentSchema,
  expectedNetAtomic: atomicAmountSchema.refine((value) => BigInt(value) > 0n),
  claimLeaf: commitmentSchema,
  agreementMembership: merkleWitnessSchema,
  claimMembership: merkleWitnessSchema,
}).strict();

export const obligationSnapshotPlanPrivateSchema = z.object({
  format: z.literal("payo-obligation-snapshot-plan-v1"),
  planId: uuidV7Schema,
  runId: uuidV7Schema,
  organizationId: uuidV7Schema,
  cycleId: z.string().min(1).max(160),
  payrollRevision: z.number().int().positive().max(0xffff_ffff),
  snapshot: obligationSnapshotV2Schema,
  snapshotCommitment: commitmentSchema,
  agreementBindings: z.array(z.object({
    agreementId: z.string().min(1).max(160),
    payeeId: uuidV7Schema,
    claimAccessGrantId: uuidV7Schema.optional(),
    claimantPrincipalId: z.string().min(1).max(160).optional(),
    claimantPublicKey: z.string().min(16).max(256).optional(),
    agreementCommitment: commitmentSchema,
    recipientCommitment: commitmentSchema,
    scheduleCommitment: commitmentSchema,
    claimCapabilityCommitment: commitmentSchema,
  }).strict()).min(1).max(50),
  claimWitness: z.object({
    claimRoot: commitmentSchema,
    lines: z.array(snapshotClaimWitnessLineSchema).min(1).max(50),
  }).strict(),
  createdAt: z.string().datetime(),
}).strict().superRefine((plan, context) => {
  if (plan.planId === plan.runId) {
    context.addIssue({
      code: "custom",
      path: ["runId"],
      message: "Snapshot plan and future payroll run must use distinct vault identifiers.",
    });
  }
  if (new Set(plan.agreementBindings.map(({ agreementId }) => agreementId)).size !== plan.agreementBindings.length) {
    context.addIssue({ code: "custom", path: ["agreementBindings"], message: "Snapshot agreements must be unique." });
  }
  if (
    plan.claimWitness.lines.length !== plan.agreementBindings.length
    || plan.claimWitness.lines.some((line, index) =>
      line.index !== index
      || line.agreementId !== plan.agreementBindings[index]?.agreementId
      || BigInt(line.claimCapabilityCommitment)
        !== BigInt(plan.agreementBindings[index]?.claimCapabilityCommitment ?? "0x0"))
  ) {
    context.addIssue({
      code: "custom",
      path: ["claimWitness", "lines"],
      message: "Snapshot claim witnesses must exactly match the ordered agreement bindings.",
    });
  }
  if (
    BigInt(plan.claimWitness.claimRoot) !== BigInt(plan.snapshot.obligationRoot)
    || BigInt(plan.claimWitness.claimRoot) !== BigInt(plan.snapshot.availabilityCommitment)
  ) {
    context.addIssue({
      code: "custom",
      path: ["claimWitness", "claimRoot"],
      message: "Snapshot claim witness root does not match the immutable snapshot.",
    });
  }
  if (obligationSnapshotCommitmentV2(plan.snapshot) !== plan.snapshotCommitment) {
    context.addIssue({
      code: "custom",
      path: ["snapshotCommitment"],
      message: "Snapshot commitment does not match its immutable plan.",
    });
  }
  if (BigInt(plan.snapshot.availabilityCommitment) !== BigInt(plan.snapshot.obligationRoot)) {
    context.addIssue({
      code: "custom",
      path: ["snapshot", "availabilityCommitment"],
      message: "The active PAYO seal binds snapshot availability to the full obligation root.",
    });
  }
});

export type ObligationSnapshotPlanPrivate = z.infer<typeof obligationSnapshotPlanPrivateSchema>;

const claimAccessBindingSchema = z.object({
  agreementId: z.string().min(1).max(160),
  payeeId: uuidV7Schema,
  claimAccessGrantId: uuidV7Schema.optional(),
  claimantPrincipalId: z.string().min(1).max(160).optional(),
  claimantPublicKey: z.string().min(16).max(256).optional(),
  agreementCommitment: commitmentSchema,
  recipientCommitment: commitmentSchema,
  scheduleCommitment: commitmentSchema,
  claimCapabilityCommitment: commitmentSchema,
}).strict();

export const obligationClaimAccessPrivateSchema = z.object({
  format: z.literal("payo-obligation-claim-access-v1"),
  grantId: uuidV7Schema,
  snapshotPlanId: uuidV7Schema,
  runId: uuidV7Schema,
  organizationId: uuidV7Schema,
  cycleId: z.string().min(1).max(160),
  payrollRevision: z.number().int().positive().max(0xffff_ffff),
  snapshot: obligationSnapshotV2Schema,
  snapshotCommitment: commitmentSchema,
  recipientSalt: commitmentSchema.optional(),
  binding: claimAccessBindingSchema,
  witness: snapshotClaimWitnessLineSchema,
  issuerPrincipal: z.object({
    principalId: z.string().min(1).max(160),
    publicKey: z.string().min(16).max(160),
  }).strict(),
  createdAt: z.string().datetime(),
}).strict().superRefine((access, context) => {
  if (
    access.binding.agreementId !== access.witness.agreementId
    || (access.binding.claimAccessGrantId !== undefined
      && access.binding.claimAccessGrantId !== access.grantId)
    || BigInt(access.binding.claimCapabilityCommitment)
      !== BigInt(access.witness.claimCapabilityCommitment)
  ) {
    context.addIssue({
      code: "custom",
      path: ["witness"],
      message: "Claim access must bind one exact agreement and worker capability.",
    });
  }
  if (
    obligationSnapshotCommitmentV2(access.snapshot) !== access.snapshotCommitment
    || BigInt(access.snapshot.obligationRoot) !== BigInt(access.snapshot.availabilityCommitment)
  ) {
    context.addIssue({
      code: "custom",
      path: ["snapshotCommitment"],
      message: "Claim access contains an invalid immutable snapshot binding.",
    });
  }
});

export type ObligationClaimAccessPrivate = z.infer<typeof obligationClaimAccessPrivateSchema>;

export const obligationClaimAccessGrantCreateSchema = z.object({
  id: uuidV7Schema,
  claimantPrincipalId: z.string().min(1).max(160),
  envelope: encryptedVaultRecordSchema,
}).strict();

export type ObligationClaimAccessGrantCreate = z.infer<typeof obligationClaimAccessGrantCreateSchema>;

export const obligationSnapshotPlanCreateSchema = z.object({
  id: uuidV7Schema,
  runId: uuidV7Schema,
  organizationId: uuidV7Schema,
  cycleId: z.string().min(1).max(160),
  payrollRevision: z.number().int().positive().max(0xffff_ffff),
  ownerAddress: starknetAddressSchema,
  snapshot: obligationSnapshotV2Schema,
  snapshotCommitment: commitmentSchema,
  claimAccessGrants: z.array(obligationClaimAccessGrantCreateSchema).min(1).max(50),
  envelope: encryptedVaultRecordSchema,
}).strict().superRefine((plan, context) => {
  if (new Set(plan.claimAccessGrants.map(({ id }) => id)).size !== plan.claimAccessGrants.length) {
    context.addIssue({
      code: "custom",
      path: ["claimAccessGrants"],
      message: "Claim-access grant identifiers must be unique.",
    });
  }
  for (const grant of plan.claimAccessGrants) {
    if (
      grant.envelope.aad.organizationId !== plan.organizationId
      || grant.envelope.aad.recordType !== "obligation-claim-access"
      || grant.envelope.aad.recordId !== grant.id
      || grant.envelope.aad.revision !== 1
      || grant.envelope.wrappedKeys.length !== 1
      || grant.envelope.wrappedKeys[0]?.principalId !== grant.claimantPrincipalId
    ) {
      context.addIssue({
        code: "custom",
        path: ["claimAccessGrants"],
        message: "Each worker claim-access packet must be encrypted only to its declared claimant.",
      });
    }
  }
  if (plan.id === plan.runId) {
    context.addIssue({
      code: "custom",
      path: ["runId"],
      message: "Snapshot plan and future payroll run identifiers must be distinct.",
    });
  }
  if (BigInt(plan.ownerAddress) === 0n || BigInt(plan.snapshot.ownerAddress) !== BigInt(plan.ownerAddress)) {
    context.addIssue({
      code: "custom",
      path: ["ownerAddress"],
      message: "Snapshot owner must be the non-zero connected Starknet account.",
    });
  }
  if (obligationSnapshotCommitmentV2(plan.snapshot) !== plan.snapshotCommitment) {
    context.addIssue({
      code: "custom",
      path: ["snapshotCommitment"],
      message: "Snapshot commitment does not match its public fields.",
    });
  }
  if (BigInt(plan.snapshot.availabilityCommitment) !== BigInt(plan.snapshot.obligationRoot)) {
    context.addIssue({
      code: "custom",
      path: ["snapshot", "availabilityCommitment"],
      message: "The active PAYO seal binds snapshot availability to the full obligation root.",
    });
  }
  if (
    plan.envelope.aad.organizationId !== plan.organizationId
    || plan.envelope.aad.recordType !== "obligation-snapshot-plan"
    || plan.envelope.aad.recordId !== plan.id
    || plan.envelope.aad.revision !== 1
  ) {
    context.addIssue({ code: "custom", path: ["envelope"], message: "Snapshot-plan envelope AAD is invalid." });
  }
}).transform((plan) => ({
  ...plan,
  ownerAddress: `0x${BigInt(plan.ownerAddress).toString(16)}`,
}));

export type ObligationSnapshotPlanCreate = z.infer<typeof obligationSnapshotPlanCreateSchema>;

export const obligationSnapshotPlanSubmissionSchema = z.object({
  transactionHash: transactionHashSchema,
}).strict();

export const obligationSnapshotPlanStateSchema = z.enum([
  "prepared",
  "submitted",
  "registered",
  "consumed",
  "cancelled",
  "expired",
]);

export const obligationSnapshotPlanSummarySchema = z.object({
  id: uuidV7Schema,
  runId: uuidV7Schema,
  organizationId: uuidV7Schema,
  cycleId: z.string(),
  revision: z.number().int().positive(),
  ownerAddress: starknetAddressSchema,
  agreementRoot: commitmentSchema,
  claimRoot: commitmentSchema,
  policyRoot: commitmentSchema,
  runNullifier: commitmentSchema,
  snapshotFact: commitmentSchema,
  dueAt: z.string().datetime(),
  graceEndsAt: z.string().datetime(),
  claimEndsAt: z.string().datetime(),
  state: obligationSnapshotPlanStateSchema,
  registrationTransactionHash: transactionHashSchema.nullable(),
  registeredAt: z.string().datetime().nullable(),
  consumedAt: z.string().datetime().nullable(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
}).strict();

export type ObligationSnapshotPlanSummary = z.infer<typeof obligationSnapshotPlanSummarySchema>;

export const obligationSnapshotPlanPublicSchema = obligationSnapshotPlanSummarySchema.extend({
  envelope: encryptedVaultRecordSchema,
}).strict();

export type ObligationSnapshotPlanPublic = z.infer<typeof obligationSnapshotPlanPublicSchema>;

export const obligationClaimAccessGrantSummarySchema = z.object({
  id: uuidV7Schema,
  claimantPrincipalId: z.string().min(1).max(160),
  revokedAt: z.string().datetime().nullable(),
  plan: obligationSnapshotPlanSummarySchema,
  envelope: encryptedVaultRecordSchema,
}).strict();

export type ObligationClaimAccessGrantSummary = z.infer<
  typeof obligationClaimAccessGrantSummarySchema
>;
