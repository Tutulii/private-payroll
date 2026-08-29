import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import {
  claimFactCommitmentV2,
  exceptionClaimFactSchema,
  obligationSnapshotCommitmentV2,
  obligationSnapshotV2Schema,
  type ExceptionClaimKind,
} from "./exception-protocol";
import {
  agreementWitnessSchema,
  merkleWitnessSchema,
} from "./obligation-snapshot-plan";
import {
  commitmentSchema,
  starknetAddressSchema,
  uuidV7Schema,
} from "./records";

export const workerClaimPrivateSchema = z.object({
  format: z.literal("payo-worker-wage-claim-v2"),
  schemaVersion: z.literal(2),
  id: uuidV7Schema,
  claimAccessGrantId: uuidV7Schema,
  snapshotPlanId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  agreementId: z.string().min(1).max(160),
  claimKind: z.enum(["missing_obligation", "below_committed_floor", "incomplete_final_pay"]),
  claimFact: exceptionClaimFactSchema,
  claimFactCommitment: commitmentSchema,
  proofBundleId: uuidV7Schema,
  claimantPrincipal: z.object({
    principalId: z.string().min(1).max(160),
    publicKey: z.string().min(16).max(256),
  }).strict(),
  remediationWitness: z.object({
    snapshot: obligationSnapshotV2Schema,
    recipientAddress: starknetAddressSchema,
    recipientSalt: commitmentSchema,
    agreement: agreementWitnessSchema,
    agreementMembership: merkleWitnessSchema,
  }).strict(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
}).strict().superRefine((claim, context) => {
  if (claim.claimFact.claimKind !== claim.claimKind) {
    context.addIssue({
      code: "custom",
      path: ["claimFact", "claimKind"],
      message: "The encrypted claim kind differs from its proved fact.",
    });
  }
  if (claimFactCommitmentV2(claim.claimFact) !== claim.claimFactCommitment) {
    context.addIssue({
      code: "custom",
      path: ["claimFactCommitment"],
      message: "The encrypted claim fact does not match its immutable commitment.",
    });
  }
  const witness = claim.remediationWitness;
  if (
    obligationSnapshotCommitmentV2(witness.snapshot) !== claim.claimFact.snapshotCommitment
    || BigInt(witness.snapshot.runNullifier) !== BigInt(claim.claimFact.runNullifier)
    || witness.agreementMembership.path_bits.some(
      (bit, level) => bit !== Boolean((claim.claimFact.targetIndex >> level) & 1),
    )
  ) {
    context.addIssue({
      code: "custom",
      path: ["remediationWitness"],
      message: "The encrypted remediation witness differs from the accepted claim.",
    });
  }
});

export type WorkerClaimPrivate = z.infer<typeof workerClaimPrivateSchema>;

export const workerClaimCreateSchema = z.object({
  id: uuidV7Schema,
  claimAccessGrantId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  revision: z.literal(1),
  proofBundleId: uuidV7Schema,
  claimSubjectNullifier: commitmentSchema,
  claimFactCommitment: commitmentSchema,
  envelope: encryptedVaultRecordSchema,
}).strict().superRefine((claim, context) => {
  if (
    claim.envelope.aad.organizationId !== claim.organizationId
    || claim.envelope.aad.recordType !== "wage-claim-v2"
    || claim.envelope.aad.recordId !== claim.id
    || claim.envelope.aad.revision !== claim.revision
  ) {
    context.addIssue({
      code: "custom",
      path: ["envelope"],
      message: "Worker claim envelope AAD does not match its storage identity.",
    });
  }
  const recipients = claim.envelope.wrappedKeys.map(({ principalId }) => principalId);
  if (recipients.length < 2 || new Set(recipients).size !== recipients.length) {
    context.addIssue({
      code: "custom",
      path: ["envelope", "wrappedKeys"],
      message: "A worker claim must be encrypted to distinct worker and employer principals.",
    });
  }
});

export type WorkerClaimCreate = z.infer<typeof workerClaimCreateSchema>;

export const workerClaimSummarySchema = z.object({
  id: uuidV7Schema,
  claimAccessGrantId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  claimantPrincipalId: z.string().min(1).max(160),
  proofBundleId: uuidV7Schema,
  claimSubjectNullifier: commitmentSchema,
  claimFactCommitment: commitmentSchema,
  state: z.enum(["prepared", "proved", "authorization_pending", "accepted", "rejected"]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  envelope: encryptedVaultRecordSchema,
}).strict();

export type WorkerClaimSummary = z.infer<typeof workerClaimSummarySchema>;

export const workerClaimKinds = [
  "missing_obligation",
  "below_committed_floor",
  "incomplete_final_pay",
] as const satisfies readonly ExceptionClaimKind[];
