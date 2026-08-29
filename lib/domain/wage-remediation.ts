import { z } from "zod";
import { hashRecipientCommitment } from "@/lib/crypto/commitments";
import { toHex } from "@/lib/crypto/encoding";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { fxSnapshotSchema } from "./fx";
import {
  claimFactCommitmentV2,
  exceptionClaimFactSchema,
  remediationFactCommitmentV2,
  remediationSubjectNullifierV2,
} from "./exception-protocol";
import { atomicAmountSchema } from "./payroll";
import {
  commitmentSchema,
  starknetAddressSchema,
  uuidV7Schema,
} from "./records";

const u64Schema = z.string().regex(/^(0|[1-9][0-9]*)$/).refine(
  (value) => BigInt(value) < 1n << 64n,
  "Value must fit in u64.",
);
const positiveAtomicAmountSchema = atomicAmountSchema.refine(
  (value) => BigInt(value) > 0n,
  "Remediation amount must be positive.",
);

export const wageRemediationStateSchema = z.enum([
  "prepared",
  "proved",
  "authorization_pending",
  "authorized",
  "payment_pending",
  "payment_confirmed",
  "reconciled",
  "expired",
  "failed",
]);

export const wageRemediationPrivateSchema = z.object({
  format: z.literal("payo-wage-remediation-v2"),
  schemaVersion: z.literal(2),
  id: uuidV7Schema,
  workerClaimId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  proofBundleId: uuidV7Schema,
  claimFact: exceptionClaimFactSchema,
  claimSubjectNullifier: commitmentSchema,
  claimFactCommitment: commitmentSchema,
  remediationSubjectNullifier: commitmentSchema,
  remediationFactCommitment: commitmentSchema,
  actionCommitment: commitmentSchema,
  recipientAddress: starknetAddressSchema,
  recipientSalt: commitmentSchema,
  recipientCommitment: commitmentSchema,
  token: z.enum(["STRK", "USDC"]),
  tokenDecimals: z.union([z.literal(6), z.literal(18)]),
  amountAtomic: positiveAtomicAmountSchema,
  referenceValueAtomic: positiveAtomicAmountSchema,
  referenceUnit: z.enum(["strk_atomic", "usdc_atomic", "usd_6", "gbp_6"]),
  fxRoot: commitmentSchema,
  fxEvidence: z.object({
    snapshots: z.array(fxSnapshotSchema).min(1).max(2),
    selectedFxIndex: z.number().int().min(0).max(1),
  }).strict().optional(),
  remediationSecret: commitmentSchema,
  actionSalt: commitmentSchema,
  validityStart: u64Schema,
  validityExpiry: u64Schema,
  createdAt: z.string().datetime(),
}).strict().superRefine((remediation, context) => {
  if (
    remediation.claimFactCommitment !== claimFactCommitmentV2(remediation.claimFact)
    || BigInt(remediation.claimSubjectNullifier)
      !== BigInt(remediation.claimFact.claimSubjectNullifier)
  ) {
    context.addIssue({
      code: "custom",
      path: ["claimFactCommitment"],
      message: "Remediation does not bind the accepted Claim v6 fact.",
    });
  }
  if (remediationSubjectNullifierV2({
    claimSubjectNullifier: remediation.claimSubjectNullifier,
    remediationSecret: remediation.remediationSecret,
  }) !== remediation.remediationSubjectNullifier) {
    context.addIssue({
      code: "custom",
      path: ["remediationSubjectNullifier"],
      message: "Remediation subject nullifier does not match its private secret.",
    });
  }
  if (toHex(hashRecipientCommitment(
    remediation.recipientAddress,
    remediation.recipientSalt,
  )) !== remediation.recipientCommitment) {
    context.addIssue({
      code: "custom",
      path: ["recipientCommitment"],
      message: "Remediation recipient does not match the accepted private recipient commitment.",
    });
  }
  const expectedDecimals = remediation.token === "STRK" ? 18 : 6;
  if (
    remediation.tokenDecimals !== expectedDecimals
    || remediation.token !== remediation.claimFact.obligationToken
  ) {
    context.addIssue({
      code: "custom",
      path: ["token"],
      message: "Remediation token and decimals must match the accepted obligation.",
    });
  }
  if (remediationFactCommitmentV2({
    remediationSubjectNullifier: remediation.remediationSubjectNullifier,
    claimSubjectNullifier: remediation.claimSubjectNullifier,
    claimFactCommitment: remediation.claimFactCommitment,
    recipientCommitment: remediation.recipientCommitment,
    token: remediation.token,
    amountAtomic: remediation.amountAtomic,
    referenceValueAtomic: remediation.referenceValueAtomic,
    referenceUnit: remediation.referenceUnit,
    fxRoot: remediation.fxRoot,
  }) !== remediation.remediationFactCommitment) {
    context.addIssue({
      code: "custom",
      path: ["remediationFactCommitment"],
      message: "Remediation fact does not match its exact private payment.",
    });
  }
  const fxClaim = remediation.claimFact.claimKind === "below_committed_floor";
  if (
    (fxClaim && !remediation.fxEvidence)
    || (!fxClaim && remediation.fxEvidence !== undefined)
    || (remediation.fxEvidence !== undefined
      && remediation.fxEvidence.selectedFxIndex >= remediation.fxEvidence.snapshots.length)
    ||     (fxClaim && BigInt(remediation.fxRoot) === 0n)
    || (!fxClaim && BigInt(remediation.fxRoot) !== 0n)
    || (!fxClaim && remediation.referenceValueAtomic !== remediation.amountAtomic)
    || remediation.referenceUnit !== remediation.claimFact.shortfallUnit
    || BigInt(remediation.referenceValueAtomic)
      < BigInt(remediation.claimFact.shortfallAtomic)
  ) {
    context.addIssue({
      code: "custom",
      path: ["referenceValueAtomic"],
      message: "Remediation value does not cover the accepted typed shortfall.",
    });
  }
  const start = BigInt(remediation.validityStart);
  const expiry = BigInt(remediation.validityExpiry);
  if (expiry <= start || expiry - start > 3_600n) {
    context.addIssue({
      code: "custom",
      path: ["validityExpiry"],
      message: "Remediation authorization must expire within one hour.",
    });
  }
});

export type WageRemediationPrivate = z.infer<
  typeof wageRemediationPrivateSchema
>;

export const wageRemediationCreateSchema = z.object({
  id: uuidV7Schema,
  workerClaimId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  revision: z.literal(1),
  proofBundleId: uuidV7Schema,
  claimSubjectNullifier: commitmentSchema,
  claimFactCommitment: commitmentSchema,
  remediationSubjectNullifier: commitmentSchema,
  remediationFactCommitment: commitmentSchema,
  actionCommitment: commitmentSchema,
  fxRoot: commitmentSchema,
  validityExpiry: u64Schema,
  envelope: encryptedVaultRecordSchema,
}).strict().superRefine((remediation, context) => {
  if (
    remediation.envelope.aad.organizationId !== remediation.organizationId
    || remediation.envelope.aad.recordType !== "wage-remediation-v2"
    || remediation.envelope.aad.recordId !== remediation.id
    || remediation.envelope.aad.revision !== remediation.revision
  ) {
    context.addIssue({
      code: "custom",
      path: ["envelope"],
      message: "Wage remediation envelope AAD does not match its storage identity.",
    });
  }
  const recipients = remediation.envelope.wrappedKeys.map(
    ({ principalId }) => principalId,
  );
  if (recipients.length < 2 || new Set(recipients).size !== recipients.length) {
    context.addIssue({
      code: "custom",
      path: ["envelope", "wrappedKeys"],
      message: "Remediation must be encrypted to distinct claimant and employer principals.",
    });
  }
});

export type WageRemediationCreate = z.infer<
  typeof wageRemediationCreateSchema
>;

export const wageRemediationSummarySchema = z.object({
  id: uuidV7Schema,
  workerClaimId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  claimantPrincipalId: z.string().min(1).max(160),
  proofBundleId: uuidV7Schema,
  claimSubjectNullifier: commitmentSchema,
  claimFactCommitment: commitmentSchema,
  remediationSubjectNullifier: commitmentSchema,
  remediationFactCommitment: commitmentSchema,
  actionCommitment: commitmentSchema,
  fxRoot: commitmentSchema,
  validityExpiresAt: z.string().datetime(),
  state: wageRemediationStateSchema,
  settlementId: uuidV7Schema.nullable(),
  authorizedAt: z.string().datetime().nullable(),
  paymentConfirmedAt: z.string().datetime().nullable(),
  reconciledAt: z.string().datetime().nullable(),
  lastErrorCode: z.string().nullable(),
  lastErrorMessage: z.string().nullable(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  envelope: encryptedVaultRecordSchema,
}).strict();

export type WageRemediationSummary = z.infer<
  typeof wageRemediationSummarySchema
>;
