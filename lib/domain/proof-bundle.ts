import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import {
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { commitmentSchema, starknetAddressSchema, uuidV7Schema } from "./records";

export const starknetFeltSchema = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,62})$/);
const uintStringSchema = z.string().regex(/^(?:0|[1-9]\d*)$/);

export const payrollIntegrityCommonInputsSchema = z.object({
  chainId: starknetFeltSchema,
  sealAddress: starknetAddressSchema,
  proofVersion: uintStringSchema,
  schemaVersion: uintStringSchema,
  agreementRootHigh: uintStringSchema,
  agreementRootLow: uintStringSchema,
  manifestRootHigh: uintStringSchema,
  manifestRootLow: uintStringSchema,
  policyRootHigh: uintStringSchema,
  policyRootLow: uintStringSchema,
  fxRootHigh: uintStringSchema,
  fxRootLow: uintStringSchema,
  runNullifierHigh: uintStringSchema,
  runNullifierLow: uintStringSchema,
  validityStart: uintStringSchema,
  validityExpiry: uintStringSchema,
}).strict();

export const payrollIntegrityBundleMetadataSchema = z.object({
  schemaVersion: z.literal(1),
  envelopeRecordId: uuidV7Schema,
  envelopeRevision: z.number().int().positive(),
  proofType: z.literal("payroll_integrity"),
  proofVersion: z.string().regex(/^[1-9]\d{0,9}$/),
  circuitSha256: commitmentSchema,
  verificationKeySha256: commitmentSchema,
  publicInputsHash: commitmentSchema,
  commonInputs: payrollIntegrityCommonInputsSchema,
  shardCalldataHashes: z.tuple([starknetFeltSchema, starknetFeltSchema]),
}).strict();

export const encryptedPayrollIntegrityBundleCreateSchema = z.object({
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  revision: z.number().int().positive(),
  proofType: z.literal("payroll_integrity"),
  proofVersion: z.string().regex(/^[1-9]\d{0,9}$/),
  circuitSha256: commitmentSchema,
  verificationKeySha256: commitmentSchema,
  publicInputsHash: commitmentSchema,
  commonInputs: payrollIntegrityCommonInputsSchema,
  shardCalldataHashes: z.tuple([starknetFeltSchema, starknetFeltSchema]),
  envelope: encryptedVaultRecordSchema,
}).strict().superRefine((bundle, context) => {
  if (bundle.circuitSha256 !== PAYROLL_INTEGRITY_CIRCUIT_SHA256) {
    context.addIssue({ code: "custom", path: ["circuitSha256"], message: "Circuit digest is not deployment-bound." });
  }
  if (bundle.verificationKeySha256 !== PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256) {
    context.addIssue({ code: "custom", path: ["verificationKeySha256"], message: "Verification key digest is not deployment-bound." });
  }
  if (bundle.commonInputs.proofVersion !== bundle.proofVersion) {
    context.addIssue({ code: "custom", path: ["proofVersion"], message: "Proof version does not match public inputs." });
  }
  if (bundle.commonInputs.schemaVersion !== "1") {
    context.addIssue({ code: "custom", path: ["commonInputs", "schemaVersion"], message: "Only schema version 1 is supported." });
  }
});

export type EncryptedPayrollIntegrityBundleCreate = z.infer<
  typeof encryptedPayrollIntegrityBundleCreateSchema
>;

export const payrollProofCalldataSchema = z
  .array(starknetFeltSchema)
  .min(35)
  .max(5_000);

export const proofVerificationRequestSchema = z.object({
  proofBundleId: uuidV7Schema,
  shards: z.tuple([payrollProofCalldataSchema, payrollProofCalldataSchema]),
}).strict();

export type ProofVerificationRequest = z.infer<typeof proofVerificationRequestSchema>;
