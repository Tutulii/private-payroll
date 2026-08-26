import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
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
  proofType: z.enum(["payroll_integrity", "wage_claim", "wage_remediation"]),
  subjectRecordId: uuidV7Schema,
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
  proofType: z.enum(["payroll_integrity", "wage_claim", "wage_remediation"]),
  subjectRecordId: uuidV7Schema,
  proofVersion: z.string().regex(/^[1-9]\d{0,9}$/),
  circuitSha256: commitmentSchema,
  verificationKeySha256: commitmentSchema,
  publicInputsHash: commitmentSchema,
  commonInputs: payrollIntegrityCommonInputsSchema,
  shardCalldataHashes: z.tuple([starknetFeltSchema, starknetFeltSchema]),
  envelope: encryptedVaultRecordSchema,
}).strict().superRefine((bundle, context) => {
  const profile = bundle.proofVersion === "1" ? {
    circuit: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    verificationKey: PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  } : bundle.proofVersion === "2" ? {
    circuit: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
    verificationKey: ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  } : bundle.proofVersion === "3" ? {
    circuit: WAGE_CLAIM_CIRCUIT_SHA256,
    verificationKey: WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  } : bundle.proofVersion === "4" ? {
    circuit: WAGE_REMEDIATION_CIRCUIT_SHA256,
    verificationKey: WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  } : undefined;
  if (!profile || bundle.circuitSha256 !== profile.circuit) {
    context.addIssue({ code: "custom", path: ["circuitSha256"], message: "Circuit digest is not deployment-bound." });
  }
  if (!profile || bundle.verificationKeySha256 !== profile.verificationKey) {
    context.addIssue({ code: "custom", path: ["verificationKeySha256"], message: "Verification key digest is not deployment-bound." });
  }
  if (bundle.commonInputs.proofVersion !== bundle.proofVersion) {
    context.addIssue({ code: "custom", path: ["proofVersion"], message: "Proof version does not match public inputs." });
  }
  const expectedType = bundle.proofVersion === "3"
    ? "wage_claim"
    : bundle.proofVersion === "4"
      ? "wage_remediation"
      : "payroll_integrity";
  if (bundle.proofType !== expectedType) {
    context.addIssue({ code: "custom", path: ["proofType"], message: "Proof type does not match proof version." });
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
  .max(PAYO_MAX_PROOF_CALLDATA_FELTS);

export const proofVerificationRequestSchema = z.object({
  proofBundleId: uuidV7Schema,
  shards: z.tuple([payrollProofCalldataSchema, payrollProofCalldataSchema]),
}).strict();

export type ProofVerificationRequest = z.infer<typeof proofVerificationRequestSchema>;
