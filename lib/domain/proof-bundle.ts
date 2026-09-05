import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256,
  OBLIGATION_SNAPSHOT_LINK_VERIFICATION_KEY_SHA256,
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
  WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256,
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { universalPayrollBookEntrySchema } from "./universal-payroll-book";
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

export const exceptionProofPublicInputsSchema = z.object({
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
  subjectNullifierHigh: uintStringSchema,
  subjectNullifierLow: uintStringSchema,
  parentNullifierHigh: uintStringSchema,
  parentNullifierLow: uintStringSchema,
  factCommitmentHigh: uintStringSchema,
  factCommitmentLow: uintStringSchema,
  parentFactCommitmentHigh: uintStringSchema,
  parentFactCommitmentLow: uintStringSchema,
  validityStart: uintStringSchema,
  validityExpiry: uintStringSchema,
  shardIndex: uintStringSchema,
}).strict();

export const exceptionProofBundleMetadataSchema = z.object({
  schemaVersion: z.literal(2),
  envelopeRecordId: uuidV7Schema,
  envelopeRevision: z.number().int().positive(),
  proofType: z.enum(["obligation_snapshot", "wage_claim", "wage_remediation"]),
  subjectRecordId: uuidV7Schema,
  proofVersion: z.enum(["5", "6", "7"]),
  circuitSha256: commitmentSchema,
  verificationKeySha256: commitmentSchema,
  publicInputsHash: commitmentSchema,
  publicInputs: exceptionProofPublicInputsSchema,
  proofCalldataHash: starknetFeltSchema,
}).strict();

export const encryptedExceptionProofBundleCreateSchema = z.object({
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  revision: z.number().int().positive(),
  proofType: z.enum(["obligation_snapshot", "wage_claim", "wage_remediation"]),
  subjectRecordId: uuidV7Schema,
  proofVersion: z.enum(["5", "6", "7"]),
  circuitSha256: commitmentSchema,
  verificationKeySha256: commitmentSchema,
  publicInputsHash: commitmentSchema,
  publicInputs: exceptionProofPublicInputsSchema,
  proofCalldataHash: starknetFeltSchema,
  envelope: encryptedVaultRecordSchema,
}).strict().superRefine((bundle, context) => {
  const profile = bundle.proofVersion === "5" ? {
    proofType: "obligation_snapshot",
    circuit: OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256,
    verificationKey: OBLIGATION_SNAPSHOT_LINK_VERIFICATION_KEY_SHA256,
  } : bundle.proofVersion === "6" ? {
    proofType: "wage_claim",
    circuit: WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
    verificationKey: WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256,
  } : {
    proofType: "wage_remediation",
    circuit: WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
    verificationKey: WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256,
  } as const;
  if (bundle.proofType !== profile.proofType) {
    context.addIssue({ code: "custom", path: ["proofType"], message: "Proof type does not match vNext proof version." });
  }
  if (bundle.circuitSha256 !== profile.circuit) {
    context.addIssue({ code: "custom", path: ["circuitSha256"], message: "vNext circuit digest is not pinned." });
  }
  if (bundle.verificationKeySha256 !== profile.verificationKey) {
    context.addIssue({ code: "custom", path: ["verificationKeySha256"], message: "vNext verification key digest is not pinned." });
  }
  if (
    bundle.publicInputs.proofVersion !== bundle.proofVersion
    || bundle.publicInputs.schemaVersion !== "2"
    || bundle.publicInputs.shardIndex !== "0"
  ) {
    context.addIssue({ code: "custom", path: ["publicInputs"], message: "vNext public-input ABI does not match the bundle." });
  }
});

export type EncryptedExceptionProofBundleCreate = z.infer<
  typeof encryptedExceptionProofBundleCreateSchema
>;

export const encryptedPayoProofBundleCreateSchema = z.union([
  encryptedPayrollIntegrityBundleCreateSchema,
  encryptedExceptionProofBundleCreateSchema,
]);

export type EncryptedPayoProofBundleCreate = z.infer<
  typeof encryptedPayoProofBundleCreateSchema
>;

export const payrollProofCalldataSchema = z
  .array(starknetFeltSchema)
  .min(35)
  .max(PAYO_MAX_PROOF_CALLDATA_FELTS);

export const exceptionProofCalldataSchema = z
  .array(starknetFeltSchema)
  .min(35)
  .max(PAYO_MAX_PROOF_CALLDATA_FELTS);

export const proofVerificationRequestSchema = z.object({
  proofBundleId: uuidV7Schema,
  shards: z.tuple([payrollProofCalldataSchema, payrollProofCalldataSchema]),
}).strict();

export type ProofVerificationRequest = z.infer<typeof proofVerificationRequestSchema>;

export const payrollAuthorizationRequestSchema = z.object({
  payrollProofBundleId: uuidV7Schema,
  snapshotProofBundleId: uuidV7Schema,
  payrollShards: z.tuple([payrollProofCalldataSchema, payrollProofCalldataSchema]),
  snapshotProof: exceptionProofCalldataSchema,
}).strict();

export type PayrollAuthorizationRequest = z.infer<typeof payrollAuthorizationRequestSchema>;

export const vestingTransitionPublicInputsSchema = z.object({
  chainId: starknetFeltSchema,
  sealAddress: starknetAddressSchema,
  proofVersion: z.literal("3"),
  schemaVersion: z.literal("1"),
  entryKind: z.enum(["0", "1", "2", "3", "4"]),
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
  subjectNullifierHigh: uintStringSchema,
  subjectNullifierLow: uintStringSchema,
  parentFactHigh: uintStringSchema,
  parentFactLow: uintStringSchema,
  factHigh: uintStringSchema,
  factLow: uintStringSchema,
  ownerAddress: uintStringSchema,
  sourceSealAddress: uintStringSchema,
  sourceProofVersion: uintStringSchema,
  attestationRootHigh: uintStringSchema,
  attestationRootLow: uintStringSchema,
  shard0ContributorCount: uintStringSchema,
  shard1ContributorCount: uintStringSchema,
  totalsDisclosed: z.enum(["0", "1"]),
  totalsCommitmentHigh: uintStringSchema,
  totalsCommitmentLow: uintStringSchema,
  shard0StrkGross: uintStringSchema,
  shard0StrkDeductions: uintStringSchema,
  shard0StrkNet: uintStringSchema,
  shard0UsdcGross: uintStringSchema,
  shard0UsdcDeductions: uintStringSchema,
  shard0UsdcNet: uintStringSchema,
  shard1StrkGross: uintStringSchema,
  shard1StrkDeductions: uintStringSchema,
  shard1StrkNet: uintStringSchema,
  shard1UsdcGross: uintStringSchema,
  shard1UsdcDeductions: uintStringSchema,
  shard1UsdcNet: uintStringSchema,
  scheduleIdHigh: uintStringSchema,
  scheduleIdLow: uintStringSchema,
  previousStateHigh: uintStringSchema,
  previousStateLow: uintStringSchema,
  nextStateHigh: uintStringSchema,
  nextStateLow: uintStringSchema,
  releaseNullifierHigh: uintStringSchema,
  releaseNullifierLow: uintStringSchema,
  bookEntryHigh: uintStringSchema,
  bookEntryLow: uintStringSchema,
  periodStart: uintStringSchema,
  periodEnd: uintStringSchema,
  validityStart: uintStringSchema,
  validityExpiry: uintStringSchema,
  shardIndex: z.enum(["0", "1"]),
}).strict();

const vestingAuthorizationShardSchema = z.object({
  shardIndex: z.union([z.literal(0), z.literal(1)]),
  proofCalldata: payrollProofCalldataSchema,
  calldataHash: starknetFeltSchema,
  publicInputs: vestingTransitionPublicInputsSchema,
}).strict();

export const vestingBookProofSubmissionSchema = z.object({
  proofVersion: z.literal(3),
  entryKind: z.enum(["ordinary", "vesting", "agent", "claim", "remediation"]),
  circuitSha256: z.literal(VESTING_TRANSITION_CIRCUIT_SHA256),
  verificationKeySha256: z.literal(VESTING_TRANSITION_VERIFICATION_KEY_SHA256),
  scheduleId: commitmentSchema,
  previousStateCommitment: commitmentSchema,
  nextStateCommitment: commitmentSchema,
  releaseNullifier: commitmentSchema,
  bookEntry: universalPayrollBookEntrySchema,
  bookEntryCommitment: commitmentSchema,
  shards: z.tuple([vestingAuthorizationShardSchema, vestingAuthorizationShardSchema]),
}).strict().superRefine((proof, context) => {
  if (
    proof.shards[0].shardIndex !== 0
    || proof.shards[1].shardIndex !== 1
    || proof.shards[0].publicInputs.shardIndex !== "0"
    || proof.shards[1].publicInputs.shardIndex !== "1"
  ) {
    context.addIssue({ code: "custom", path: ["shards"], message: "Vesting proof shards are not ordered." });
  }
});

export const exceptionAuthorizationRequestSchema = z.object({
  proofCalldata: exceptionProofCalldataSchema,
  vestingBook: vestingBookProofSubmissionSchema,
}).strict();

export type ExceptionAuthorizationRequest = z.infer<typeof exceptionAuthorizationRequestSchema>;

export const vestingAuthorizationRequestSchema = z.object({
  payrollProofBundleId: uuidV7Schema,
  payrollShards: z.tuple([payrollProofCalldataSchema, payrollProofCalldataSchema]),
  vestingBook: vestingBookProofSubmissionSchema,
}).strict();

export type VestingAuthorizationRequest = z.infer<typeof vestingAuthorizationRequestSchema>;
