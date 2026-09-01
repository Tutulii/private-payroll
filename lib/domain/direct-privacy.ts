import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { agentExecutionRequestSchema } from "./capability";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  SETTLEMENT_MATCH_CIRCUIT_SHA256,
  SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";

const feltSchema = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/)
  .transform((value) => value as `0x${string}`);
const wireFeltSchema = z.string()
  .regex(/^(?:0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})|(?:0|[1-9]\d*))$/)
  .transform((value, context) => {
    const parsed = BigInt(value);
    const starkPrime = (1n << 251n) + 17n * (1n << 192n) + 1n;
    if (parsed >= starkPrime) {
      context.addIssue({ code: "custom", message: "Value is outside the Starknet field." });
      return z.NEVER;
    }
    return `0x${parsed.toString(16)}` as `0x${string}`;
  });
const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/)
  .transform((value) => value as `0x${string}`);
const uintStringSchema = z.string().regex(/^(?:0|[1-9]\d*)$/);
const blockIdentifierSchema = z.union([
  z.number().int().nonnegative(),
  z.enum(["latest", "pre_confirmed"]),
  z.object({ block_number: z.number().int().nonnegative() }).strict(),
  z.object({ block_hash: feltSchema }).strict(),
]);

export const directPrivacySecretsSchema = z.object({
  version: z.literal("payo-direct-privacy-secrets-v2"),
  sessionPrivateKey: commitmentSchema,
  proofPrincipal: z.object({
    principalId: z.string().min(8).max(160),
    publicKey: z.string().min(16).max(256),
    secretKey: z.string().min(16).max(256),
  }).strict(),
}).strict();
export type DirectPrivacySecrets = z.infer<typeof directPrivacySecretsSchema>;

/**
 * One durable viewing identity belongs to the private treasury address, not
 * to an individual short-lived capability. Keeping it separate prevents two
 * capabilities from discovering or spending the same note set with divergent
 * keys or state.
 */
export const directPrivacyTreasurySecretsSchema = z.object({
  version: z.literal("payo-direct-privacy-treasury-secrets-v1"),
  viewingKey: feltSchema,
}).strict();
export type DirectPrivacyTreasurySecrets = z.infer<typeof directPrivacyTreasurySecretsSchema>;

const serializedNoteSchema = z.object({
  id: feltSchema,
  amount: uintStringSchema,
  created: z.number().int().nonnegative().nullable(),
  witness: z.string().min(2).max(32_768),
  viewingKey: feltSchema.nullable(),
  sender: feltSchema,
  open: z.boolean(),
}).strict();

const addressNumberEntriesSchema = z.array(z.tuple([
  feltSchema,
  z.number().int().nonnegative(),
])).max(1_024);

export const serializedPrivateRegistrySchema = z.object({
  version: z.literal("payo-private-registry-v1"),
  channels: z.array(z.object({
    recipient: feltSchema,
    channel: z.string().min(2).max(65_536),
  }).strict()).max(1_024),
  notes: z.array(z.object({
    token: feltSchema,
    notes: z.array(serializedNoteSchema).max(4_096),
  }).strict()).max(64),
  cursor: z.object({
    blockId: blockIdentifierSchema,
    incomingChannels: z.array(z.object({
      sender: feltSchema,
      channelKey: feltSchema,
      subchannelIdIndex: z.number().int().nonnegative(),
      noteIndexes: addressNumberEntriesSchema,
      totalNoteCounts: addressNumberEntriesSchema,
    }).strict()).max(1_024),
  }).strict().nullable(),
  channelTotal: z.number().int().nonnegative().nullable(),
}).strict();
export type SerializedPrivateRegistry = z.infer<typeof serializedPrivateRegistrySchema>;

export const directPrivacyHistoryCursorSchema = z.object({
  subchannels: z.array(z.object({
    channelKey: feltSchema,
    token: feltSchema,
    channelKind: z.enum(["incoming", "outgoing", "self_channel"]),
    counterparty: feltSchema,
    nextIndex: z.number().int().nonnegative().nullable(),
  }).strict()).max(4_096),
  beginBlockNumber: z.number().int().nonnegative().nullable(),
  historyComplete: z.boolean(),
}).strict();

const directPrivacyHistoryNoteSchema = z.object({
  channelKind: z.enum(["incoming", "outgoing", "self_channel"]),
  token: feltSchema,
  noteIndex: z.number().int().nonnegative(),
  noteId: feltSchema,
  counterparty: feltSchema,
  amount: uintStringSchema,
  salt: feltSchema,
}).strict();

const directPrivacyHistoryDepositSchema = z.object({
  fromAddress: feltSchema,
  token: feltSchema,
  amount: uintStringSchema,
}).strict();

const directPrivacyHistoryWithdrawalSchema = z.object({
  toAddress: feltSchema,
  token: feltSchema,
  amount: uintStringSchema,
}).strict();

const directPrivacyHistoryOpenNoteDepositSchema = z.object({
  depositor: feltSchema,
  token: feltSchema,
  noteId: feltSchema,
  amount: uintStringSchema,
}).strict();

/**
 * Private transaction history is stored only inside the treasury ciphertext.
 * Its bounded shape prevents a compromised indexer from inflating encrypted
 * state without limit while retaining enough data for deterministic recovery.
 */
export const directPrivacyHistoryTransactionSchema = z.object({
  blockNumber: z.number().int().nonnegative(),
  transactionHash: feltSchema,
  notes: z.array(directPrivacyHistoryNoteSchema).max(256),
  deposits: z.array(directPrivacyHistoryDepositSchema).max(256),
  withdrawals: z.array(directPrivacyHistoryWithdrawalSchema).max(256),
  openNoteDeposits: z.array(directPrivacyHistoryOpenNoteDepositSchema).max(256),
  registeredPubkey: feltSchema.nullable(),
}).strict();
export type DirectPrivacyHistoryTransaction = z.infer<
  typeof directPrivacyHistoryTransactionSchema
>;

export const directPrivacyStateSchema = z.object({
  version: z.literal("payo-direct-privacy-state-v1"),
  registry: serializedPrivateRegistrySchema,
  historyCursor: directPrivacyHistoryCursorSchema.nullable(),
  historyPinnedBlock: z.object({
    number: z.number().int().nonnegative(),
    hash: feltSchema,
  }).strict().nullable().default(null),
  history: z.array(directPrivacyHistoryTransactionSchema).max(1_024).default([]),
  pinnedBlock: z.object({
    number: z.number().int().nonnegative(),
    hash: feltSchema,
  }).strict().nullable(),
}).strict();
export type DirectPrivacyState = z.infer<typeof directPrivacyStateSchema>;

export const directPrivacyAccountConfigSchema = z.object({
  version: z.literal("payo-direct-privacy-account-v1"),
  chainId: feltSchema,
  policyAccountAddress: feltSchema,
  policyId: feltSchema,
  sessionPublicKey: feltSchema,
  sealMode: z.union([z.literal(0), z.literal(1)]),
  proofVersion: z.number().int().positive(),
  schemaVersion: z.number().int().positive(),
  payrollPolicyRoot: commitmentSchema,
  tokenSetCommitment: feltSchema,
  recipientSetCommitment: feltSchema,
  purposeCommitment: feltSchema,
  amountLimitCommitment: feltSchema,
  authorizedRunsRoot: feltSchema,
  validAfterUnix: uintStringSchema,
  validBeforeUnix: uintStringSchema,
  periodSeconds: uintStringSchema,
  maxCallsPerPeriod: z.number().int().positive().max(4_294_967_295),
  maxCallCount: z.number().int().positive().max(4_294_967_295),
  poolAddress: feltSchema,
  sealAddress: feltSchema,
  tokenAddresses: z.object({
    STRK: feltSchema,
    USDC: feltSchema,
  }).strict(),
  sdkVersion: z.literal("0.14.3-rc.5"),
  sdkRevision: z.literal("66e3caae8c0201227a6719696d004e30d90aea65"),
}).strict();
export type DirectPrivacyAccountConfig = z.infer<typeof directPrivacyAccountConfigSchema>;

export function commitDirectPrivacyAccountConfig(
  input: DirectPrivacyAccountConfig,
): `0x${string}` {
  const config = directPrivacyAccountConfigSchema.parse(input);
  return hashCanonicalJson({ domain: "PAYO_DIRECT_PRIVACY_ACCOUNT_CONFIG_V1", config });
}

const directPrivacySdkProofSchema = z.object({
  data: z.string().min(16).max(5_000_000),
  proofFacts: z.array(feltSchema).min(1).max(256),
}).strict();

const directPrivacySettlementSchema = z.object({
  transactionReference: commitmentSchema,
  settlementRoot: commitmentSchema,
  encryptedPayrollWitness: encryptedVaultRecordSchema,
  encryptedSettlementWitness: encryptedVaultRecordSchema,
}).strict();

const directPrivacyPinnedBlockSchema = z.object({
  number: z.number().int().nonnegative(),
  hash: feltSchema,
}).strict();

/**
 * Exact SDK output persisted before SettlementMatch proving. Retries must use
 * this encrypted draft instead of regenerating note randomness or calldata.
 */
export const directPrivacyProofDraftSchema = z.object({
  version: z.literal("payo-direct-privacy-proof-draft-v1"),
  executionId: z.string().min(8).max(128),
  requestCommitment: commitmentSchema,
  poolCalldata: z.array(feltSchema).min(2).max(12_000),
  sdkProof: directPrivacySdkProofSchema,
  settlement: directPrivacySettlementSchema,
  proofValidAfterUnix: uintStringSchema,
  proofValidBeforeUnix: uintStringSchema,
  nextState: directPrivacyStateSchema,
  expectedStateVersion: z.number().int().positive(),
  pinnedBlock: directPrivacyPinnedBlockSchema,
}).strict();
export type DirectPrivacyProofDraft = z.infer<typeof directPrivacyProofDraftSchema>;

export function commitDirectPrivacyProofDraft(input: DirectPrivacyProofDraft): `0x${string}` {
  const draft = directPrivacyProofDraftSchema.parse(input);
  return hashCanonicalJson({ domain: "PAYO_DIRECT_PRIVACY_PROOF_DRAFT_V1", draft });
}

export const directPrivacyPreparationSchema = z.object({
  version: z.literal("payo-direct-privacy-preparation-v1"),
  executionId: z.string().min(8).max(128),
  requestCommitment: commitmentSchema,
  policyCall: z.object({
    contractAddress: feltSchema,
    entrypoint: z.literal("execute_policy_intent"),
    calldata: z.array(feltSchema).min(20).max(4_904),
  }).strict(),
  outsideCall: z.object({
    contractAddress: feltSchema,
    entrypoint: z.literal("execute_from_outside_v2"),
    // Starknet.js emits compiled Cairo calldata as decimal strings. Normalize
    // it once before encryption so retries compare and submit one canonical
    // outside authorization regardless of JSON/RPC number formatting.
    calldata: z.array(wireFeltSchema).min(1).max(5_000),
  }).strict(),
  sdkProof: directPrivacySdkProofSchema,
  settlement: directPrivacySettlementSchema,
  proofValidAfterUnix: uintStringSchema,
  proofValidBeforeUnix: uintStringSchema,
  nextState: directPrivacyStateSchema,
  expectedStateVersion: z.number().int().positive(),
  pinnedBlock: directPrivacyPinnedBlockSchema,
  feeEstimateAtomic: uintStringSchema,
}).strict().superRefine((preparation, context) => {
  if (BigInt(preparation.outsideCall.contractAddress) !== BigInt(preparation.policyCall.contractAddress)) {
    context.addIssue({
      code: "custom",
      path: ["outsideCall", "contractAddress"],
      message: "The outside authorization must target the configured policy account.",
    });
  }
});
export type DirectPrivacyPreparation = z.infer<typeof directPrivacyPreparationSchema>;

export function commitDirectPrivacyPreparation(
  input: DirectPrivacyPreparation,
): `0x${string}` {
  const preparation = directPrivacyPreparationSchema.parse(input);
  return hashCanonicalJson({ domain: "PAYO_DIRECT_PRIVACY_PREPARATION_V1", preparation });
}

const resourceBoundSchema = z.object({
  max_amount: feltSchema,
  max_price_per_unit: feltSchema,
}).strict();

export const directPrivacySignedTransactionSchema = z.object({
  type: z.literal("INVOKE"),
  sender_address: feltSchema,
  calldata: z.array(feltSchema).min(1).max(12_000),
  signature: z.array(feltSchema).min(1).max(64),
  nonce: feltSchema,
  resource_bounds: z.object({
    l1_gas: resourceBoundSchema,
    l1_data_gas: resourceBoundSchema,
    l2_gas: resourceBoundSchema,
  }).strict(),
  tip: feltSchema,
  paymaster_data: z.array(feltSchema).max(256),
  nonce_data_availability_mode: z.enum(["L1", "L2"]),
  fee_data_availability_mode: z.enum(["L1", "L2"]),
  account_deployment_data: z.array(feltSchema).max(256),
  version: z.literal("0x3"),
  proof_facts: z.array(feltSchema).min(1).max(256),
  proof: z.string().min(1).max(5_000_000),
}).strict();
export type DirectPrivacySignedTransaction = z.infer<typeof directPrivacySignedTransactionSchema>;

export const directPrivacyPreparedSubmissionSchema = z.object({
  version: z.literal("payo-direct-privacy-submission-v1"),
  executionId: z.string().min(8).max(128),
  requestCommitment: commitmentSchema,
  expectedTransactionHash: feltSchema,
  signedTransaction: directPrivacySignedTransactionSchema,
  settlement: directPrivacyPreparationSchema.shape.settlement,
  proofValidAfterUnix: uintStringSchema,
  proofValidBeforeUnix: uintStringSchema,
  nextState: directPrivacyStateSchema,
  expectedStateVersion: z.number().int().positive(),
  pinnedBlock: z.object({
    number: z.number().int().nonnegative(),
    hash: feltSchema,
  }).strict(),
  feeEstimateAtomic: uintStringSchema,
}).strict();
export type DirectPrivacyPreparedSubmission = z.infer<typeof directPrivacyPreparedSubmissionSchema>;

export function commitDirectPrivacyPreparedSubmission(
  input: DirectPrivacyPreparedSubmission,
): `0x${string}` {
  const submission = directPrivacyPreparedSubmissionSchema.parse(input);
  return hashCanonicalJson({ domain: "PAYO_DIRECT_PRIVACY_SUBMISSION_V1", submission });
}

const settlementUnsignedSchema = z.string().regex(/^(?:0|[1-9][0-9]*)$/);
const settlementProofPublicInputsSchema = z.object({
  proofVersion: settlementUnsignedSchema,
  manifestRootHigh: settlementUnsignedSchema,
  manifestRootLow: settlementUnsignedSchema,
  runNullifierHigh: settlementUnsignedSchema,
  runNullifierLow: settlementUnsignedSchema,
  transactionReferenceHigh: settlementUnsignedSchema,
  transactionReferenceLow: settlementUnsignedSchema,
  settlementRootHigh: settlementUnsignedSchema,
  settlementRootLow: settlementUnsignedSchema,
  chunkIndex: settlementUnsignedSchema,
  chunkCount: settlementUnsignedSchema,
}).strict();

const settlementMatchProofSchema = z.object({
  version: z.literal(8),
  type: z.literal("settlement-proof-complete"),
  requestId: z.string().min(8).max(128),
  scheme: z.literal("ultra_keccak_zk_honk"),
  circuitSha256: z.literal(SETTLEMENT_MATCH_CIRCUIT_SHA256),
  verificationKeySha256: z.literal(SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256),
  settlementRoot: commitmentSchema,
  transactionReference: commitmentSchema,
  provingTimeMs: z.number().int().nonnegative(),
  chunks: z.array(z.object({
    chunkIndex: z.number().int().nonnegative().max(16),
    chunkCount: z.number().int().min(1).max(17),
    proofCalldata: z.array(feltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    calldataHash: feltSchema,
    publicInputs: settlementProofPublicInputsSchema,
  }).strict()).min(1).max(17),
}).strict();

function digestFromLimbs(high: string, low: string): string {
  return "0x" + ((BigInt(high) << 128n) | BigInt(low)).toString(16).padStart(64, "0");
}

export const directPrivacyReconciliationProofSchema = z.object({
  version: z.literal("payo-direct-privacy-reconciliation-proof-v1"),
  executionId: z.string().min(8).max(128),
  requestCommitment: commitmentSchema,
  proof: settlementMatchProofSchema,
}).strict().superRefine((value, context) => {
  const proof = value.proof;
  const first = proof.chunks[0];
  if (
    proof.requestId !== value.executionId
    || proof.chunks.length !== first.chunkCount
  ) {
    context.addIssue({ code: "custom", path: ["proof"], message: "Settlement proof request or chunk count is not bound." });
    return;
  }
  for (let index = 0; index < proof.chunks.length; index += 1) {
    const chunk = proof.chunks[index];
    const inputs = chunk.publicInputs;
    if (
      chunk.chunkIndex !== index
      || chunk.chunkCount !== proof.chunks.length
      || BigInt(inputs.proofVersion) !== 8n
      || BigInt(inputs.chunkIndex) !== BigInt(index)
      || BigInt(inputs.chunkCount) !== BigInt(proof.chunks.length)
      || digestFromLimbs(inputs.settlementRootHigh, inputs.settlementRootLow)
        !== proof.settlementRoot.toLowerCase()
      || digestFromLimbs(
        inputs.transactionReferenceHigh,
        inputs.transactionReferenceLow,
      ) !== proof.transactionReference.toLowerCase()
      || BigInt(chunk.calldataHash) !== BigInt(hashProofCalldata(chunk.proofCalldata))
      || BigInt(inputs.manifestRootHigh) !== BigInt(first.publicInputs.manifestRootHigh)
      || BigInt(inputs.manifestRootLow) !== BigInt(first.publicInputs.manifestRootLow)
      || BigInt(inputs.runNullifierHigh) !== BigInt(first.publicInputs.runNullifierHigh)
      || BigInt(inputs.runNullifierLow) !== BigInt(first.publicInputs.runNullifierLow)
    ) {
      context.addIssue({
        code: "custom",
        path: ["proof", "chunks", index],
        message: "Settlement proof chunks are not one canonical, fully bound sequence.",
      });
    }
  }
});
export type DirectPrivacyReconciliationProof = z.infer<
  typeof directPrivacyReconciliationProofSchema
>;

export function commitDirectPrivacyReconciliationProof(
  input: DirectPrivacyReconciliationProof,
) {
  const payload = directPrivacyReconciliationProofSchema.parse(input);
  return hashCanonicalJson({
    domain: "PAYO_DIRECT_PRIVACY_RECONCILIATION_PROOF_V1",
    payload,
  });
}

export const directPrivacyFinalizationSignedTransactionSchema =
  directPrivacySignedTransactionSchema.omit({
    proof_facts: true,
    proof: true,
  }).extend({
    proof_facts: z.array(feltSchema).max(256).optional(),
    proof: z.string().max(5_000_000).optional(),
  }).strict();

export const directPrivacyFinalizationSubmissionSchema = z.object({
  version: z.literal("payo-direct-privacy-finalization-v1"),
  executionId: z.string().min(8).max(128),
  requestCommitment: commitmentSchema,
  chunkIndex: z.number().int().nonnegative().max(16),
  chunkCount: z.number().int().min(1).max(17),
  calldataHash: feltSchema,
  expectedTransactionHash: feltSchema,
  signedTransaction: directPrivacyFinalizationSignedTransactionSchema,
}).strict();
export type DirectPrivacyFinalizationSubmission = z.infer<
  typeof directPrivacyFinalizationSubmissionSchema
>;

export function commitDirectPrivacyFinalizationSubmission(
  input: DirectPrivacyFinalizationSubmission,
) {
  const submission = directPrivacyFinalizationSubmissionSchema.parse(input);
  return hashCanonicalJson({
    domain: "PAYO_DIRECT_PRIVACY_FINALIZATION_V1",
    submission,
  });
}

const payrollPublicInputSchema = z.object({
  chainId: uintStringSchema.or(feltSchema),
  sealAddress: uintStringSchema.or(feltSchema),
  proofVersion: uintStringSchema.or(feltSchema),
  schemaVersion: uintStringSchema.or(feltSchema),
  agreementRootHigh: uintStringSchema.or(feltSchema),
  agreementRootLow: uintStringSchema.or(feltSchema),
  manifestRootHigh: uintStringSchema.or(feltSchema),
  manifestRootLow: uintStringSchema.or(feltSchema),
  policyRootHigh: uintStringSchema.or(feltSchema),
  policyRootLow: uintStringSchema.or(feltSchema),
  fxRootHigh: uintStringSchema.or(feltSchema),
  fxRootLow: uintStringSchema.or(feltSchema),
  runNullifierHigh: uintStringSchema.or(feltSchema),
  runNullifierLow: uintStringSchema.or(feltSchema),
  validityStart: uintStringSchema.or(feltSchema),
  validityExpiry: uintStringSchema.or(feltSchema),
  shardIndex: uintStringSchema.or(feltSchema),
}).strict();

const directPayrollShardSchema = z.object({
  shardIndex: z.union([z.literal(0), z.literal(1)]),
  proofCalldata: z.array(feltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
  calldataHash: feltSchema,
  publicInputs: payrollPublicInputSchema,
}).strict();

/** Exact randomized PayrollIntegrity calldata retained before any precommit. */
export const directPrivacyPayrollAuthorizationSchema = z.object({
  version: z.literal("payo-direct-payroll-authorization-v1"),
  executionId: z.string().min(8).max(128),
  requestCommitment: commitmentSchema,
  circuitSha256: z.union([
    z.literal(PAYROLL_INTEGRITY_CIRCUIT_SHA256),
    z.literal(ADVANCED_OBLIGATION_CIRCUIT_SHA256),
  ]),
  precommitCall: z.object({
    contractAddress: feltSchema,
    entrypoint: z.literal("precommit_direct"),
    calldata: z.array(feltSchema).length(16),
  }).strict(),
  shards: z.tuple([
    directPayrollShardSchema.extend({ shardIndex: z.literal(0) }),
    directPayrollShardSchema.extend({ shardIndex: z.literal(1) }),
  ]),
}).strict().superRefine((authorization, context) => {
  const [zero, one] = authorization.shards;
  const orderedKeys = [
    "chainId", "sealAddress", "proofVersion", "schemaVersion",
    "agreementRootHigh", "agreementRootLow", "manifestRootHigh", "manifestRootLow",
    "policyRootHigh", "policyRootLow", "fxRootHigh", "fxRootLow",
    "runNullifierHigh", "runNullifierLow", "validityStart", "validityExpiry",
  ] as const;
  const mismatch = orderedKeys.find((key) =>
    BigInt(zero.publicInputs[key]) !== BigInt(one.publicInputs[key]));
  const expectedPrecommit = [
    zero.publicInputs.proofVersion,
    zero.publicInputs.schemaVersion,
    zero.publicInputs.agreementRootHigh,
    zero.publicInputs.agreementRootLow,
    zero.publicInputs.manifestRootHigh,
    zero.publicInputs.manifestRootLow,
    zero.publicInputs.policyRootHigh,
    zero.publicInputs.policyRootLow,
    zero.publicInputs.fxRootHigh,
    zero.publicInputs.fxRootLow,
    zero.publicInputs.runNullifierHigh,
    zero.publicInputs.runNullifierLow,
    zero.publicInputs.validityStart,
    zero.publicInputs.validityExpiry,
    zero.calldataHash,
    one.calldataHash,
  ];
  if (
    mismatch
    || BigInt(zero.publicInputs.shardIndex) !== 0n
    || BigInt(one.publicInputs.shardIndex) !== 1n
    || BigInt(authorization.precommitCall.contractAddress)
      !== BigInt(zero.publicInputs.sealAddress)
    || authorization.precommitCall.calldata.some((value, index) =>
      BigInt(value) !== BigInt(expectedPrecommit[index]))
    || BigInt(zero.calldataHash) !== BigInt(hashProofCalldata(zero.proofCalldata))
    || BigInt(one.calldataHash) !== BigInt(hashProofCalldata(one.proofCalldata))
  ) context.addIssue({
    code: "custom",
    path: ["shards"],
    message: "Payroll authorization is not one canonical, linked and hash-bound proof.",
  });
});
export type DirectPrivacyPayrollAuthorization = z.infer<
  typeof directPrivacyPayrollAuthorizationSchema
>;

export function commitDirectPrivacyPayrollAuthorization(
  input: DirectPrivacyPayrollAuthorization,
): `0x${string}` {
  const authorization = directPrivacyPayrollAuthorizationSchema.parse(input);
  return hashCanonicalJson({
    domain: "PAYO_DIRECT_PAYROLL_AUTHORIZATION_V1",
    authorization,
  });
}

export const directPrivacyRunMaterialSchema = z.object({
  version: z.literal("payo-direct-privacy-run-v1"),
  organizationId: z.string().min(8).max(128),
  capabilityId: z.string().min(8).max(128),
  runId: z.string().min(8).max(128),
  runVersion: z.number().int().positive(),
  requestCommitment: commitmentSchema,
  authoritativeRequest: agentExecutionRequestSchema,
  encryptedWitness: encryptedVaultRecordSchema,
  policyRun: z.object({
    agreementRoot: commitmentSchema,
    manifestRoot: commitmentSchema,
    runNullifier: commitmentSchema,
    pathBits: z.number().int().min(0).max(255),
    siblings: z.array(feltSchema).length(8),
  }).strict(),
}).strict().superRefine((material, context) => {
  if (material.authoritativeRequest.runId !== material.runId) {
    context.addIssue({
      code: "custom",
      path: ["authoritativeRequest", "runId"],
      message: "The authoritative request must bind this run.",
    });
  }
  if (hashCanonicalJson({
    domain: "PAYO_AGENT_EXECUTION_REQUEST_V1",
    request: material.authoritativeRequest,
  }).toLowerCase() !== material.requestCommitment.toLowerCase()) {
    context.addIssue({
      code: "custom",
      path: ["requestCommitment"],
      message: "The authoritative execution commitment does not match.",
    });
  }
  const first = material.authoritativeRequest.intents[0];
  if (
    first.organizationId !== material.organizationId
    || first.runId !== material.runId
  ) {
    context.addIssue({
      code: "custom",
      path: ["authoritativeRequest"],
      message: "The authoritative request crosses a run or organization boundary.",
    });
  }
});
export type DirectPrivacyRunMaterial = z.infer<typeof directPrivacyRunMaterialSchema>;

export function commitDirectPrivacyRunMaterial(
  input: DirectPrivacyRunMaterial,
): `0x${string}` {
  const material = directPrivacyRunMaterialSchema.parse(input);
  return hashCanonicalJson({ domain: "PAYO_DIRECT_PRIVACY_RUN_V1", material });
}

export function emptyDirectPrivacyState(): DirectPrivacyState {
  return {
    version: "payo-direct-privacy-state-v1",
    registry: {
      version: "payo-private-registry-v1",
      channels: [],
      notes: [],
      cursor: null,
      channelTotal: null,
    },
    historyCursor: null,
    historyPinnedBlock: null,
    history: [],
    pinnedBlock: null,
  };
}
