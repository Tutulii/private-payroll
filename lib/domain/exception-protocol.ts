import { keccak_256 } from "@noble/hashes/sha3.js";
import { z } from "zod";
import {
  concatBytes,
  encodeUint,
  normalizedHexBytes,
  toHex,
  utf8,
} from "@/lib/crypto/encoding";

export const PAYO_EXCEPTION_SCHEMA_VERSION = 2 as const;

export const PAYO_EXCEPTION_PROOF_VERSIONS = Object.freeze({
  payroll: 5,
  claim: 6,
  remediation: 7,
});

export const claimEvidenceSources = Object.freeze({
  unsettled_period: 0,
  payo_run: 1,
  employer_statement: 2,
  settlement_match: 3,
});

export const claimShortfallUnits = Object.freeze({
  strk_atomic: 0,
  usdc_atomic: 1,
  usd_6: 2,
  gbp_6: 3,
});

export const exceptionClaimKinds = Object.freeze({
  missing_obligation: 0,
  below_committed_floor: 1,
  incomplete_final_pay: 2,
});

export const exceptionTokens = Object.freeze({
  STRK: 0,
  USDC: 1,
});

export type ExceptionClaimKind = keyof typeof exceptionClaimKinds;
export type ClaimEvidenceSource = keyof typeof claimEvidenceSources;
export type ClaimShortfallUnit = keyof typeof claimShortfallUnits;
export type ExceptionToken = keyof typeof exceptionTokens;

const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const starknetAddressSchema = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const u64StringSchema = z.string().regex(/^(0|[1-9][0-9]*)$/).refine(
  (value) => BigInt(value) < 1n << 64n,
  "Value must fit in u64.",
);
const positiveU128StringSchema = z.string().regex(/^[1-9][0-9]*$/).refine(
  (value) => BigInt(value) < 1n << 128n,
  "Value must fit in a positive u128.",
);

export const obligationSnapshotV2Schema = z.object({
  schemaVersion: z.literal(PAYO_EXCEPTION_SCHEMA_VERSION),
  runNullifier: commitmentSchema,
  baseAgreementRoot: commitmentSchema,
  obligationRoot: commitmentSchema,
  policyRoot: commitmentSchema,
  ownerAddress: starknetAddressSchema,
  dueAt: u64StringSchema,
  graceEndsAt: u64StringSchema,
  claimEndsAt: u64StringSchema,
  availabilityCommitment: commitmentSchema,
}).strict().superRefine((snapshot, context) => {
  const dueAt = BigInt(snapshot.dueAt);
  const graceEndsAt = BigInt(snapshot.graceEndsAt);
  const claimEndsAt = BigInt(snapshot.claimEndsAt);
  if (graceEndsAt < dueAt) {
    context.addIssue({ code: "custom", path: ["graceEndsAt"], message: "Grace cannot end before payday." });
  }
  if (claimEndsAt <= graceEndsAt) {
    context.addIssue({ code: "custom", path: ["claimEndsAt"], message: "Claim deadline must follow the grace period." });
  }
});

export type ObligationSnapshotV2 = z.infer<typeof obligationSnapshotV2Schema>;

export const payrollStatementV2Schema = z.object({
  schemaVersion: z.literal(PAYO_EXCEPTION_SCHEMA_VERSION),
  runNullifier: commitmentSchema,
  snapshotCommitment: commitmentSchema,
  manifestRoot: commitmentSchema,
  fxRoot: commitmentSchema,
  availabilityCommitment: commitmentSchema,
  observedAt: u64StringSchema,
  source: z.enum(["employer_statement", "settlement_match"]),
}).strict();

export type PayrollStatementV2 = z.infer<typeof payrollStatementV2Schema>;

function hashFixed(domain: string, ...fields: readonly Uint8Array[]): `0x${string}` {
  return toHex(keccak_256(concatBytes(utf8(domain), ...fields)));
}

function u8(value: number, label: string): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new Error(`${label} must fit in u8.`);
  }
  return Uint8Array.of(value);
}

function u64(value: string | bigint, label: string): Uint8Array {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= 1n << 64n) throw new Error(`${label} must fit in u64.`);
  return encodeUint(parsed, 8);
}

function u128(value: string | bigint, label: string, positive = false): Uint8Array {
  const parsed = BigInt(value);
  if (parsed < (positive ? 1n : 0n) || parsed >= 1n << 128n) {
    throw new Error(`${label} must fit in ${positive ? "a positive " : ""}u128.`);
  }
  return encodeUint(parsed, 16);
}

export function claimCapabilityCommitmentV2(secret: string): `0x${string}` {
  return hashFixed(
    "PAYO_CLAIM_CAPABILITY_V2",
    normalizedHexBytes(secret, 32),
  );
}

export function obligationSnapshotCommitmentV2(
  input: ObligationSnapshotV2,
): `0x${string}` {
  const snapshot = obligationSnapshotV2Schema.parse(input);
  return hashFixed(
    "PAYO_OBLIGATION_SNAPSHOT_V2",
    u8(snapshot.schemaVersion, "Snapshot schema version"),
    normalizedHexBytes(snapshot.runNullifier, 32),
    normalizedHexBytes(snapshot.baseAgreementRoot, 32),
    normalizedHexBytes(snapshot.obligationRoot, 32),
    normalizedHexBytes(snapshot.policyRoot, 32),
    normalizedHexBytes(snapshot.ownerAddress, 32),
    u64(snapshot.dueAt, "Snapshot payday"),
    u64(snapshot.graceEndsAt, "Snapshot grace deadline"),
    u64(snapshot.claimEndsAt, "Snapshot claim deadline"),
    normalizedHexBytes(snapshot.availabilityCommitment, 32),
  );
}

export function payrollStatementCommitmentV2(
  input: PayrollStatementV2,
): `0x${string}` {
  const statement = payrollStatementV2Schema.parse(input);
  return hashFixed(
    "PAYO_PAYROLL_STATEMENT_V2",
    u8(statement.schemaVersion, "Statement schema version"),
    normalizedHexBytes(statement.runNullifier, 32),
    normalizedHexBytes(statement.snapshotCommitment, 32),
    normalizedHexBytes(statement.manifestRoot, 32),
    normalizedHexBytes(statement.fxRoot, 32),
    normalizedHexBytes(statement.availabilityCommitment, 32),
    u64(statement.observedAt, "Statement observation time"),
    u8(claimEvidenceSources[statement.source], "Statement source"),
  );
}

export function claimSubjectNullifierV2(input: {
  claimCapabilitySecret: string;
  runNullifier: string;
  agreementLeaf: string;
  claimKind: ExceptionClaimKind;
}): `0x${string}` {
  return hashFixed(
    "PAYO_CLAIM_SUBJECT_V2",
    normalizedHexBytes(input.claimCapabilitySecret, 32),
    normalizedHexBytes(input.runNullifier, 32),
    normalizedHexBytes(input.agreementLeaf, 32),
    u8(exceptionClaimKinds[input.claimKind], "Claim kind"),
  );
}

export function claimFactCommitmentV2(input: {
  claimSubjectNullifier: string;
  runNullifier: string;
  snapshotCommitment: string;
  statementCommitment: string;
  manifestRoot: string;
  agreementLeaf: string;
  targetIndex: number;
  claimKind: ExceptionClaimKind;
  shortfallAtomic: string | bigint;
  shortfallUnit: ClaimShortfallUnit;
  obligationToken: ExceptionToken;
  evidenceSource: ClaimEvidenceSource;
}): `0x${string}` {
  return hashFixed(
    "PAYO_CLAIM_FACT_V2",
    normalizedHexBytes(input.claimSubjectNullifier, 32),
    normalizedHexBytes(input.runNullifier, 32),
    normalizedHexBytes(input.snapshotCommitment, 32),
    normalizedHexBytes(input.statementCommitment, 32),
    normalizedHexBytes(input.manifestRoot, 32),
    normalizedHexBytes(input.agreementLeaf, 32),
    u8(input.targetIndex, "Claim target index"),
    u8(exceptionClaimKinds[input.claimKind], "Claim kind"),
    u128(input.shortfallAtomic, "Claim shortfall", true),
    u8(claimShortfallUnits[input.shortfallUnit], "Claim shortfall unit"),
    u8(exceptionTokens[input.obligationToken], "Claim obligation token"),
    u8(claimEvidenceSources[input.evidenceSource], "Claim evidence source"),
  );
}

export function remediationSubjectNullifierV2(input: {
  claimSubjectNullifier: string;
  remediationSecret: string;
}): `0x${string}` {
  return hashFixed(
    "PAYO_REMEDIATION_SUBJECT_V2",
    normalizedHexBytes(input.claimSubjectNullifier, 32),
    normalizedHexBytes(input.remediationSecret, 32),
  );
}

export function remediationFactCommitmentV2(input: {
  remediationSubjectNullifier: string;
  claimSubjectNullifier: string;
  claimFactCommitment: string;
  recipientCommitment: string;
  token: ExceptionToken;
  amountAtomic: string | bigint;
  referenceValueAtomic: string | bigint;
  referenceUnit: ClaimShortfallUnit;
  fxRoot: string;
}): `0x${string}` {
  return hashFixed(
    "PAYO_REMEDIATION_FACT_V2",
    normalizedHexBytes(input.remediationSubjectNullifier, 32),
    normalizedHexBytes(input.claimSubjectNullifier, 32),
    normalizedHexBytes(input.claimFactCommitment, 32),
    normalizedHexBytes(input.recipientCommitment, 32),
    u8(exceptionTokens[input.token], "Remediation token"),
    u128(input.amountAtomic, "Remediation amount", true),
    u128(input.referenceValueAtomic, "Remediation reference value"),
    u8(claimShortfallUnits[input.referenceUnit], "Remediation reference unit"),
    normalizedHexBytes(input.fxRoot, 32),
  );
}

export const exceptionPublicInputV2Keys = [
  "chainId",
  "sealAddress",
  "proofVersion",
  "schemaVersion",
  "agreementRootHigh",
  "agreementRootLow",
  "manifestRootHigh",
  "manifestRootLow",
  "policyRootHigh",
  "policyRootLow",
  "fxRootHigh",
  "fxRootLow",
  "subjectNullifierHigh",
  "subjectNullifierLow",
  "parentNullifierHigh",
  "parentNullifierLow",
  "factCommitmentHigh",
  "factCommitmentLow",
  "parentFactCommitmentHigh",
  "parentFactCommitmentLow",
  "validityStart",
  "validityExpiry",
  "shardIndex",
] as const;

export const PAYO_EXCEPTION_PUBLIC_INPUT_COUNT = exceptionPublicInputV2Keys.length;

export type ExceptionPublicInputsV2 = Record<
  (typeof exceptionPublicInputV2Keys)[number],
  string
>;

export function mapExceptionPublicInputsV2(
  values: readonly string[],
): ExceptionPublicInputsV2 {
  if (values.length !== PAYO_EXCEPTION_PUBLIC_INPUT_COUNT) {
    throw new Error(
      `Expected ${PAYO_EXCEPTION_PUBLIC_INPUT_COUNT} exception public inputs; received ${values.length}.`,
    );
  }
  return Object.fromEntries(
    exceptionPublicInputV2Keys.map((key, index) => [key, values[index]]),
  ) as ExceptionPublicInputsV2;
}

export const exceptionClaimFactSchema = z.object({
  claimSubjectNullifier: commitmentSchema,
  runNullifier: commitmentSchema,
  snapshotCommitment: commitmentSchema,
  statementCommitment: commitmentSchema,
  manifestRoot: commitmentSchema,
  agreementLeaf: commitmentSchema,
  targetIndex: z.number().int().min(0).max(49),
  claimKind: z.enum(["missing_obligation", "below_committed_floor", "incomplete_final_pay"]),
  shortfallAtomic: positiveU128StringSchema,
  shortfallUnit: z.enum(["strk_atomic", "usdc_atomic", "usd_6", "gbp_6"]),
  obligationToken: z.enum(["STRK", "USDC"]),
  evidenceSource: z.enum(["unsettled_period", "payo_run", "employer_statement", "settlement_match"]),
}).strict().superRefine((claim, context) => {
  if (
    claim.claimKind === "below_committed_floor"
    && !["usd_6", "gbp_6"].includes(claim.shortfallUnit)
  ) {
    context.addIssue({
      code: "custom",
      path: ["shortfallUnit"],
      message: "An FX-floor shortfall must use a reference-currency unit.",
    });
  }
  if (
    claim.claimKind !== "below_committed_floor"
    && claim.shortfallUnit !== (claim.obligationToken === "STRK" ? "strk_atomic" : "usdc_atomic")
  ) {
    context.addIssue({
      code: "custom",
      path: ["shortfallUnit"],
      message: "A non-FX claim shortfall must use its obligation token atomic unit.",
    });
  }
  if (
    claim.claimKind !== "missing_obligation"
    && claim.evidenceSource === "unsettled_period"
  ) {
    context.addIssue({
      code: "custom",
      path: ["evidenceSource"],
      message: "Only a missing-obligation claim can use an unsettled period.",
    });
  }
  if (claim.evidenceSource === "payo_run") {
    context.addIssue({
      code: "custom",
      path: ["evidenceSource"],
      message: "A verified native PAYO run cannot be used as evidence of a condition its circuit rejects.",
    });
  }
});
