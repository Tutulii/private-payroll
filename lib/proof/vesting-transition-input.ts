import type { InputMap } from "@noir-lang/noir_js";
import { splitHashToU128, hashTextCommitment } from "@/lib/crypto/commitments";
import { fromBase64, normalizedHexBytes, toHex } from "@/lib/crypto/encoding";
import { encodeAdvancedObligation } from "@/lib/domain/advanced-obligation-commitment";
import {
  PAYO_EXTERNAL_ATTESTATION_ALL_FACTS,
  verifySignedExternalAttestation,
  type SignedExternalAttestation,
} from "@/lib/domain/external-attestation";
import {
  claimEvidenceSources,
  claimFactCommitmentV2,
  claimShortfallUnits,
  exceptionClaimFactSchema,
  exceptionClaimKinds,
  exceptionTokens,
  remediationFactCommitmentV2,
  remediationSubjectNullifierV2,
  type ExceptionPublicInputsV2,
} from "@/lib/domain/exception-protocol";
import {
  employmentAgreementSchema,
  type EmploymentAgreement,
} from "@/lib/domain/obligations";
import {
  assertVestingTransition,
  vestingScheduleId,
  type VestingScheduleTerms,
  type VestingState,
} from "@/lib/domain/vesting-tax";
import type {
  PayrollBookEntryKind,
  UniversalPayrollBookEntry,
} from "@/lib/domain/universal-payroll-book";
import { PAYROLL_TOKENS } from "@/lib/starknet/tokens";
import { advancedPlanProofCommitment } from "./advanced-plan-commitment";
import { createProofCommitter } from "./commitments";
import type { PayrollIntegrityInputBuild } from "./input-builder";
import {
  buildUniversalExceptionPayrollBookInput,
  buildUniversalPayrollBookInput,
  type PayrollBookShardAggregate,
} from "./universal-payroll-book-input";

export const PAYO_VESTING_TRANSITION_PROOF_VERSION = 3;
export const PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT = 58;

const ZERO = `0x${"00".repeat(32)}` as const;

export type VestingTransitionPublicInputs = {
  chainId: string;
  sealAddress: string;
  proofVersion: "3";
  schemaVersion: "1";
  entryKind: "0" | "1" | "2" | "3" | "4";
  agreementRootHigh: string;
  agreementRootLow: string;
  manifestRootHigh: string;
  manifestRootLow: string;
  policyRootHigh: string;
  policyRootLow: string;
  fxRootHigh: string;
  fxRootLow: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  subjectNullifierHigh: string;
  subjectNullifierLow: string;
  parentFactHigh: string;
  parentFactLow: string;
  factHigh: string;
  factLow: string;
  ownerAddress: string;
  sourceSealAddress: string;
  sourceProofVersion: string;
  attestationRootHigh: string;
  attestationRootLow: string;
  shard0ContributorCount: string;
  shard1ContributorCount: string;
  totalsDisclosed: "0" | "1";
  totalsCommitmentHigh: string;
  totalsCommitmentLow: string;
  shard0StrkGross: string;
  shard0StrkDeductions: string;
  shard0StrkNet: string;
  shard0UsdcGross: string;
  shard0UsdcDeductions: string;
  shard0UsdcNet: string;
  shard1StrkGross: string;
  shard1StrkDeductions: string;
  shard1StrkNet: string;
  shard1UsdcGross: string;
  shard1UsdcDeductions: string;
  shard1UsdcNet: string;
  scheduleIdHigh: string;
  scheduleIdLow: string;
  previousStateHigh: string;
  previousStateLow: string;
  nextStateHigh: string;
  nextStateLow: string;
  releaseNullifierHigh: string;
  releaseNullifierLow: string;
  bookEntryHigh: string;
  bookEntryLow: string;
  periodStart: string;
  periodEnd: string;
  validityStart: string;
  validityExpiry: string;
  shardIndex: "0" | "1";
};

export type ExternalAttestationProofInput = {
  agreementId: string;
  catalogRoot: string;
  signed: SignedExternalAttestation;
  siblings: readonly string[];
  pathBits: readonly boolean[];
};

export type VestingTransitionInputBuild = {
  circuitInputs: [InputMap, InputMap];
  publicInputs: [VestingTransitionPublicInputs, VestingTransitionPublicInputs];
  scheduleId: `0x${string}`;
  previousStateCommitment: `0x${string}`;
  nextStateCommitment: `0x${string}`;
  releaseNullifier: `0x${string}`;
  bookEntry: UniversalPayrollBookEntry;
  bookEntryCommitment: `0x${string}`;
  totalsOpening: ReturnType<typeof buildUniversalPayrollBookInput>["totalsOpening"];
  entryKind: PayrollBookEntryKind;
};

export function mapVestingTransitionPublicInputs(
  values: readonly string[],
): VestingTransitionPublicInputs {
  if (values.length !== PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT) {
    throw new Error(
      `Expected ${PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT} vesting-transition public inputs; received ${values.length}.`,
    );
  }
  if (BigInt(values[2]) !== 3n || BigInt(values[3]) !== 1n) {
    throw new Error("Vesting transition returned the wrong versioned public-input ABI.");
  }
  if (BigInt(values[4]) < 0n || BigInt(values[4]) > 4n) {
    throw new Error("Vesting transition returned an invalid entry kind.");
  }
  if (BigInt(values[28]) < 0n || BigInt(values[28]) > 1n) {
    throw new Error("Vesting transition returned an invalid totals-disclosure mode.");
  }
  if (BigInt(values[57]) < 0n || BigInt(values[57]) > 1n) {
    throw new Error("Vesting transition returned an invalid shard index.");
  }
  return {
    chainId: values[0],
    sealAddress: values[1],
    proofVersion: "3",
    schemaVersion: "1",
    entryKind: BigInt(values[4]).toString() as "0" | "1" | "2" | "3" | "4",
    agreementRootHigh: values[5],
    agreementRootLow: values[6],
    manifestRootHigh: values[7],
    manifestRootLow: values[8],
    policyRootHigh: values[9],
    policyRootLow: values[10],
    fxRootHigh: values[11],
    fxRootLow: values[12],
    runNullifierHigh: values[13],
    runNullifierLow: values[14],
    subjectNullifierHigh: values[15],
    subjectNullifierLow: values[16],
    parentFactHigh: values[17],
    parentFactLow: values[18],
    factHigh: values[19],
    factLow: values[20],
    ownerAddress: values[21],
    sourceSealAddress: values[22],
    sourceProofVersion: values[23],
    attestationRootHigh: values[24],
    attestationRootLow: values[25],
    shard0ContributorCount: values[26],
    shard1ContributorCount: values[27],
    totalsDisclosed: BigInt(values[28]) === 0n ? "0" : "1",
    totalsCommitmentHigh: values[29],
    totalsCommitmentLow: values[30],
    shard0StrkGross: values[31],
    shard0StrkDeductions: values[32],
    shard0StrkNet: values[33],
    shard0UsdcGross: values[34],
    shard0UsdcDeductions: values[35],
    shard0UsdcNet: values[36],
    shard1StrkGross: values[37],
    shard1StrkDeductions: values[38],
    shard1StrkNet: values[39],
    shard1UsdcGross: values[40],
    shard1UsdcDeductions: values[41],
    shard1UsdcNet: values[42],
    scheduleIdHigh: values[43],
    scheduleIdLow: values[44],
    previousStateHigh: values[45],
    previousStateLow: values[46],
    nextStateHigh: values[47],
    nextStateLow: values[48],
    releaseNullifierHigh: values[49],
    releaseNullifierLow: values[50],
    bookEntryHigh: values[51],
    bookEntryLow: values[52],
    periodStart: values[53],
    periodEnd: values[54],
    validityStart: values[55],
    validityExpiry: values[56],
    shardIndex: BigInt(values[57]) === 0n ? "0" : "1",
  };
}

function bytes32(value: string): number[] {
  return [...normalizedHexBytes(value, 32)];
}

function hexFromBytes(value: readonly number[]): `0x${string}` {
  if (value.length !== 32) throw new Error("Circuit commitment must contain exactly 32 bytes.");
  return toHex(Uint8Array.from(value));
}

function limbs(value: string): { high: string; low: string } {
  const split = splitHashToU128(value);
  return { high: split.high.toString(), low: split.low.toString() };
}

function unixSeconds(value: string): string {
  const timestamp = new Date(value).getTime();
  if (!Number.isSafeInteger(timestamp)) throw new Error("Vesting timestamp is invalid.");
  return BigInt(Math.floor(timestamp / 1_000)).toString();
}

function advancedPlanWitness(agreement: Extract<EmploymentAgreement, { agreementVersion: "payo-agreement-v2" }>) {
  const encoded = encodeAdvancedObligation(agreement);
  return {
    enabled: true,
    kind: encoded.kind.toString(),
    cadence: encoded.cadence.toString(),
    flags: encoded.flags.toString(),
    occurrence: encoded.occurrence.toString(),
    release_sequence: encoded.releaseSequence.toString(),
    checkpoint_sequence: encoded.checkpointSequence.toString(),
    minimum_checkpoint_seconds: encoded.minimumCheckpointSeconds.toString(),
    timestamps: encoded.timestamps.map(String),
    amounts: encoded.amounts.map(String),
    required_mask: encoded.requiredMask.toString(),
    included_mask: encoded.includedMask.toString(),
    commitments: encoded.commitments.map(bytes32),
    salt: bytes32(encoded.salt),
  };
}

function emptyAgreementWitness() {
  return {
    enabled: false,
    id_commitment: bytes32(ZERO),
    recipient_commitment: bytes32(ZERO),
    earnings: Array(8).fill("0"),
    earnings_count: "0",
    token: "0",
    policy_commitment: bytes32(ZERO),
    schedule_commitment: bytes32(ZERO),
    due_at: "0",
    valid_until: "0",
    classification_declared: "0",
    classification_score: "0",
    classification_employee_threshold: "0",
    final_pay_mode: false,
    final_required_mask: "0",
    final_components: Array(5).fill("0"),
    fx_floor_atomic: "0",
    reference_currency: "0",
    salt: bytes32(ZERO),
  };
}

function emptyPayrollLineWitness() {
  return {
    active: false,
    deductions: Array(8).fill("0"),
    deductions_count: "0",
    policy_slot: "0",
    fx_slot: "0",
    salt: bytes32(ZERO),
    classification_treatment: "0",
    final_included_mask: "0",
    reference_value_atomic: "0",
  };
}

function emptyAdvancedPlanWitness() {
  return {
    enabled: false,
    kind: "0",
    cadence: "0",
    flags: "0",
    occurrence: "0",
    release_sequence: "0",
    checkpoint_sequence: "0",
    minimum_checkpoint_seconds: "0",
    timestamps: Array(12).fill("0"),
    amounts: Array(10).fill("0"),
    required_mask: "0",
    included_mask: "0",
    commitments: Array.from({ length: 6 }, () => bytes32(ZERO)),
    salt: bytes32(ZERO),
  };
}

function emptyExceptionEntryWitness() {
  return {
    enabled: false,
    claim_subject_nullifier: bytes32(ZERO),
    snapshot_commitment: bytes32(ZERO),
    statement_commitment: bytes32(ZERO),
    claim_manifest_root: bytes32(ZERO),
    agreement_leaf: bytes32(ZERO),
    target_index: "0",
    claim_kind: "0",
    shortfall_atomic: "0",
    shortfall_unit: "0",
    obligation_token: "0",
    evidence_source: "0",
    remediation_secret: bytes32(ZERO),
    recipient_commitment: bytes32(ZERO),
    remediation_amount_atomic: "0",
    remediation_reference_value_atomic: "0",
    remediation_action_salt: bytes32(ZERO),
  };
}

function emptyExternalAttestationCircuitFields() {
  return {
    root: ZERO,
    witness: {
      enabled: false,
      issuer_public_key: bytes32(ZERO),
      subject_commitment: bytes32(ZERO),
      fact_mask: "0",
      jurisdiction_commitment: bytes32(ZERO),
      status_commitment: bytes32(ZERO),
      valid_from: "0",
      valid_until: "0",
      nonce: bytes32(ZERO),
      policy_root: bytes32(ZERO),
    },
    membership: {
      siblings: Array(6).fill("0"),
      path_bits: Array(6).fill(false),
    },
  };
}

function externalAttestationCircuitFields(
  input: ExternalAttestationProofInput | undefined,
  policyRoot: string,
) {
  if (!input) return emptyExternalAttestationCircuitFields();
  const signed = verifySignedExternalAttestation(input.signed);
  if (BigInt(signed.attestation.policyRoot) !== BigInt(policyRoot)) {
    throw new Error("External attestation is bound to another payroll policy catalog.");
  }
  if (signed.attestation.factMask !== PAYO_EXTERNAL_ATTESTATION_ALL_FACTS) {
    throw new Error("External attestation must cover residency, employment and tax status.");
  }
  if (input.siblings.length !== 6 || input.pathBits.length !== 6) {
    throw new Error("External attestation membership must contain exactly six levels.");
  }
  if (BigInt(input.catalogRoot) === 0n) {
    throw new Error("External attestation catalog root is zero.");
  }
  return {
    root: toHex(normalizedHexBytes(input.catalogRoot, 32)),
    witness: {
      enabled: true,
      issuer_public_key: [...fromBase64(signed.attestation.issuerPublicKey)],
      subject_commitment: bytes32(signed.attestation.subjectCommitment),
      fact_mask: signed.attestation.factMask.toString(),
      jurisdiction_commitment: bytes32(signed.attestation.jurisdictionCommitment),
      status_commitment: bytes32(signed.attestation.statusCommitment),
      valid_from: signed.attestation.validFrom,
      valid_until: signed.attestation.validUntil,
      nonce: bytes32(signed.attestation.nonce),
      policy_root: bytes32(signed.attestation.policyRoot),
    },
    membership: {
      siblings: input.siblings.map((value) => BigInt(value).toString()),
      path_bits: [...input.pathBits],
    },
  };
}

function exposedAggregate(
  aggregate: PayrollBookShardAggregate,
  disclosed: boolean,
): PayrollBookShardAggregate {
  if (disclosed) return aggregate;
  return {
    contributorCount: aggregate.contributorCount,
    STRK: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
    USDC: { grossAtomic: "0", deductionsAtomic: "0", netAtomic: "0" },
  };
}

function commonBookFields(input: {
  payroll: PayrollIntegrityInputBuild;
  universal: ReturnType<typeof buildUniversalPayrollBookInput>;
  ownerAddress: string;
  periodStart: bigint;
  periodEnd: bigint;
  attestationRoot: string;
  totalsSalt: string;
  entryKind: PayrollBookEntryKind;
  scheduleId: string;
  previousStateCommitment: string;
  nextStateCommitment: string;
  releaseNullifier: string;
}) {
  const payroll = input.payroll.publicInputs[0];
  const schedule = limbs(input.scheduleId);
  const previous = limbs(input.previousStateCommitment);
  const next = limbs(input.nextStateCommitment);
  const release = limbs(input.releaseNullifier);
  const attestation = limbs(input.attestationRoot);
  const totalsCommitment = limbs(input.universal.entry.totalsCommitment);
  const disclosed = input.universal.entry.totalsDisclosure === "public";
  const shardZero = exposedAggregate(input.universal.shards[0].aggregate, disclosed);
  const shardOne = exposedAggregate(input.universal.shards[1].aggregate, disclosed);
  return {
    chain_id: payroll.chainId,
    seal_address: BigInt(input.universal.entry.sealAddress).toString(),
    proof_version: PAYO_VESTING_TRANSITION_PROOF_VERSION.toString(),
    schema_version: "1",
    entry_kind: input.universal.entryKindCode.toString(),
    agreement_root_high: payroll.agreementRootHigh,
    agreement_root_low: payroll.agreementRootLow,
    manifest_root_high: payroll.manifestRootHigh,
    manifest_root_low: payroll.manifestRootLow,
    policy_root_high: payroll.policyRootHigh,
    policy_root_low: payroll.policyRootLow,
    fx_root_high: payroll.fxRootHigh,
    fx_root_low: payroll.fxRootLow,
    run_nullifier_high: payroll.runNullifierHigh,
    run_nullifier_low: payroll.runNullifierLow,
    subject_nullifier_high: payroll.runNullifierHigh,
    subject_nullifier_low: payroll.runNullifierLow,
    parent_fact_high: "0",
    parent_fact_low: "0",
    fact_high: "0",
    fact_low: "0",
    owner_address: BigInt(input.ownerAddress).toString(),
    source_seal_address: BigInt(input.universal.entry.sourceSealAddress).toString(),
    source_proof_version: "2",
    attestation_root_high: attestation.high,
    attestation_root_low: attestation.low,
    shard_0_contributor_count: shardZero.contributorCount.toString(),
    shard_1_contributor_count: shardOne.contributorCount.toString(),
    totals_disclosed: disclosed ? "1" : "0",
    totals_commitment_high: totalsCommitment.high,
    totals_commitment_low: totalsCommitment.low,
    private_shard_0_strk_gross: input.universal.shards[0].aggregate.STRK.grossAtomic,
    private_shard_0_strk_deductions: input.universal.shards[0].aggregate.STRK.deductionsAtomic,
    private_shard_0_strk_net: input.universal.shards[0].aggregate.STRK.netAtomic,
    private_shard_0_usdc_gross: input.universal.shards[0].aggregate.USDC.grossAtomic,
    private_shard_0_usdc_deductions: input.universal.shards[0].aggregate.USDC.deductionsAtomic,
    private_shard_0_usdc_net: input.universal.shards[0].aggregate.USDC.netAtomic,
    private_shard_1_strk_gross: input.universal.shards[1].aggregate.STRK.grossAtomic,
    private_shard_1_strk_deductions: input.universal.shards[1].aggregate.STRK.deductionsAtomic,
    private_shard_1_strk_net: input.universal.shards[1].aggregate.STRK.netAtomic,
    private_shard_1_usdc_gross: input.universal.shards[1].aggregate.USDC.grossAtomic,
    private_shard_1_usdc_deductions: input.universal.shards[1].aggregate.USDC.deductionsAtomic,
    private_shard_1_usdc_net: input.universal.shards[1].aggregate.USDC.netAtomic,
    totals_salt: bytes32(input.totalsSalt),
    shard_0_strk_gross: shardZero.STRK.grossAtomic,
    shard_0_strk_deductions: shardZero.STRK.deductionsAtomic,
    shard_0_strk_net: shardZero.STRK.netAtomic,
    shard_0_usdc_gross: shardZero.USDC.grossAtomic,
    shard_0_usdc_deductions: shardZero.USDC.deductionsAtomic,
    shard_0_usdc_net: shardZero.USDC.netAtomic,
    shard_1_strk_gross: shardOne.STRK.grossAtomic,
    shard_1_strk_deductions: shardOne.STRK.deductionsAtomic,
    shard_1_strk_net: shardOne.STRK.netAtomic,
    shard_1_usdc_gross: shardOne.USDC.grossAtomic,
    shard_1_usdc_deductions: shardOne.USDC.deductionsAtomic,
    shard_1_usdc_net: shardOne.USDC.netAtomic,
    schedule_id_high: schedule.high,
    schedule_id_low: schedule.low,
    previous_state_high: previous.high,
    previous_state_low: previous.low,
    next_state_high: next.high,
    next_state_low: next.low,
    release_nullifier_high: release.high,
    release_nullifier_low: release.low,
    book_entry_high: input.universal.entryCommitmentLimbs.high,
    book_entry_low: input.universal.entryCommitmentLimbs.low,
    period_start: input.periodStart.toString(),
    period_end: input.periodEnd.toString(),
    validity_start: payroll.validityStart,
    validity_expiry: payroll.validityExpiry,
  };
}

function publicBookFields(
  common: ReturnType<typeof commonBookFields>,
  shardIndex: "0" | "1",
): VestingTransitionPublicInputs {
  return {
    chainId: common.chain_id,
    sealAddress: common.seal_address,
    proofVersion: "3",
    schemaVersion: "1",
    entryKind: common.entry_kind as "0" | "1" | "2" | "3" | "4",
    agreementRootHigh: common.agreement_root_high,
    agreementRootLow: common.agreement_root_low,
    manifestRootHigh: common.manifest_root_high,
    manifestRootLow: common.manifest_root_low,
    policyRootHigh: common.policy_root_high,
    policyRootLow: common.policy_root_low,
    fxRootHigh: common.fx_root_high,
    fxRootLow: common.fx_root_low,
    runNullifierHigh: common.run_nullifier_high,
    runNullifierLow: common.run_nullifier_low,
    subjectNullifierHigh: common.subject_nullifier_high,
    subjectNullifierLow: common.subject_nullifier_low,
    parentFactHigh: common.parent_fact_high,
    parentFactLow: common.parent_fact_low,
    factHigh: common.fact_high,
    factLow: common.fact_low,
    ownerAddress: common.owner_address,
    sourceSealAddress: common.source_seal_address,
    sourceProofVersion: common.source_proof_version,
    attestationRootHigh: common.attestation_root_high,
    attestationRootLow: common.attestation_root_low,
    shard0ContributorCount: common.shard_0_contributor_count,
    shard1ContributorCount: common.shard_1_contributor_count,
    totalsDisclosed: common.totals_disclosed as "0" | "1",
    totalsCommitmentHigh: common.totals_commitment_high,
    totalsCommitmentLow: common.totals_commitment_low,
    shard0StrkGross: common.shard_0_strk_gross,
    shard0StrkDeductions: common.shard_0_strk_deductions,
    shard0StrkNet: common.shard_0_strk_net,
    shard0UsdcGross: common.shard_0_usdc_gross,
    shard0UsdcDeductions: common.shard_0_usdc_deductions,
    shard0UsdcNet: common.shard_0_usdc_net,
    shard1StrkGross: common.shard_1_strk_gross,
    shard1StrkDeductions: common.shard_1_strk_deductions,
    shard1StrkNet: common.shard_1_strk_net,
    shard1UsdcGross: common.shard_1_usdc_gross,
    shard1UsdcDeductions: common.shard_1_usdc_deductions,
    shard1UsdcNet: common.shard_1_usdc_net,
    scheduleIdHigh: common.schedule_id_high,
    scheduleIdLow: common.schedule_id_low,
    previousStateHigh: common.previous_state_high,
    previousStateLow: common.previous_state_low,
    nextStateHigh: common.next_state_high,
    nextStateLow: common.next_state_low,
    releaseNullifierHigh: common.release_nullifier_high,
    releaseNullifierLow: common.release_nullifier_low,
    bookEntryHigh: common.book_entry_high,
    bookEntryLow: common.book_entry_low,
    periodStart: common.period_start,
    periodEnd: common.period_end,
    validityStart: common.validity_start,
    validityExpiry: common.validity_expiry,
    shardIndex,
  };
}

function aggregateCircuitFields(
  shard: ReturnType<typeof buildUniversalPayrollBookInput>["shards"][number],
) {
  return {
    aggregate_agreement_leaves: shard.agreementLeaves,
    aggregate_payroll_leaves: shard.payrollLeaves,
    aggregate_agreements: shard.agreements,
    aggregate_lines: shard.lines,
  };
}

/**
 * Builds the auxiliary v3 proof that links one private-vesting transition and
 * exact two-shard payroll aggregates to the Advanced v2 payroll roots.
 */
export async function buildVestingTransitionInputs(input: {
  payroll: PayrollIntegrityInputBuild;
  agreement: EmploymentAgreement;
  ownerAddress: string;
  bookSealAddress?: string;
  periodStart: bigint;
  periodEnd: bigint;
  previousStateSalt: string;
  nextStateSalt: string;
  totalsSalt: string;
  totalsDisclosure?: "hidden" | "public";
  attestation?: ExternalAttestationProofInput;
}): Promise<VestingTransitionInputBuild> {
  const agreement = employmentAgreementSchema.parse(input.agreement);
  if (agreement.agreementVersion !== "payo-agreement-v2"
    || agreement.paymentPlan.kind !== "private_vesting") {
    throw new Error("A vesting transition requires one private-vesting PAYO v2 agreement.");
  }
  const binding = input.payroll.proofBindings.find(({ agreementId }) => agreementId === agreement.id);
  if (!binding) throw new Error("The vesting agreement is absent from this proved payroll run.");
  if (input.payroll.proofBindings.filter(({ agreementId }) => agreementId === agreement.id).length !== 1) {
    throw new Error("The vesting agreement must occupy exactly one payroll slot.");
  }
  const expectedPlanCommitment = await advancedPlanProofCommitment(agreement);
  if (BigInt(expectedPlanCommitment) !== BigInt(binding.source.scheduleCommitment)) {
    throw new Error("The payroll leaf is not bound to this private-vesting plan.");
  }

  const plan = agreement.paymentPlan;
  const schedule: VestingScheduleTerms = {
    scheduleVersion: "payo-private-vesting-v1",
    agreementIdCommitment: toHex(hashTextCommitment("PAYO_AGREEMENT_ID_V1", agreement.id)),
    recipientCommitment: hexFromBytes(binding.agreement.recipient_commitment),
    tokenAddress: PAYROLL_TOKENS[agreement.settlementToken].address,
    startsAt: unixSeconds(plan.startsAt),
    cliffAt: unixSeconds(plan.cliffAt),
    endsAt: unixSeconds(plan.endsAt),
    totalAtomic: plan.totalAtomic,
    planSalt: agreement.planSalt,
  };
  const scheduleId = vestingScheduleId(schedule);
  const previous: VestingState = {
    stateVersion: "payo-vesting-state-v1",
    scheduleId,
    releasedAtomic: plan.releasedAtomic,
    releaseSequence: plan.releaseSequence,
    stateSalt: input.previousStateSalt,
  };
  const releaseAt = unixSeconds(plan.releaseAt);
  const startsAt = BigInt(schedule.startsAt);
  const endsAt = BigInt(schedule.endsAt);
  const releaseTimestamp = BigInt(releaseAt);
  const total = BigInt(schedule.totalAtomic);
  const earned = releaseTimestamp >= endsAt
    ? total
    : (total / (endsAt - startsAt)) * (releaseTimestamp - startsAt)
      + ((total % (endsAt - startsAt)) * (releaseTimestamp - startsAt)) / (endsAt - startsAt);
  const payable = earned - BigInt(plan.releasedAtomic);
  if (payable <= 0n || BigInt(binding.calculated.grossAtomic) !== payable) {
    throw new Error("The payroll gross does not equal the exact unpaid vested delta.");
  }
  const next: VestingState = {
    stateVersion: "payo-vesting-state-v1",
    scheduleId,
    releasedAtomic: earned.toString(),
    releaseSequence: plan.releaseSequence + 1,
    stateSalt: input.nextStateSalt,
  };
  const transition = assertVestingTransition({
    transitionVersion: "payo-vesting-transition-v1",
    schedule,
    previous,
    releaseAt,
    payableAtomic: payable.toString(),
    next,
    runNullifier: input.payroll.runNullifier,
  });
  if (input.attestation) {
    if (input.attestation.agreementId !== agreement.id) {
      throw new Error("External attestation selects another payroll agreement.");
    }
    if (BigInt(input.attestation.signed.attestation.subjectCommitment)
      !== BigInt(hexFromBytes(binding.agreement.recipient_commitment))) {
      throw new Error("External attestation belongs to another private recipient.");
    }
  }
  const attestation = externalAttestationCircuitFields(
    input.attestation,
    input.payroll.policyRoot,
  );
  const attestationRoot = attestation.root;
  const universal = buildUniversalPayrollBookInput({
    payroll: input.payroll,
    entryKind: "vesting",
    ownerAddress: input.ownerAddress,
    bookSealAddress: input.bookSealAddress,
    sourceSealAddress: input.payroll.publicInputs[0].sealAddress,
    periodStart: input.periodStart,
    periodEnd: input.periodEnd,
    totalsDisclosure: input.totalsDisclosure ?? "public",
    totalsSalt: input.totalsSalt,
    attestationRoot,
    vestingScheduleId: transition.scheduleId,
    vestingStateCommitment: transition.nextStateCommitment,
  });

  const committer = await createProofCommitter();
  const agreementMembership = committer.buildProofFixedMerkleMembership(
    input.payroll.proofBindings.map(({ agreementLeaf }) => agreementLeaf),
    binding.index,
  );
  const payrollMembership = committer.buildProofFixedMerkleMembership(
    input.payroll.proofBindings.map(({ payrollLeaf }) => payrollLeaf),
    binding.index,
  );
  if (BigInt(agreementMembership.root) !== BigInt(input.payroll.agreementRoot)
    || BigInt(payrollMembership.root) !== BigInt(input.payroll.manifestRoot)) {
    throw new Error("Vesting membership paths do not reconstruct the payroll roots.");
  }

  const common = {
    ...commonBookFields({
      payroll: input.payroll,
      universal,
      ownerAddress: input.ownerAddress,
      periodStart: input.periodStart,
      periodEnd: input.periodEnd,
      attestationRoot,
      totalsSalt: input.totalsSalt,
      entryKind: "vesting",
      scheduleId: transition.scheduleId,
      previousStateCommitment: transition.previousStateCommitment,
      nextStateCommitment: transition.nextStateCommitment,
      releaseNullifier: transition.releaseNullifier,
    }),
    target_index: binding.index.toString(),
    agreement: binding.agreement,
    line: binding.line,
    plan: advancedPlanWitness(agreement),
    agreement_membership: {
      siblings: agreementMembership.siblings.map((value) => BigInt(value).toString()),
      path_bits: agreementMembership.pathBits,
    },
    payroll_membership: {
      siblings: payrollMembership.siblings.map((value) => BigInt(value).toString()),
      path_bits: payrollMembership.pathBits,
    },
    previous_state_salt: bytes32(input.previousStateSalt),
    next_state_salt: bytes32(input.nextStateSalt),
    external_attestation: attestation.witness,
    external_attestation_membership: attestation.membership,
    exception_entry: emptyExceptionEntryWitness(),
  };
  return {
    circuitInputs: [
      { ...common, shard_index: "0", ...aggregateCircuitFields(universal.shards[0]) },
      { ...common, shard_index: "1", ...aggregateCircuitFields(universal.shards[1]) },
    ],
    publicInputs: [publicBookFields(common, "0"), publicBookFields(common, "1")],
    scheduleId: transition.scheduleId,
    previousStateCommitment: transition.previousStateCommitment,
    nextStateCommitment: transition.nextStateCommitment,
    releaseNullifier: transition.releaseNullifier,
    bookEntry: universal.entry,
    bookEntryCommitment: universal.entryCommitment,
    totalsOpening: universal.totalsOpening,
    entryKind: "vesting",
  };
}

/**
 * Builds the v3 bookkeeping proof for an ordinary or agent payroll. Advanced
 * v2 authenticates private line semantics; v3 proves the complete contributor
 * count and optional public token totals across both ordered halves.
 */
export async function buildPayrollBookEntryInputs(input: {
  payroll: PayrollIntegrityInputBuild;
  ownerAddress: string;
  bookSealAddress?: string;
  periodStart: bigint;
  periodEnd: bigint;
  entryKind?: "ordinary" | "agent";
  totalsDisclosure?: "hidden" | "public";
  totalsSalt: string;
  attestation?: ExternalAttestationProofInput;
}): Promise<VestingTransitionInputBuild> {
  const entryKind = input.entryKind ?? "ordinary";
  const attestation = externalAttestationCircuitFields(
    input.attestation,
    input.payroll.policyRoot,
  );
  const attestedBinding = input.attestation
    ? input.payroll.proofBindings.find(({ agreementId }) => agreementId === input.attestation!.agreementId)
    : undefined;
  if (input.attestation && !attestedBinding) {
    throw new Error("External attestation selects an agreement outside this payroll.");
  }
  if (input.attestation && attestedBinding
    && BigInt(input.attestation.signed.attestation.subjectCommitment)
      !== BigInt(hexFromBytes(attestedBinding.agreement.recipient_commitment))) {
    throw new Error("External attestation belongs to another private recipient.");
  }
  const attestedMembership = attestedBinding
    ? (await createProofCommitter()).buildProofFixedMerkleMembership(
        input.payroll.proofBindings.map(({ agreementLeaf }) => agreementLeaf),
        attestedBinding.index,
      )
    : undefined;
  const attestationRoot = attestation.root;
  const universal = buildUniversalPayrollBookInput({
    payroll: input.payroll,
    entryKind,
    ownerAddress: input.ownerAddress,
    bookSealAddress: input.bookSealAddress,
    sourceSealAddress: input.payroll.publicInputs[0].sealAddress,
    periodStart: input.periodStart,
    periodEnd: input.periodEnd,
    totalsDisclosure: input.totalsDisclosure ?? "public",
    totalsSalt: input.totalsSalt,
    attestationRoot,
  });
  const common = {
    ...commonBookFields({
      payroll: input.payroll,
      universal,
      ownerAddress: input.ownerAddress,
      periodStart: input.periodStart,
      periodEnd: input.periodEnd,
      attestationRoot,
      totalsSalt: input.totalsSalt,
      entryKind,
      scheduleId: ZERO,
      previousStateCommitment: ZERO,
      nextStateCommitment: ZERO,
      releaseNullifier: ZERO,
    }),
    target_index: (attestedBinding?.index ?? 0).toString(),
    agreement: attestedBinding?.agreement ?? emptyAgreementWitness(),
    line: emptyPayrollLineWitness(),
    plan: emptyAdvancedPlanWitness(),
    agreement_membership: attestedMembership
      ? {
          siblings: attestedMembership.siblings.map((value) => BigInt(value).toString()),
          path_bits: attestedMembership.pathBits,
        }
      : { siblings: Array(6).fill("0"), path_bits: Array(6).fill(false) },
    payroll_membership: { siblings: Array(6).fill("0"), path_bits: Array(6).fill(false) },
    previous_state_salt: bytes32(ZERO),
    next_state_salt: bytes32(ZERO),
    external_attestation: attestation.witness,
    external_attestation_membership: attestation.membership,
    exception_entry: emptyExceptionEntryWitness(),
  };
  return {
    circuitInputs: [
      { ...common, shard_index: "0", ...aggregateCircuitFields(universal.shards[0]) },
      { ...common, shard_index: "1", ...aggregateCircuitFields(universal.shards[1]) },
    ],
    publicInputs: [publicBookFields(common, "0"), publicBookFields(common, "1")],
    scheduleId: ZERO,
    previousStateCommitment: ZERO,
    nextStateCommitment: ZERO,
    releaseNullifier: ZERO,
    bookEntry: universal.entry,
    bookEntryCommitment: universal.entryCommitment,
    totalsOpening: universal.totalsOpening,
    entryKind,
  };
}


export type ExceptionBookRemediationBinding = {
  remediationSecret: string;
  recipientCommitment: string;
  amountAtomic: string;
  referenceValueAtomic: string;
  actionSalt: string;
};

function joinedPublicCommitment(high: string, low: string): `0x${string}` {
  const left = BigInt(high);
  const right = BigInt(low);
  if (left < 0n || left >= 1n << 128n || right < 0n || right >= 1n << 128n) {
    throw new Error("Exception public-input commitment limb exceeds u128.");
  }
  return `0x${left.toString(16).padStart(32, "0")}${right.toString(16).padStart(32, "0")}`;
}

/**
 * Links an already-proved Claim v6 or Remediation v7 fact into the universal
 * v3 payroll book. Remediation totals are forced to the exact private action;
 * claims carry zero value and only record the durable proved obligation.
 */
export async function buildExceptionPayrollBookEntryInputs(input: {
  source: ExceptionPublicInputsV2;
  entryKind: "claim" | "remediation";
  bookSealAddress: string;
  sourceSealAddress: string;
  ownerAddress: string;
  runNullifier: string;
  periodStart: bigint;
  periodEnd: bigint;
  totalsSalt: string;
  totalsDisclosure?: "hidden" | "public";
  claimFact: ReturnType<typeof exceptionClaimFactSchema.parse>;
  remediation?: ExceptionBookRemediationBinding;
}): Promise<VestingTransitionInputBuild> {
  const claim = exceptionClaimFactSchema.parse(input.claimFact);
  const claimFactCommitment = claimFactCommitmentV2(claim);
  const sourceSubject = joinedPublicCommitment(
    input.source.subjectNullifierHigh, input.source.subjectNullifierLow,
  );
  const sourceParent = joinedPublicCommitment(
    input.source.parentNullifierHigh, input.source.parentNullifierLow,
  );
  const sourceFact = joinedPublicCommitment(
    input.source.factCommitmentHigh, input.source.factCommitmentLow,
  );
  const sourceParentFact = joinedPublicCommitment(
    input.source.parentFactCommitmentHigh, input.source.parentFactCommitmentLow,
  );
  const sourceManifest = joinedPublicCommitment(
    input.source.manifestRootHigh, input.source.manifestRootLow,
  );
  const sourceFx = joinedPublicCommitment(input.source.fxRootHigh, input.source.fxRootLow);
  const expectedClaimParent = BigInt(claim.statementCommitment) === 0n
    ? claim.snapshotCommitment
    : claim.statementCommitment;
  if (BigInt(input.runNullifier) !== BigInt(claim.runNullifier)) {
    throw new Error("Exception book run differs from the proved claim run.");
  }

  let remediationAmount: string | undefined;
  let exceptionWitness: ReturnType<typeof emptyExceptionEntryWitness>;
  if (input.entryKind === "claim") {
    if (BigInt(input.source.proofVersion) !== 6n
      || BigInt(sourceSubject) !== BigInt(claim.claimSubjectNullifier)
      || BigInt(sourceParent) !== BigInt(claim.runNullifier)
      || BigInt(sourceFact) !== BigInt(claimFactCommitment)
      || BigInt(sourceParentFact) !== BigInt(expectedClaimParent)
      || BigInt(sourceManifest) !== BigInt(claim.manifestRoot)) {
      throw new Error("Claim v6 public inputs do not match the private claim fact.");
    }
    if (input.remediation) throw new Error("A claim book entry cannot include remediation data.");
    exceptionWitness = {
      ...emptyExceptionEntryWitness(),
      enabled: true,
      claim_subject_nullifier: bytes32(claim.claimSubjectNullifier),
      snapshot_commitment: bytes32(claim.snapshotCommitment),
      statement_commitment: bytes32(claim.statementCommitment),
      claim_manifest_root: bytes32(claim.manifestRoot),
      agreement_leaf: bytes32(claim.agreementLeaf),
      target_index: claim.targetIndex.toString(),
      claim_kind: exceptionClaimKinds[claim.claimKind].toString(),
      shortfall_atomic: claim.shortfallAtomic,
      shortfall_unit: claimShortfallUnits[claim.shortfallUnit].toString(),
      obligation_token: exceptionTokens[claim.obligationToken].toString(),
      evidence_source: claimEvidenceSources[claim.evidenceSource].toString(),
    };
  } else {
    const remediation = input.remediation;
    if (!remediation) throw new Error("A remediation book entry requires private payment binding data.");
    const remediationSubject = remediationSubjectNullifierV2({
      claimSubjectNullifier: claim.claimSubjectNullifier,
      remediationSecret: remediation.remediationSecret,
    });
    const committer = await createProofCommitter();
    const actionCommitment = committer.proofRemediationActionCommitment({
      claimSubjectNullifier: claim.claimSubjectNullifier,
      recipientCommitment: remediation.recipientCommitment,
      token: exceptionTokens[claim.obligationToken],
      amountAtomic: remediation.amountAtomic,
      salt: remediation.actionSalt,
    });
    const remediationFact = remediationFactCommitmentV2({
      remediationSubjectNullifier: remediationSubject,
      claimSubjectNullifier: claim.claimSubjectNullifier,
      claimFactCommitment,
      recipientCommitment: remediation.recipientCommitment,
      token: claim.obligationToken,
      amountAtomic: remediation.amountAtomic,
      referenceValueAtomic: remediation.referenceValueAtomic,
      referenceUnit: claim.shortfallUnit,
      fxRoot: sourceFx,
    });
    if (BigInt(input.source.proofVersion) !== 7n
      || BigInt(sourceSubject) !== BigInt(remediationSubject)
      || BigInt(sourceParent) !== BigInt(claim.claimSubjectNullifier)
      || BigInt(sourceParentFact) !== BigInt(claimFactCommitment)
      || BigInt(sourceFact) !== BigInt(remediationFact)
      || BigInt(sourceManifest) !== BigInt(actionCommitment)) {
      throw new Error("Remediation v7 public inputs do not match the exact private payment.");
    }
    remediationAmount = BigInt(remediation.amountAtomic).toString();
    exceptionWitness = {
      enabled: true,
      claim_subject_nullifier: bytes32(claim.claimSubjectNullifier),
      snapshot_commitment: bytes32(claim.snapshotCommitment),
      statement_commitment: bytes32(claim.statementCommitment),
      claim_manifest_root: bytes32(claim.manifestRoot),
      agreement_leaf: bytes32(claim.agreementLeaf),
      target_index: claim.targetIndex.toString(),
      claim_kind: exceptionClaimKinds[claim.claimKind].toString(),
      shortfall_atomic: claim.shortfallAtomic,
      shortfall_unit: claimShortfallUnits[claim.shortfallUnit].toString(),
      obligation_token: exceptionTokens[claim.obligationToken].toString(),
      evidence_source: claimEvidenceSources[claim.evidenceSource].toString(),
      remediation_secret: bytes32(remediation.remediationSecret),
      recipient_commitment: bytes32(remediation.recipientCommitment),
      remediation_amount_atomic: remediationAmount,
      remediation_reference_value_atomic: BigInt(remediation.referenceValueAtomic).toString(),
      remediation_action_salt: bytes32(remediation.actionSalt),
    };
  }

  const universal = buildUniversalExceptionPayrollBookInput({
    source: input.source,
    entryKind: input.entryKind,
    bookSealAddress: input.bookSealAddress,
    sourceSealAddress: input.sourceSealAddress,
    ownerAddress: input.ownerAddress,
    runNullifier: input.runNullifier,
    periodStart: input.periodStart,
    periodEnd: input.periodEnd,
    totalsSalt: input.totalsSalt,
    totalsDisclosure: input.totalsDisclosure,
    ...(remediationAmount ? {
      payment: { token: claim.obligationToken, amountAtomic: remediationAmount },
    } : {}),
  });
  const disclosed = universal.entry.totalsDisclosure === "public";
  const shardZero = exposedAggregate(universal.shards[0].aggregate, disclosed);
  const shardOne = exposedAggregate(universal.shards[1].aggregate, disclosed);
  const totalsCommitment = limbs(universal.entry.totalsCommitment);
  const run = limbs(input.runNullifier);
  const zero = limbs(ZERO);
  const common: ReturnType<typeof commonBookFields> = {
    chain_id: input.source.chainId,
    seal_address: BigInt(input.bookSealAddress).toString(),
    proof_version: PAYO_VESTING_TRANSITION_PROOF_VERSION.toString(),
    schema_version: "1",
    entry_kind: universal.entryKindCode.toString(),
    agreement_root_high: input.source.agreementRootHigh,
    agreement_root_low: input.source.agreementRootLow,
    manifest_root_high: input.source.manifestRootHigh,
    manifest_root_low: input.source.manifestRootLow,
    policy_root_high: input.source.policyRootHigh,
    policy_root_low: input.source.policyRootLow,
    fx_root_high: input.source.fxRootHigh,
    fx_root_low: input.source.fxRootLow,
    run_nullifier_high: run.high,
    run_nullifier_low: run.low,
    subject_nullifier_high: input.source.subjectNullifierHigh,
    subject_nullifier_low: input.source.subjectNullifierLow,
    parent_fact_high: input.source.parentFactCommitmentHigh,
    parent_fact_low: input.source.parentFactCommitmentLow,
    fact_high: input.source.factCommitmentHigh,
    fact_low: input.source.factCommitmentLow,
    owner_address: BigInt(input.ownerAddress).toString(),
    source_seal_address: BigInt(input.sourceSealAddress).toString(),
    source_proof_version: input.source.proofVersion,
    attestation_root_high: zero.high,
    attestation_root_low: zero.low,
    shard_0_contributor_count: "1",
    shard_1_contributor_count: "0",
    totals_disclosed: disclosed ? "1" : "0",
    totals_commitment_high: totalsCommitment.high,
    totals_commitment_low: totalsCommitment.low,
    private_shard_0_strk_gross: universal.shards[0].aggregate.STRK.grossAtomic,
    private_shard_0_strk_deductions: universal.shards[0].aggregate.STRK.deductionsAtomic,
    private_shard_0_strk_net: universal.shards[0].aggregate.STRK.netAtomic,
    private_shard_0_usdc_gross: universal.shards[0].aggregate.USDC.grossAtomic,
    private_shard_0_usdc_deductions: universal.shards[0].aggregate.USDC.deductionsAtomic,
    private_shard_0_usdc_net: universal.shards[0].aggregate.USDC.netAtomic,
    private_shard_1_strk_gross: "0",
    private_shard_1_strk_deductions: "0",
    private_shard_1_strk_net: "0",
    private_shard_1_usdc_gross: "0",
    private_shard_1_usdc_deductions: "0",
    private_shard_1_usdc_net: "0",
    totals_salt: bytes32(input.totalsSalt),
    shard_0_strk_gross: shardZero.STRK.grossAtomic,
    shard_0_strk_deductions: shardZero.STRK.deductionsAtomic,
    shard_0_strk_net: shardZero.STRK.netAtomic,
    shard_0_usdc_gross: shardZero.USDC.grossAtomic,
    shard_0_usdc_deductions: shardZero.USDC.deductionsAtomic,
    shard_0_usdc_net: shardZero.USDC.netAtomic,
    shard_1_strk_gross: shardOne.STRK.grossAtomic,
    shard_1_strk_deductions: shardOne.STRK.deductionsAtomic,
    shard_1_strk_net: shardOne.STRK.netAtomic,
    shard_1_usdc_gross: shardOne.USDC.grossAtomic,
    shard_1_usdc_deductions: shardOne.USDC.deductionsAtomic,
    shard_1_usdc_net: shardOne.USDC.netAtomic,
    schedule_id_high: zero.high,
    schedule_id_low: zero.low,
    previous_state_high: zero.high,
    previous_state_low: zero.low,
    next_state_high: zero.high,
    next_state_low: zero.low,
    release_nullifier_high: zero.high,
    release_nullifier_low: zero.low,
    book_entry_high: universal.entryCommitmentLimbs.high,
    book_entry_low: universal.entryCommitmentLimbs.low,
    period_start: input.periodStart.toString(),
    period_end: input.periodEnd.toString(),
    validity_start: input.source.validityStart,
    validity_expiry: input.source.validityExpiry,
  };
  const circuitBase = {
    ...common,
    target_index: "0",
    agreement: emptyAgreementWitness(),
    line: emptyPayrollLineWitness(),
    plan: emptyAdvancedPlanWitness(),
    agreement_membership: { siblings: Array(6).fill("0"), path_bits: Array(6).fill(false) },
    payroll_membership: { siblings: Array(6).fill("0"), path_bits: Array(6).fill(false) },
    previous_state_salt: bytes32(ZERO),
    next_state_salt: bytes32(ZERO),
    external_attestation: emptyExternalAttestationCircuitFields().witness,
    external_attestation_membership: emptyExternalAttestationCircuitFields().membership,
    exception_entry: exceptionWitness,
  };
  return {
    circuitInputs: [
      { ...circuitBase, shard_index: "0", ...aggregateCircuitFields(universal.shards[0]) },
      { ...circuitBase, shard_index: "1", ...aggregateCircuitFields(universal.shards[1]) },
    ],
    publicInputs: [publicBookFields(common, "0"), publicBookFields(common, "1")],
    scheduleId: ZERO,
    previousStateCommitment: ZERO,
    nextStateCommitment: ZERO,
    releaseNullifier: ZERO,
    bookEntry: universal.entry,
    bookEntryCommitment: universal.entryCommitment,
    totalsOpening: universal.totalsOpening,
    entryKind: input.entryKind,
  };
}
