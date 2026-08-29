import type { InputMap } from "@noir-lang/noir_js";
import { splitHashToU128 } from "@/lib/crypto/commitments";
import { normalizedHexBytes, toHex } from "@/lib/crypto/encoding";
import {
  claimCapabilityCommitmentV2,
  claimFactCommitmentV2,
  claimShortfallUnits,
  claimSubjectNullifierV2,
  exceptionClaimFactSchema,
  exceptionClaimKinds,
  exceptionTokens,
  obligationSnapshotCommitmentV2,
  obligationSnapshotV2Schema,
  payrollStatementCommitmentV2,
  payrollStatementV2Schema,
  remediationFactCommitmentV2,
  remediationSubjectNullifierV2,
  type ClaimEvidenceSource,
  type ClaimShortfallUnit,
  type ExceptionClaimKind,
  type ExceptionPublicInputsV2,
  type ExceptionToken,
  type ObligationSnapshotV2,
  type PayrollStatementV2,
} from "@/lib/domain/exception-protocol";
import {
  fxSnapshotCommitment,
  toCircuitFxSnapshot,
  type FxSnapshot,
} from "@/lib/domain/fx";
import { calculatePayrollLine } from "@/lib/domain/payroll";
import {
  createProofCommitter,
  PAYO_PROOF_EMPTY_LEAF,
} from "./commitments";
import {
  type FxSnapshotCircuitWitness,
  type MerkleCircuitWitness,
  type PayrollAgreementCircuitWitness,
  type PayrollAgreementSnapshotBuild,
  type PayrollIntegrityInputBuild,
  type PayrollLineCircuitWitness,
} from "./input-builder";

const ZERO = `0x${"00".repeat(32)}` as const;
const ZERO_BYTES = Array(32).fill(0) as number[];
const MAX_LINES = 64;
const MAX_REAL_LINES = 50;

function bytes32(value: string): number[] {
  return [...normalizedHexBytes(value, 32)];
}

function limbs(value: string): { high: string; low: string } {
  const split = splitHashToU128(value);
  return { high: split.high.toString(), low: split.low.toString() };
}

function boundedU64(value: bigint, label: string): string {
  if (value < 0n || value >= 1n << 64n) throw new Error(`${label} must fit in u64.`);
  return value.toString();
}

function boundedU128(value: bigint, label: string, positive = false): string {
  if (value < (positive ? 1n : 0n) || value >= 1n << 128n) {
    throw new Error(`${label} must fit in ${positive ? "a positive " : ""}u128.`);
  }
  return value.toString();
}

function padded<T>(items: readonly T[], length: number, empty: () => T): T[] {
  if (items.length > length) throw new Error(`Cannot pad ${items.length} values into ${length} slots.`);
  return [...items, ...Array.from({ length: length - items.length }, empty)];
}

function emptyLine(): PayrollLineCircuitWitness {
  return {
    active: false,
    deductions: Array(8).fill("0"),
    deductions_count: "0",
    policy_slot: "0",
    fx_slot: "0",
    salt: [...ZERO_BYTES],
    classification_treatment: "0",
    final_included_mask: "0",
    reference_value_atomic: "0",
  };
}

function emptyFxSnapshot(): FxSnapshotCircuitWitness {
  return {
    token: "0",
    token_decimals: "0",
    reference_currency: "0",
    quote_decimals: "0",
    feed_commitment: [...ZERO_BYTES],
    sources_commitment: [...ZERO_BYTES],
    price_numerator: "0",
    price_denominator: "0",
    observed_at: "0",
    source_count: "0",
    minimum_source_count: "0",
    maximum_age_seconds: "0",
    haircut_bps: "0",
  };
}

function emptyMembership(): MerkleCircuitWitness {
  return { siblings: Array(6).fill("0"), path_bits: Array(6).fill(false) };
}

function circuitFx(snapshot: FxSnapshot): FxSnapshotCircuitWitness {
  const value = toCircuitFxSnapshot(snapshot);
  return {
    token: value.token.toString(),
    token_decimals: value.tokenDecimals.toString(),
    reference_currency: value.referenceCurrency.toString(),
    quote_decimals: value.quoteDecimals.toString(),
    feed_commitment: bytes32(value.feedCommitment),
    sources_commitment: bytes32(value.sourcesCommitment),
    price_numerator: value.priceNumerator,
    price_denominator: value.priceDenominator,
    observed_at: value.observedAt,
    source_count: value.sourceCount.toString(),
    minimum_source_count: value.minimumSourceCount.toString(),
    maximum_age_seconds: value.maximumAgeSeconds,
    haircut_bps: value.haircutBps.toString(),
  };
}

function publicInputs(input: {
  chainId: string;
  sealAddress: string;
  proofVersion: number;
  agreementRoot: string;
  manifestRoot: string;
  policyRoot: string;
  fxRoot: string;
  subjectNullifier: string;
  parentNullifier: string;
  factCommitment: string;
  parentFactCommitment: string;
  validityStart: bigint;
  validityExpiry: bigint;
}): ExceptionPublicInputsV2 {
  if (BigInt(input.chainId) === 0n || BigInt(input.sealAddress) === 0n) {
    throw new Error("An exception proof requires non-zero deployment binding.");
  }
  if (
    input.validityStart < 0n
    || input.validityExpiry < input.validityStart
    || input.validityExpiry - input.validityStart > 3_600n
  ) throw new Error("Exception proof validity must be ordered and no longer than one hour.");
  const agreement = limbs(input.agreementRoot);
  const manifest = limbs(input.manifestRoot);
  const policy = limbs(input.policyRoot);
  const fx = limbs(input.fxRoot);
  const subject = limbs(input.subjectNullifier);
  const parent = limbs(input.parentNullifier);
  const fact = limbs(input.factCommitment);
  const parentFact = limbs(input.parentFactCommitment);
  return {
    chainId: BigInt(input.chainId).toString(),
    sealAddress: BigInt(input.sealAddress).toString(),
    proofVersion: input.proofVersion.toString(),
    schemaVersion: "2",
    agreementRootHigh: agreement.high,
    agreementRootLow: agreement.low,
    manifestRootHigh: manifest.high,
    manifestRootLow: manifest.low,
    policyRootHigh: policy.high,
    policyRootLow: policy.low,
    fxRootHigh: fx.high,
    fxRootLow: fx.low,
    subjectNullifierHigh: subject.high,
    subjectNullifierLow: subject.low,
    parentNullifierHigh: parent.high,
    parentNullifierLow: parent.low,
    factCommitmentHigh: fact.high,
    factCommitmentLow: fact.low,
    parentFactCommitmentHigh: parentFact.high,
    parentFactCommitmentLow: parentFact.low,
    validityStart: boundedU64(input.validityStart, "Validity start"),
    validityExpiry: boundedU64(input.validityExpiry, "Validity expiry"),
    shardIndex: "0",
  };
}

function circuitPublicInputs(inputs: ExceptionPublicInputsV2): InputMap {
  return {
    chain_id: inputs.chainId,
    seal_address: inputs.sealAddress,
    proof_version: inputs.proofVersion,
    schema_version: inputs.schemaVersion,
    agreement_root_high: inputs.agreementRootHigh,
    agreement_root_low: inputs.agreementRootLow,
    manifest_root_high: inputs.manifestRootHigh,
    manifest_root_low: inputs.manifestRootLow,
    policy_root_high: inputs.policyRootHigh,
    policy_root_low: inputs.policyRootLow,
    fx_root_high: inputs.fxRootHigh,
    fx_root_low: inputs.fxRootLow,
    subject_nullifier_high: inputs.subjectNullifierHigh,
    subject_nullifier_low: inputs.subjectNullifierLow,
    parent_nullifier_high: inputs.parentNullifierHigh,
    parent_nullifier_low: inputs.parentNullifierLow,
    fact_commitment_high: inputs.factCommitmentHigh,
    fact_commitment_low: inputs.factCommitmentLow,
    parent_fact_commitment_high: inputs.parentFactCommitmentHigh,
    parent_fact_commitment_low: inputs.parentFactCommitmentLow,
    validity_start: inputs.validityStart,
    validity_expiry: inputs.validityExpiry,
    shard_index: inputs.shardIndex,
  };
}

export type ObligationSnapshotLineBinding = {
  index: number;
  agreementId: string;
  calculated: PayrollAgreementSnapshotBuild["calculatedLines"][number];
  agreementLeaf: `0x${string}`;
  agreement: PayrollAgreementCircuitWitness;
  claimCapabilityCommitment: `0x${string}`;
  expectedNetAtomic: string;
  claimLeaf: `0x${string}`;
  agreementMembership: MerkleCircuitWitness;
  claimMembership: MerkleCircuitWitness;
};

export type ObligationSnapshotPlanBuild = {
  snapshot: ObligationSnapshotV2;
  snapshotCommitment: `0x${string}`;
  claimRoot: `0x${string}`;
  lines: ObligationSnapshotLineBinding[];
};

export type ObligationSnapshotLinkBuild = ObligationSnapshotPlanBuild & {
  circuitInputs: InputMap;
  publicInputs: ExceptionPublicInputsV2;
};

/** Creates the immutable pre-payday fact without generating a proof. */
export async function buildObligationSnapshotPlanInputs(input: {
  ownerAddress: string;
  payroll: PayrollAgreementSnapshotBuild;
  claimCapabilityCommitments: Readonly<Record<string, string>>;
  graceEndsAt: bigint;
  claimEndsAt: bigint;
}): Promise<ObligationSnapshotPlanBuild> {
  if (input.payroll.proofBindings.length < 1 || input.payroll.proofBindings.length > MAX_REAL_LINES) {
    throw new Error("An obligation snapshot requires 1–50 payroll obligations.");
  }
  const dueAt = input.payroll.proofBindings[0].source.dueAt;
  if (input.payroll.proofBindings.some((binding) => binding.source.dueAt !== dueAt)) {
    throw new Error("One obligation snapshot can contain only obligations with the same payday.");
  }
  const committer = await createProofCommitter();
  const baseLeaves = input.payroll.proofBindings.map(({ agreementLeaf }) => agreementLeaf);
  const claimLeaves = input.payroll.proofBindings.map((binding) => {
    const capability = input.claimCapabilityCommitments[binding.agreementId];
    if (!capability) throw new Error(`Agreement ${binding.agreementId} has no worker claim capability commitment.`);
    const expectedNetAtomic = boundedU128(BigInt(binding.calculated.netAtomic), "Expected claim minimum", true);
    return committer.proofClaimObligationCommitment({
      agreementLeaf: binding.agreementLeaf,
      claimCapabilityCommitment: capability,
      expectedNetAtomic,
    });
  });
  const claimRoot = committer.buildProofFixedMerkleRoot(claimLeaves);
  if (committer.buildProofFixedMerkleRoot(baseLeaves) !== input.payroll.agreementRoot) {
    throw new Error("The snapshot agreement leaves do not reconstruct PayrollIntegrity's agreement root.");
  }
  const snapshot = obligationSnapshotV2Schema.parse({
    schemaVersion: 2,
    runNullifier: input.payroll.runNullifier,
    baseAgreementRoot: input.payroll.agreementRoot,
    obligationRoot: claimRoot,
    policyRoot: input.payroll.policyRoot,
    ownerAddress: toHex(normalizedHexBytes(input.ownerAddress, 32)),
    dueAt: boundedU64(dueAt, "Snapshot payday"),
    graceEndsAt: boundedU64(input.graceEndsAt, "Snapshot grace deadline"),
    claimEndsAt: boundedU64(input.claimEndsAt, "Snapshot claim deadline"),
    availabilityCommitment: claimRoot,
  });
  const snapshotCommitment = obligationSnapshotCommitmentV2(snapshot);
  const lines = input.payroll.proofBindings.map((binding, index) => ({
    index,
    agreementId: binding.agreementId,
    calculated: binding.calculated,
    agreementLeaf: binding.agreementLeaf,
    agreement: binding.agreement,
    claimCapabilityCommitment: toHex(normalizedHexBytes(input.claimCapabilityCommitments[binding.agreementId], 32)),
    expectedNetAtomic: binding.calculated.netAtomic,
    claimLeaf: claimLeaves[index],
    agreementMembership: (() => {
      const membership = committer.buildProofFixedMerkleMembership(baseLeaves, index);
      return { siblings: membership.siblings.map((value) => BigInt(value).toString()), path_bits: membership.pathBits };
    })(),
    claimMembership: (() => {
      const membership = committer.buildProofFixedMerkleMembership(claimLeaves, index);
      return { siblings: membership.siblings.map((value) => BigInt(value).toString()), path_bits: membership.pathBits };
    })(),
  }));
  return { snapshot, snapshotCommitment, claimRoot, lines };
}

export async function buildObligationSnapshotLinkInputs(input: {
  chainId: string;
  sealAddress: string;
  ownerAddress: string;
  payroll: PayrollIntegrityInputBuild;
  claimCapabilityCommitments: Readonly<Record<string, string>>;
  graceEndsAt: bigint;
  claimEndsAt: bigint;
  validityStart: bigint;
  validityExpiry: bigint;
}): Promise<ObligationSnapshotLinkBuild> {
  const plan = await buildObligationSnapshotPlanInputs({
    ownerAddress: input.ownerAddress,
    payroll: input.payroll,
    claimCapabilityCommitments: input.claimCapabilityCommitments,
    graceEndsAt: input.graceEndsAt,
    claimEndsAt: input.claimEndsAt,
  });
  const proofPublicInputs = publicInputs({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    proofVersion: 5,
    agreementRoot: input.payroll.agreementRoot,
    manifestRoot: plan.claimRoot,
    policyRoot: input.payroll.policyRoot,
    fxRoot: ZERO,
    subjectNullifier: input.payroll.runNullifier,
    parentNullifier: ZERO,
    factCommitment: plan.snapshotCommitment,
    parentFactCommitment: ZERO,
    validityStart: input.validityStart,
    validityExpiry: input.validityExpiry,
  });
  return {
    ...plan,
    publicInputs: proofPublicInputs,
    circuitInputs: {
      ...circuitPublicInputs(proofPublicInputs),
      run_nullifier: bytes32(input.payroll.runNullifier),
      policy_root: bytes32(input.payroll.policyRoot),
      owner_address: bytes32(plan.snapshot.ownerAddress),
      due_at: plan.snapshot.dueAt,
      grace_ends_at: plan.snapshot.graceEndsAt,
      claim_ends_at: plan.snapshot.claimEndsAt,
      base_agreement_leaves: padded(plan.lines.map(({ agreementLeaf }) => BigInt(agreementLeaf).toString()), MAX_LINES, () => BigInt(PAYO_PROOF_EMPTY_LEAF).toString()),
      claim_capability_commitments: padded(plan.lines.map(({ claimCapabilityCommitment }) => bytes32(claimCapabilityCommitment)), MAX_REAL_LINES, () => [...ZERO_BYTES]),
      expected_net_amounts: padded(plan.lines.map(({ expectedNetAtomic }) => expectedNetAtomic), MAX_REAL_LINES, () => "0"),
    },
  };
}

export type PayrollStatementEvidence = {
  source: "employer_statement" | "settlement_match";
  observedAt: bigint;
  availabilityCommitment: string;
  target: ({ kind: "empty" } | {
    kind: "line";
    deductionsAtomic: string[];
    lineSalt: string;
    classificationTreatment: 1 | 2;
    finalIncludedMask: number;
    referenceValueAtomic: string;
  }) & {
    manifestRoot?: string;
    manifestMembership?: {
      siblings: readonly string[];
      pathBits: readonly boolean[];
    };
  };
  fxSnapshots?: readonly FxSnapshot[];
  selectedFxIndex?: number;
};

export type WageClaimSnapshotBuild = Pick<
  ObligationSnapshotLinkBuild,
  "snapshot" | "snapshotCommitment" | "claimRoot" | "lines"
>;

export type WageClaimV2Build = {
  circuitInputs: InputMap;
  publicInputs: ExceptionPublicInputsV2;
  claimFact: ReturnType<typeof exceptionClaimFactSchema.parse>;
  claimFactCommitment: `0x${string}`;
  claimSubjectNullifier: `0x${string}`;
  statement?: PayrollStatementV2;
  statementCommitment: `0x${string}`;
  snapshot: WageClaimSnapshotBuild;
  target: ObligationSnapshotLineBinding;
};

function statementLine(input: {
  target: ObligationSnapshotLineBinding;
  evidence: Extract<PayrollStatementEvidence["target"], { kind: "line" }>;
}): { witness: PayrollLineCircuitWitness; leaf: Promise<`0x${string}`> } {
  const count = input.evidence.deductionsAtomic.length;
  if (count > 8) throw new Error("A statement line supports at most eight deductions.");
  const original = input.target.calculated;
  const calculated = calculatePayrollLine({
    agreementId: original.agreementId,
    recipientAddress: original.recipientAddress,
    token: original.token,
    earningsAtomic: original.earningsAtomic,
    deductionsAtomic: input.evidence.deductionsAtomic,
    committedPolicyId: original.committedPolicyId,
    scheduleCommitment: original.scheduleCommitment,
    salt: toHex(normalizedHexBytes(input.evidence.lineSalt, 32)),
  });
  const witness: PayrollLineCircuitWitness = {
    active: true,
    deductions: padded(input.evidence.deductionsAtomic, 8, () => "0"),
    deductions_count: count.toString(),
    policy_slot: "0",
    fx_slot: "0",
    salt: bytes32(input.evidence.lineSalt),
    classification_treatment: input.evidence.classificationTreatment.toString(),
    final_included_mask: input.evidence.finalIncludedMask.toString(),
    reference_value_atomic: boundedU128(BigInt(input.evidence.referenceValueAtomic), "Statement reference value"),
  };
  return {
    witness,
    leaf: createProofCommitter().then((committer) => committer.proofPayrollCommitment(
      calculated,
      input.target.agreementLeaf,
      {
        classificationTreatment: input.evidence.classificationTreatment,
        finalIncludedMask: input.evidence.finalIncludedMask,
        referenceValueAtomic: input.evidence.referenceValueAtomic,
      },
    )),
  };
}

async function fxEvidence(input: {
  snapshots?: readonly FxSnapshot[];
  selectedIndex?: number;
}) {
  if (!input.snapshots?.length) {
    return { root: ZERO, snapshot: emptyFxSnapshot(), membership: emptyMembership() };
  }
  if (input.snapshots.length > 2) throw new Error("An exception FX catalog supports at most two snapshots.");
  const selectedIndex = input.selectedIndex ?? 0;
  if (!Number.isInteger(selectedIndex) || selectedIndex < 0 || selectedIndex >= input.snapshots.length) {
    throw new Error("The selected exception FX snapshot is unavailable.");
  }
  const committer = await createProofCommitter();
  const commitments = input.snapshots.map(fxSnapshotCommitment);
  const catalog = committer.buildProofCatalog(commitments);
  const membership = catalog.memberships[selectedIndex];
  return {
    root: catalog.root,
    snapshot: circuitFx(input.snapshots[selectedIndex]),
    membership: {
      siblings: membership.siblings.map((value) => BigInt(value).toString()),
      path_bits: membership.pathBits,
    },
  };
}

function sumRequiredFinalShortfall(agreement: PayrollAgreementCircuitWitness, includedMask: number): bigint {
  if (!agreement.final_pay_mode || Number(agreement.final_required_mask) === 0) {
    throw new Error("The selected agreement has no committed final-pay requirement.");
  }
  let shortfall = 0n;
  const requiredMask = Number(agreement.final_required_mask);
  for (let index = 0; index < 5; index += 1) {
    if ((requiredMask & (1 << index)) !== 0 && (includedMask & (1 << index)) === 0) {
      const component = BigInt(agreement.final_components[index]);
      if (component <= 0n) throw new Error("A required final-pay component is zero.");
      shortfall += component;
    }
  }
  if (shortfall === 0n) throw new Error("The statement contains every required final-pay component.");
  return shortfall;
}

export async function buildWageClaimV2Inputs(input: {
  chainId: string;
  sealAddress: string;
  snapshot: WageClaimSnapshotBuild;
  agreementId: string;
  claimCapabilitySecret: string;
  claimKind: ExceptionClaimKind;
  evidence: { source: "unsettled_period" } | PayrollStatementEvidence;
  validityStart: bigint;
  validityExpiry: bigint;
}): Promise<WageClaimV2Build> {
  const target = input.snapshot.lines.find(({ agreementId }) => agreementId === input.agreementId);
  if (!target) throw new Error("The selected agreement is not part of the immutable obligation snapshot.");
  const capability = claimCapabilityCommitmentV2(input.claimCapabilitySecret);
  if (capability !== target.claimCapabilityCommitment) {
    throw new Error("This vault does not control the worker claim capability committed before payday.");
  }
  if (input.validityStart < BigInt(input.snapshot.snapshot.graceEndsAt)) {
    throw new Error("The committed wage-claim grace period has not ended.");
  }
  if (input.validityStart > BigInt(input.snapshot.snapshot.claimEndsAt)) {
    throw new Error("The committed wage-claim deadline has passed.");
  }
  const hasStatement = input.evidence.source !== "unsettled_period";
  if (!hasStatement && input.claimKind !== "missing_obligation") {
    throw new Error("FX-floor and final-pay claims require an immutable employer statement or SettlementMatch anchor.");
  }
  const committer = await createProofCommitter();
  let line = emptyLine();
  let statement: PayrollStatementV2 | undefined;
  let statementCommitment = ZERO as `0x${string}`;
  let manifestRoot = ZERO as `0x${string}`;
  let manifestMembership = emptyMembership();
  let fx = { root: ZERO as `0x${string}`, snapshot: emptyFxSnapshot(), membership: emptyMembership() };
  if (hasStatement) {
    const evidence = input.evidence as PayrollStatementEvidence;
    const targetStatement = evidence.target.kind === "line"
      ? statementLine({ target, evidence: evidence.target })
      : undefined;
    if (input.claimKind === "missing_obligation" && targetStatement) {
      throw new Error("A missing-obligation statement must keep the target settlement slot empty.");
    }
    if (input.claimKind !== "missing_obligation" && !targetStatement) {
      throw new Error("The selected claim requires an actual anchored settlement line.");
    }
    line = targetStatement?.witness ?? emptyLine();
    const targetLeaf = targetStatement ? await targetStatement.leaf : PAYO_PROOF_EMPTY_LEAF;
    if (evidence.target.manifestMembership) {
      const opening = evidence.target.manifestMembership;
      if (opening.siblings.length !== 6 || opening.pathBits.length !== 6) {
        throw new Error("The statement manifest opening must contain six Merkle levels.");
      }
      const expectedPath = opening.pathBits.every(
        (bit, level) => bit === Boolean((target.index >> level) & 1),
      );
      if (!expectedPath) {
        throw new Error("The statement manifest opening targets a different payroll slot.");
      }
      const reconstructed = opening.siblings.reduce(
        (current, sibling, level) => opening.pathBits[level]
          ? committer.proofMerkleNode(sibling, current)
          : committer.proofMerkleNode(current, sibling),
        targetLeaf as `0x${string}`,
      );
      if (!evidence.target.manifestRoot || BigInt(reconstructed) !== BigInt(evidence.target.manifestRoot)) {
        throw new Error("The worker statement line does not open the registered manifest root.");
      }
      manifestRoot = toHex(normalizedHexBytes(evidence.target.manifestRoot, 32));
      manifestMembership = {
        siblings: opening.siblings.map((value) => BigInt(value).toString()),
        path_bits: [...opening.pathBits],
      };
    } else {
      if (input.snapshot.lines.length !== 1 || target.index !== 0) {
        throw new Error("A multi-worker statement requires the target worker Merkle opening.");
      }
      const opening = committer.buildProofFixedMerkleMembership([targetLeaf], 0);
      manifestRoot = opening.root;
      manifestMembership = {
        siblings: opening.siblings.map((value) => BigInt(value).toString()),
        path_bits: opening.pathBits,
      };
    }
    fx = input.claimKind === "below_committed_floor"
      ? await fxEvidence({ snapshots: evidence.fxSnapshots, selectedIndex: evidence.selectedFxIndex })
      : fx;
    if (input.claimKind === "below_committed_floor" && fx.root === ZERO) {
      throw new Error("An FX-floor claim requires its original committed FX snapshot.");
    }
    statement = payrollStatementV2Schema.parse({
      schemaVersion: 2,
      runNullifier: input.snapshot.snapshot.runNullifier,
      snapshotCommitment: input.snapshot.snapshotCommitment,
      manifestRoot,
      fxRoot: input.claimKind === "below_committed_floor" ? fx.root : ZERO,
      availabilityCommitment: toHex(normalizedHexBytes(evidence.availabilityCommitment, 32)),
      observedAt: boundedU64(evidence.observedAt, "Statement observation time"),
      source: evidence.source,
    });
    statementCommitment = payrollStatementCommitmentV2(statement);
  }
  const token: ExceptionToken = target.agreement.token === "0" ? "STRK" : "USDC";
  let shortfall: bigint;
  let shortfallUnit: ClaimShortfallUnit;
  if (input.claimKind === "missing_obligation") {
    shortfall = BigInt(target.expectedNetAtomic);
    shortfallUnit = token === "STRK" ? "strk_atomic" : "usdc_atomic";
  } else if (input.claimKind === "below_committed_floor") {
    const floor = BigInt(target.agreement.fx_floor_atomic);
    const actual = BigInt(line.reference_value_atomic);
    if (floor === 0n || actual >= floor) throw new Error("The anchored statement meets the committed FX floor.");
    const selectedFx = fx.snapshot;
    const net = target.agreement.earnings.slice(0, Number(target.agreement.earnings_count))
      .reduce((total, amount) => total + BigInt(amount), 0n)
      - line.deductions.slice(0, Number(line.deductions_count)).reduce((total, amount) => total + BigInt(amount), 0n);
    const reference = net * BigInt(selectedFx.price_numerator) / BigInt(selectedFx.price_denominator)
      * BigInt(10_000 - Number(selectedFx.haircut_bps)) / 10_000n;
    if (reference !== actual) throw new Error("The statement reference value does not match its committed FX snapshot.");
    shortfall = floor - actual;
    shortfallUnit = target.agreement.reference_currency === "0" ? "usd_6" : "gbp_6";
  } else {
    shortfall = sumRequiredFinalShortfall(target.agreement, Number(line.final_included_mask));
    shortfallUnit = token === "STRK" ? "strk_atomic" : "usdc_atomic";
  }
  const claimSubjectNullifier = claimSubjectNullifierV2({
    claimCapabilitySecret: input.claimCapabilitySecret,
    runNullifier: input.snapshot.snapshot.runNullifier,
    agreementLeaf: target.agreementLeaf,
    claimKind: input.claimKind,
  });
  const claimFact = exceptionClaimFactSchema.parse({
    claimSubjectNullifier,
    runNullifier: input.snapshot.snapshot.runNullifier,
    snapshotCommitment: input.snapshot.snapshotCommitment,
    statementCommitment,
    manifestRoot,
    agreementLeaf: target.agreementLeaf,
    targetIndex: target.index,
    claimKind: input.claimKind,
    shortfallAtomic: boundedU128(shortfall, "Claim shortfall", true),
    shortfallUnit,
    obligationToken: token,
    evidenceSource: input.evidence.source,
  });
  const claimFactCommitment = claimFactCommitmentV2(claimFact);
  const proofPublicInputs = publicInputs({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    proofVersion: 6,
    agreementRoot: input.snapshot.snapshot.baseAgreementRoot,
    manifestRoot,
    policyRoot: input.snapshot.snapshot.policyRoot,
    fxRoot: fx.root,
    subjectNullifier: claimSubjectNullifier,
    parentNullifier: input.snapshot.snapshot.runNullifier,
    factCommitment: claimFactCommitment,
    parentFactCommitment: statementCommitment === ZERO ? input.snapshot.snapshotCommitment : statementCommitment,
    validityStart: input.validityStart,
    validityExpiry: input.validityExpiry,
  });
  return {
    publicInputs: proofPublicInputs,
    claimFact,
    claimFactCommitment,
    claimSubjectNullifier,
    statement,
    statementCommitment,
    snapshot: input.snapshot,
    target,
    circuitInputs: {
      ...circuitPublicInputs(proofPublicInputs),
      run_nullifier: bytes32(input.snapshot.snapshot.runNullifier),
      policy_root: bytes32(input.snapshot.snapshot.policyRoot),
      snapshot_owner_address: bytes32(input.snapshot.snapshot.ownerAddress),
      snapshot_due_at: input.snapshot.snapshot.dueAt,
      snapshot_grace_ends_at: input.snapshot.snapshot.graceEndsAt,
      snapshot_claim_ends_at: input.snapshot.snapshot.claimEndsAt,
      target_index: target.index.toString(),
      agreement: target.agreement,
      agreement_siblings: target.agreementMembership.siblings,
      agreement_path_bits: target.agreementMembership.path_bits,
      claim_capability_secret: bytes32(input.claimCapabilitySecret),
      expected_net_atomic: target.expectedNetAtomic,
      claim_siblings: target.claimMembership.siblings,
      claim_path_bits: target.claimMembership.path_bits,
      claim_kind: exceptionClaimKinds[input.claimKind].toString(),
      evidence_source: ({ unsettled_period: 0, employer_statement: 2, settlement_match: 3 } as const)[input.evidence.source].toString(),
      statement_availability_commitment: statement ? bytes32(statement.availabilityCommitment) : [...ZERO_BYTES],
      statement_observed_at: statement?.observedAt ?? "0",
      line,
      manifest_siblings: manifestMembership.siblings,
      manifest_path_bits: manifestMembership.path_bits,
      fx_snapshot: fx.snapshot,
      fx_membership: fx.membership,
    },
  };
}

export type AcceptedWageClaimV2Build = {
  claimFact: WageClaimV2Build["claimFact"];
  claimFactCommitment: WageClaimV2Build["claimFactCommitment"];
  claimSubjectNullifier: WageClaimV2Build["claimSubjectNullifier"];
  snapshot: {
    snapshot: Pick<ObligationSnapshotV2, "baseAgreementRoot" | "policyRoot">;
  };
  target: Pick<ObligationSnapshotLineBinding, "agreement" | "agreementMembership">;
};

export type WageRemediationV2Build = {
  circuitInputs: InputMap;
  publicInputs: ExceptionPublicInputsV2;
  remediationSubjectNullifier: `0x${string}`;
  remediationFactCommitment: `0x${string}`;
  actionCommitment: `0x${string}`;
  fxRoot: `0x${string}`;
  referenceValueAtomic: string;
  claim: AcceptedWageClaimV2Build;
};

export async function buildWageRemediationV2Inputs(input: {
  chainId: string;
  sealAddress: string;
  claim: AcceptedWageClaimV2Build;
  remediationSecret: string;
  actionSalt: string;
  amountAtomic: string;
  token: ExceptionToken;
  fxSnapshots?: readonly FxSnapshot[];
  selectedFxIndex?: number;
  validityStart: bigint;
  validityExpiry: bigint;
}): Promise<WageRemediationV2Build> {
  if (input.token !== input.claim.claimFact.obligationToken) {
    throw new Error("The remediation token must equal the accepted claim obligation token.");
  }
  const amount = BigInt(input.amountAtomic);
  boundedU128(amount, "Remediation amount", true);
  const isFx = input.claim.claimFact.claimKind === "below_committed_floor";
  const fx = isFx
    ? await fxEvidence({ snapshots: input.fxSnapshots, selectedIndex: input.selectedFxIndex })
    : { root: ZERO as `0x${string}`, snapshot: emptyFxSnapshot(), membership: emptyMembership() };
  if (isFx && fx.root === ZERO) throw new Error("An FX remediation requires a fresh committed conversion snapshot.");
  const referenceValue = isFx
    ? amount * BigInt(fx.snapshot.price_numerator) / BigInt(fx.snapshot.price_denominator)
      * BigInt(10_000 - Number(fx.snapshot.haircut_bps)) / 10_000n
    : amount;
  if (referenceValue < BigInt(input.claim.claimFact.shortfallAtomic)) {
    throw new Error("The remediation is below the accepted typed shortfall.");
  }
  const remediationSubjectNullifier = remediationSubjectNullifierV2({
    claimSubjectNullifier: input.claim.claimSubjectNullifier,
    remediationSecret: input.remediationSecret,
  });
  const committer = await createProofCommitter();
  const actionCommitment = committer.proofRemediationActionCommitment({
    claimSubjectNullifier: input.claim.claimSubjectNullifier,
    recipientCommitment: toHex(Uint8Array.from(input.claim.target.agreement.recipient_commitment)),
    token: exceptionTokens[input.token],
    amountAtomic: amount,
    salt: input.actionSalt,
  });
  const remediationFactCommitment = remediationFactCommitmentV2({
    remediationSubjectNullifier,
    claimSubjectNullifier: input.claim.claimSubjectNullifier,
    claimFactCommitment: input.claim.claimFactCommitment,
    recipientCommitment: toHex(Uint8Array.from(input.claim.target.agreement.recipient_commitment)),
    token: input.token,
    amountAtomic: amount,
    referenceValueAtomic: referenceValue,
    referenceUnit: input.claim.claimFact.shortfallUnit,
    fxRoot: fx.root,
  });
  const proofPublicInputs = publicInputs({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    proofVersion: 7,
    agreementRoot: input.claim.snapshot.snapshot.baseAgreementRoot,
    manifestRoot: actionCommitment,
    policyRoot: input.claim.snapshot.snapshot.policyRoot,
    fxRoot: fx.root,
    subjectNullifier: remediationSubjectNullifier,
    parentNullifier: input.claim.claimSubjectNullifier,
    factCommitment: remediationFactCommitment,
    parentFactCommitment: input.claim.claimFactCommitment,
    validityStart: input.validityStart,
    validityExpiry: input.validityExpiry,
  });
  return {
    publicInputs: proofPublicInputs,
    remediationSubjectNullifier,
    remediationFactCommitment,
    actionCommitment,
    fxRoot: fx.root,
    referenceValueAtomic: referenceValue.toString(),
    claim: input.claim,
    circuitInputs: {
      ...circuitPublicInputs(proofPublicInputs),
      policy_root: bytes32(input.claim.snapshot.snapshot.policyRoot),
      accepted_claim_subject: bytes32(input.claim.claimSubjectNullifier),
      accepted_claim_run_nullifier: bytes32(input.claim.claimFact.runNullifier),
      accepted_snapshot_commitment: bytes32(input.claim.claimFact.snapshotCommitment),
      accepted_statement_commitment: bytes32(input.claim.claimFact.statementCommitment),
      accepted_manifest_root: bytes32(input.claim.claimFact.manifestRoot),
      accepted_target_index: input.claim.claimFact.targetIndex.toString(),
      accepted_claim_kind: exceptionClaimKinds[input.claim.claimFact.claimKind].toString(),
      accepted_claim_shortfall: input.claim.claimFact.shortfallAtomic,
      accepted_claim_shortfall_unit: claimShortfallUnits[input.claim.claimFact.shortfallUnit].toString(),
      accepted_obligation_token: exceptionTokens[input.claim.claimFact.obligationToken].toString(),
      accepted_evidence_source: ({ unsettled_period: 0, employer_statement: 2, settlement_match: 3 } as const)[input.claim.claimFact.evidenceSource as Exclude<ClaimEvidenceSource, "payo_run">].toString(),
      agreement: input.claim.target.agreement,
      agreement_siblings: input.claim.target.agreementMembership.siblings,
      agreement_path_bits: input.claim.target.agreementMembership.path_bits,
      remediation_secret: bytes32(input.remediationSecret),
      remediation_action_salt: bytes32(input.actionSalt),
      remediation_amount_atomic: input.amountAtomic,
      remediation_token: exceptionTokens[input.token].toString(),
      fx_snapshot: fx.snapshot,
      fx_membership: fx.membership,
    },
  };
}
