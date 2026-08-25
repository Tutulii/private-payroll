import { randomBytes } from "@noble/ciphers/utils.js";
import type { InputMap } from "@noir-lang/noir_js";
import {
  deriveRunNullifier,
  hashRecipientCommitment,
  hashTextCommitment,
  splitHashToU128,
} from "@/lib/crypto/commitments";
import { normalizedHexBytes, toHex } from "@/lib/crypto/encoding";
import {
  fxSnapshotCommitment,
  toCircuitFxSnapshot,
  type FxSnapshot,
} from "@/lib/domain/fx";
import {
  calculatePayrollLine,
  comparePayrollAgreementIds,
  type CalculatedPayrollLine,
  type PayrollTokenSymbol,
} from "@/lib/domain/payroll";
import {
  compilePolicyPack,
  evaluatePolicyPack,
  policyPackCommitment,
  type PolicyPack,
} from "@/lib/policy/engine";
import {
  createProofCommitter,
  PAYO_PROOF_EMPTY_LEAF,
} from "./commitments";
import type { PayrollIntegrityPublicInputs } from "./protocol";

const ZERO = `0x${"00".repeat(32)}`;
const MAX_LINES = 50;

export const PAYO_NET_INVOICE_POLICY: PolicyPack = {
  packVersion: "payo-policy-pack-v1",
  id: "payo-net-invoice-no-withholding-v1",
  revision: 1,
  jurisdictionCode: "US",
  appliesTo: ["contractor", "agent_service"],
  effectiveFrom: "2026-01-01",
  effectiveUntil: "2027-12-31",
  sourceUri: "https://github.com/Tutulii/private-payroll/blob/main/docs/policies/net-invoice-v1.md",
  legalReviewRequired: true,
  instructions: [{ op: "CONST", out: "no_withholding", value: "0" }],
  outputs: { statutoryWithholding: "no_withholding" },
};

export type PayrollIntegrityLineInput = {
  agreementId: string;
  recipientAddress: string;
  recipientSalt: `0x${string}`;
  agreementSalt: `0x${string}`;
  lineSalt: `0x${string}`;
  token: PayrollTokenSymbol;
  earningsAtomic: string[];
  deductionsAtomic: string[];
  policyId: string;
  scheduleCommitment: `0x${string}`;
  dueAt: bigint;
  validUntil: bigint;
  classification: {
    declared: 1 | 2;
    score: number;
    employeeThreshold: number;
  };
  finalPay?: {
    requiredMask: number;
    includedMask: number;
    componentsAtomic: string[];
  };
  fxFloorAtomic?: string;
  referenceCurrency: "USD" | "GBP";
};

export type SerializedPayrollIntegrityLineInput = Omit<
  PayrollIntegrityLineInput,
  "dueAt" | "validUntil"
> & {
  dueAt: string;
  validUntil: string;
};

export type SerializedPayrollIntegrityBuildRequest = {
  chainId: string;
  sealAddress: string;
  organizationSecret: string;
  cycleId: string;
  revision: number;
  validityStart: string;
  validityExpiry: string;
  policies: PolicyPack[];
  fxSnapshots: FxSnapshot[];
  lines: SerializedPayrollIntegrityLineInput[];
};

export type PayrollIntegrityInputBuild = {
  witness: { circuitInputs: [InputMap, InputMap] };
  publicInputs: readonly [PayrollIntegrityPublicInputs, PayrollIntegrityPublicInputs];
  agreementRoot: `0x${string}`;
  manifestRoot: `0x${string}`;
  policyRoot: `0x${string}`;
  fxRoot: `0x${string}`;
  runNullifier: `0x${string}`;
  calculatedLines: CalculatedPayrollLine[];
};

function bytes32(value: string): number[] {
  return [...normalizedHexBytes(value, 32)];
}

function limbs(root: string) {
  const value = splitHashToU128(root);
  return { high: value.high.toString(), low: value.low.toString() };
}

function boundedUnsigned(value: bigint, bits: number, label: string): string {
  if (value < 0n || value >= 1n << BigInt(bits)) throw new Error(`${label} does not fit in u${bits}.`);
  return value.toString();
}

function emptyProgram() {
  return {
    metadata_commitment: bytes32(ZERO),
    instruction_count: "0",
    opcodes: Array(16).fill("0"),
    left: Array(16).fill("0"),
    right: Array(16).fill("0"),
    immediate: Array(16).fill("0"),
    numerator: Array(16).fill("0"),
    denominator: Array(16).fill("0"),
    output_register: "0",
  };
}

function emptyMembership() {
  return { siblings: Array(6).fill("0"), path_bits: Array(6).fill(false) };
}

function emptyAgreement() {
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

function emptyLine() {
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

function emptySnapshot() {
  return {
    token: "0",
    token_decimals: "0",
    reference_currency: "0",
    quote_decimals: "0",
    feed_commitment: bytes32(ZERO),
    sources_commitment: bytes32(ZERO),
    price_numerator: "0",
    price_denominator: "0",
    observed_at: "0",
    source_count: "0",
    minimum_source_count: "0",
    maximum_age_seconds: "0",
    haircut_bps: "0",
  };
}

function padded<T>(items: readonly T[], length: number, empty: () => T): T[] {
  if (items.length > length) throw new Error(`Cannot pad ${items.length} values into ${length} slots.`);
  return [...items, ...Array.from({ length: length - items.length }, empty)];
}

function policyOutput(pack: PolicyPack, line: CalculatedPayrollLine): bigint {
  const inputs: Record<string, string> = {
    gross: line.grossAtomic,
    taxable_gross: line.grossAtomic,
  };
  line.earningsAtomic.forEach((earning, index) => { inputs[`earning_${index}`] = earning; });
  const evaluated = evaluatePolicyPack(pack, inputs);
  const output = evaluated.statutoryWithholding
    ?? evaluated.statutoryDeduction
    ?? Object.values(evaluated)[0];
  if (output === undefined) throw new Error(`Policy ${pack.id} has no evaluated deduction output.`);
  return BigInt(output);
}

type PreparedPolicy = {
  pack: PolicyPack;
  compiled: ReturnType<typeof compilePolicyPack>;
  commitment: `0x${string}`;
};

type PreparedAgreement = {
  source: PayrollIntegrityLineInput;
  calculated: CalculatedPayrollLine;
  idCommitment: `0x${string}`;
  recipientCommitment: `0x${string}`;
  agreementTerms: `0x${string}`;
  policySlot: number;
};

function prepareAgreementDetails(input: {
  lines: readonly PayrollIntegrityLineInput[];
  policyDetails: readonly PreparedPolicy[];
  committer: Awaited<ReturnType<typeof createProofCommitter>>;
}): PreparedAgreement[] {
  const prepared = input.lines.map((line) => {
    const policySlot = input.policyDetails.findIndex(({ pack }) => pack.id === line.policyId);
    if (policySlot < 0) throw new Error(`Agreement ${line.agreementId} selects an unavailable policy.`);
    const calculated = calculatePayrollLine({
      agreementId: line.agreementId,
      recipientAddress: line.recipientAddress,
      token: line.token,
      earningsAtomic: line.earningsAtomic,
      deductionsAtomic: line.deductionsAtomic,
      committedPolicyId: line.policyId,
      scheduleCommitment: line.scheduleCommitment,
      salt: line.lineSalt,
    });
    if (policyOutput(input.policyDetails[policySlot].pack, calculated) !== BigInt(calculated.deductionsTotalAtomic)) {
      throw new Error(`Agreement ${line.agreementId} deductions do not match its policy.`);
    }
    const expectedClassification = line.classification.score >= line.classification.employeeThreshold ? 1 : 2;
    if (line.classification.employeeThreshold <= 0 || line.classification.employeeThreshold >= 2 ** 16) {
      throw new Error(`Agreement ${line.agreementId} has an invalid classification threshold.`);
    }
    if (line.classification.declared !== expectedClassification) {
      throw new Error(`Agreement ${line.agreementId} classification facts do not match its treatment.`);
    }
    const finalPay = line.finalPay;
    const finalComponents = finalPay?.componentsAtomic ?? [];
    if (finalComponents.length > 5) throw new Error("Final pay supports at most five components.");
    const idCommitment = toHex(hashTextCommitment("PAYO_AGREEMENT_ID_V1", line.agreementId));
    const recipientCommitment = toHex(hashRecipientCommitment(line.recipientAddress, line.recipientSalt));
    const agreementTerms = input.committer.proofAgreementCommitment({
      agreementIdCommitment: idCommitment,
      recipientCommitment,
      earningsAtomic: calculated.earningsAtomic,
      token: calculated.token,
      policyCommitment: input.policyDetails[policySlot].commitment,
      scheduleCommitment: line.scheduleCommitment,
      dueAt: line.dueAt,
      validUntil: line.validUntil,
      classificationDeclared: line.classification.declared,
      classificationScore: line.classification.score,
      classificationEmployeeThreshold: line.classification.employeeThreshold,
      finalPayMode: Boolean(finalPay),
      finalRequiredMask: finalPay?.requiredMask ?? 0,
      finalComponentsAtomic: finalComponents,
      fxFloorAtomic: line.fxFloorAtomic ?? "0",
      referenceCurrency: line.referenceCurrency,
      salt: line.agreementSalt,
    });
    return {
      source: line,
      calculated,
      idCommitment,
      recipientCommitment,
      agreementTerms,
      policySlot,
    };
  }).sort((left, right) => comparePayrollAgreementIds(
    left.source.agreementId,
    right.source.agreementId,
  ));

  for (let index = 1; index < prepared.length; index += 1) {
    if (comparePayrollAgreementIds(
      prepared[index - 1].source.agreementId,
      prepared[index].source.agreementId,
    ) === 0) {
      throw new Error("Payroll agreement identifiers must be unique.");
    }
  }
  return prepared;
}

function cycleBytes(cycleId: string): { value: number[]; length: number } {
  const encoded = new TextEncoder().encode(cycleId);
  if (encoded.length === 0 || encoded.length > 64) throw new Error("Cycle ID must contain 1–64 UTF-8 bytes.");
  return { value: [...encoded, ...Array(64 - encoded.length).fill(0)], length: encoded.length };
}

export function randomCommitmentSalt(): `0x${string}` {
  return toHex(randomBytes(32));
}

export async function buildPolicyCatalogRoot(
  policies: readonly PolicyPack[],
): Promise<`0x${string}`> {
  if (policies.length < 1 || policies.length > 4) {
    throw new Error("A proof policy catalog requires 1–4 policy programs.");
  }
  const committer = await createProofCommitter();
  return committer.buildProofCatalog(policies.map(policyPackCommitment)).root;
}

function buildFxCatalog(
  snapshots: readonly FxSnapshot[],
  committer: Awaited<ReturnType<typeof createProofCommitter>>,
) {
  if (snapshots.length < 1 || snapshots.length > 2) {
    throw new Error("An FX catalog requires 1–2 snapshots.");
  }
  const details = snapshots.map((snapshot) => ({
    snapshot,
    circuit: toCircuitFxSnapshot(snapshot),
    commitment: fxSnapshotCommitment(snapshot),
  }));
  return {
    details,
    catalog: committer.buildProofCatalog(details.map(({ commitment }) => commitment)),
  };
}

export async function buildFxCatalogRoot(
  snapshots: readonly FxSnapshot[],
): Promise<`0x${string}`> {
  const committer = await createProofCommitter();
  return buildFxCatalog(snapshots, committer).catalog.root;
}

/** Builds the exact agreement root consumed by PayrollIntegrity without needing
 * a short-lived FX snapshot or salary-line salt. This is the root an
 * organization schedules through the obligation registry before payday. */
export async function buildPayrollAgreementRoot(input: {
  policies: readonly PolicyPack[];
  lines: readonly PayrollIntegrityLineInput[];
}): Promise<`0x${string}`> {
  if (input.lines.length < 1 || input.lines.length > MAX_LINES) {
    throw new Error(`An obligation root requires 1–${MAX_LINES} agreement lines.`);
  }
  if (input.policies.length < 1 || input.policies.length > 4) {
    throw new Error("An obligation root requires 1–4 policy programs.");
  }
  const committer = await createProofCommitter();
  const policyDetails: PreparedPolicy[] = input.policies.map((pack) => ({
    pack,
    compiled: compilePolicyPack(pack),
    commitment: policyPackCommitment(pack),
  }));
  const prepared = prepareAgreementDetails({
    lines: input.lines,
    policyDetails,
    committer,
  });
  return committer.buildProofFixedMerkleRoot(
    prepared.map(({ agreementTerms }) => agreementTerms),
  );
}

export function serializePayrollIntegrityBuildRequest(input: {
  chainId: string;
  sealAddress: string;
  organizationSecret: string;
  cycleId: string;
  revision: number;
  validityStart: bigint;
  validityExpiry: bigint;
  policies: readonly PolicyPack[];
  fxSnapshots: readonly FxSnapshot[];
  lines: readonly PayrollIntegrityLineInput[];
}): SerializedPayrollIntegrityBuildRequest {
  return {
    ...input,
    validityStart: input.validityStart.toString(),
    validityExpiry: input.validityExpiry.toString(),
    policies: [...input.policies],
    fxSnapshots: [...input.fxSnapshots],
    lines: input.lines.map((line) => ({
      ...line,
      dueAt: line.dueAt.toString(),
      validUntil: line.validUntil.toString(),
    })),
  };
}

export function buildPayrollIntegrityInputsFromSerialized(
  input: SerializedPayrollIntegrityBuildRequest,
): Promise<PayrollIntegrityInputBuild> {
  return buildPayrollIntegrityInputs({
    ...input,
    validityStart: BigInt(input.validityStart),
    validityExpiry: BigInt(input.validityExpiry),
    lines: input.lines.map((line) => ({
      ...line,
      dueAt: BigInt(line.dueAt),
      validUntil: BigInt(line.validUntil),
    })),
  });
}

export async function buildPayrollIntegrityInputs(input: {
  chainId: string;
  sealAddress: string;
  organizationSecret: string;
  cycleId: string;
  revision: number;
  validityStart: bigint;
  validityExpiry: bigint;
  policies: readonly PolicyPack[];
  fxSnapshots: readonly FxSnapshot[];
  lines: readonly PayrollIntegrityLineInput[];
}): Promise<PayrollIntegrityInputBuild> {
  if (input.lines.length < 1 || input.lines.length > MAX_LINES) {
    throw new Error(`PayrollIntegrity requires 1–${MAX_LINES} lines.`);
  }
  if (input.policies.length < 1 || input.policies.length > 4) {
    throw new Error("PayrollIntegrity requires 1–4 policy programs.");
  }
  if (input.fxSnapshots.length < 1 || input.fxSnapshots.length > 2) {
    throw new Error("PayrollIntegrity requires 1–2 FX snapshots.");
  }
  if (!Number.isInteger(input.revision) || input.revision < 1 || input.revision >= 2 ** 32) {
    throw new Error("Payroll revision must be a positive u32.");
  }
  if (
    input.validityStart < 0n
    || input.validityExpiry < input.validityStart
    || input.validityExpiry - input.validityStart > 3_600n
  ) {
    throw new Error("PayrollIntegrity validity must be ordered and no longer than one hour.");
  }
  if (BigInt(input.chainId) === 0n || BigInt(input.sealAddress) === 0n) {
    throw new Error("PayrollIntegrity requires non-zero deployment binding.");
  }
  bytes32(input.organizationSecret);

  const committer = await createProofCommitter();
  const policyDetails: PreparedPolicy[] = input.policies.map((pack) => ({
    pack,
    compiled: compilePolicyPack(pack),
    commitment: policyPackCommitment(pack),
  }));
  const policyCatalog = committer.buildProofCatalog(policyDetails.map(({ commitment }) => commitment));
  const { details: fxDetails, catalog: fxCatalog } = buildFxCatalog(input.fxSnapshots, committer);

  const agreementPrepared = prepareAgreementDetails({
    lines: input.lines,
    policyDetails,
    committer,
  });
  const prepared = agreementPrepared.map((entry) => {
    const line = entry.source;
    const fxSlot = fxDetails.findIndex(({ snapshot }) =>
      snapshot.baseToken === line.token && snapshot.referenceCurrency === line.referenceCurrency);
    if (fxSlot < 0) throw new Error(`Agreement ${line.agreementId} has no matching FX snapshot.`);
    if (line.dueAt > input.validityStart || input.validityStart > line.validUntil) {
      throw new Error(`Agreement ${line.agreementId} is not due in the proof window.`);
    }
    const circuitFx = fxDetails[fxSlot].circuit;
    const net = BigInt(entry.calculated.netAtomic);
    const rawReference = net * BigInt(circuitFx.priceNumerator) / BigInt(circuitFx.priceDenominator);
    const referenceValue = rawReference * BigInt(10_000 - circuitFx.haircutBps) / 10_000n;
    const fxFloor = BigInt(line.fxFloorAtomic ?? "0");
    if (referenceValue < fxFloor) throw new Error(`Agreement ${line.agreementId} does not meet its FX floor.`);

    const payrollLeaf = committer.proofPayrollCommitment(entry.calculated, entry.agreementTerms, {
      classificationTreatment: line.classification.declared,
      finalIncludedMask: line.finalPay?.includedMask ?? 0,
      referenceValueAtomic: referenceValue,
    });
    return {
      ...entry,
      payrollLeaf,
      fxSlot,
      referenceValue,
    };
  });

  const agreementRoot = committer.buildProofFixedMerkleRoot(prepared.map(({ agreementTerms }) => agreementTerms));
  const manifestRoot = committer.buildProofFixedMerkleRoot(prepared.map(({ payrollLeaf }) => payrollLeaf));
  const nullifier = deriveRunNullifier({
    organizationSecret: input.organizationSecret,
    cycleId: input.cycleId,
    revision: input.revision,
  });
  const rootValues = {
    agreement: limbs(agreementRoot),
    manifest: limbs(manifestRoot),
    policy: limbs(policyCatalog.root),
    fx: limbs(fxCatalog.root),
    nullifier: limbs(nullifier),
  };
  const agreementLeaves = padded(
    prepared.map(({ agreementTerms }) => BigInt(agreementTerms).toString()),
    64,
    () => BigInt(PAYO_PROOF_EMPTY_LEAF).toString(),
  );
  const payrollLeaves = padded(
    prepared.map(({ payrollLeaf }) => BigInt(payrollLeaf).toString()),
    64,
    () => BigInt(PAYO_PROOF_EMPTY_LEAF).toString(),
  );

  const agreementWitnesses = prepared.map((entry) => ({
    enabled: true,
    id_commitment: bytes32(entry.idCommitment),
    recipient_commitment: bytes32(entry.recipientCommitment),
    earnings: padded(entry.calculated.earningsAtomic, 8, () => "0"),
    earnings_count: entry.calculated.earningsAtomic.length.toString(),
    token: entry.calculated.token === "STRK" ? "0" : "1",
    policy_commitment: bytes32(policyDetails[entry.policySlot].commitment),
    schedule_commitment: bytes32(entry.source.scheduleCommitment),
    due_at: boundedUnsigned(entry.source.dueAt, 64, "Agreement due timestamp"),
    valid_until: boundedUnsigned(entry.source.validUntil, 64, "Agreement expiry timestamp"),
    classification_declared: entry.source.classification.declared.toString(),
    classification_score: entry.source.classification.score.toString(),
    classification_employee_threshold: entry.source.classification.employeeThreshold.toString(),
    final_pay_mode: Boolean(entry.source.finalPay),
    final_required_mask: (entry.source.finalPay?.requiredMask ?? 0).toString(),
    final_components: padded(entry.source.finalPay?.componentsAtomic ?? [], 5, () => "0"),
    fx_floor_atomic: entry.source.fxFloorAtomic ?? "0",
    reference_currency: entry.source.referenceCurrency === "USD" ? "0" : "1",
    salt: bytes32(entry.source.agreementSalt),
  }));
  const lineWitnesses = prepared.map((entry) => ({
    active: true,
    deductions: padded(entry.calculated.deductionsAtomic, 8, () => "0"),
    deductions_count: entry.calculated.deductionsAtomic.length.toString(),
    policy_slot: entry.policySlot.toString(),
    fx_slot: entry.fxSlot.toString(),
    salt: bytes32(entry.source.lineSalt),
    classification_treatment: entry.source.classification.declared.toString(),
    final_included_mask: (entry.source.finalPay?.includedMask ?? 0).toString(),
    reference_value_atomic: entry.referenceValue.toString(),
  }));
  const policyWitnesses = padded(policyDetails.map((entry, index) => ({
    enabled: true,
    program: {
      metadata_commitment: bytes32(entry.compiled.metadataCommitment),
      instruction_count: entry.compiled.instructionCount.toString(),
      opcodes: entry.compiled.opcodes.map(String),
      left: entry.compiled.left.map(String),
      right: entry.compiled.right.map(String),
      immediate: [...entry.compiled.immediate],
      numerator: [...entry.compiled.numerator],
      denominator: [...entry.compiled.denominator],
      output_register: entry.compiled.outputRegister.toString(),
    },
    membership: {
      siblings: policyCatalog.memberships[index].siblings.map((value) => BigInt(value).toString()),
      path_bits: policyCatalog.memberships[index].pathBits,
    },
  })), 4, () => ({ enabled: false, program: emptyProgram(), membership: emptyMembership() }));
  const fxWitnesses = padded(fxDetails.map((entry, index) => ({
    enabled: true,
    snapshot: {
      token: entry.circuit.token.toString(),
      token_decimals: entry.circuit.tokenDecimals.toString(),
      reference_currency: entry.circuit.referenceCurrency.toString(),
      quote_decimals: entry.circuit.quoteDecimals.toString(),
      feed_commitment: bytes32(entry.circuit.feedCommitment),
      sources_commitment: bytes32(entry.circuit.sourcesCommitment),
      price_numerator: entry.circuit.priceNumerator,
      price_denominator: entry.circuit.priceDenominator,
      observed_at: entry.circuit.observedAt,
      source_count: entry.circuit.sourceCount.toString(),
      minimum_source_count: entry.circuit.minimumSourceCount.toString(),
      maximum_age_seconds: entry.circuit.maximumAgeSeconds,
      haircut_bps: entry.circuit.haircutBps.toString(),
    },
    membership: {
      siblings: fxCatalog.memberships[index].siblings.map((value) => BigInt(value).toString()),
      path_bits: fxCatalog.memberships[index].pathBits,
    },
  })), 2, () => ({ enabled: false, snapshot: emptySnapshot(), membership: emptyMembership() }));
  const cycle = cycleBytes(input.cycleId);

  const makeShard = (shardIndex: 0 | 1): InputMap => {
    const agreementOffset = shardIndex === 0 ? 0 : 24;
    const lineOffset = shardIndex === 0 ? 0 : 25;
    return {
      chain_id: BigInt(input.chainId).toString(),
      seal_address: BigInt(input.sealAddress).toString(),
      proof_version: "1",
      schema_version: "1",
      agreement_root_high: rootValues.agreement.high,
      agreement_root_low: rootValues.agreement.low,
      manifest_root_high: rootValues.manifest.high,
      manifest_root_low: rootValues.manifest.low,
      policy_root_high: rootValues.policy.high,
      policy_root_low: rootValues.policy.low,
      fx_root_high: rootValues.fx.high,
      fx_root_low: rootValues.fx.low,
      run_nullifier_high: rootValues.nullifier.high,
      run_nullifier_low: rootValues.nullifier.low,
      validity_start: boundedUnsigned(input.validityStart, 64, "Validity start"),
      validity_expiry: boundedUnsigned(input.validityExpiry, 64, "Validity expiry"),
      shard_index: shardIndex.toString(),
      organization_secret: bytes32(input.organizationSecret),
      cycle_id: cycle.value,
      cycle_id_len: cycle.length.toString(),
      revision: input.revision.toString(),
      agreement_leaves: agreementLeaves,
      payroll_leaves: payrollLeaves,
      agreements: padded(agreementWitnesses.slice(agreementOffset, agreementOffset + 26), 26, emptyAgreement),
      lines: padded(lineWitnesses.slice(lineOffset, lineOffset + 25), 25, emptyLine),
      policies: policyWitnesses,
      fx_snapshots: fxWitnesses,
    };
  };

  const commonInputs = {
    chainId: BigInt(input.chainId).toString(),
    sealAddress: BigInt(input.sealAddress).toString(),
    proofVersion: "1",
    schemaVersion: "1",
    agreementRootHigh: rootValues.agreement.high,
    agreementRootLow: rootValues.agreement.low,
    manifestRootHigh: rootValues.manifest.high,
    manifestRootLow: rootValues.manifest.low,
    policyRootHigh: rootValues.policy.high,
    policyRootLow: rootValues.policy.low,
    fxRootHigh: rootValues.fx.high,
    fxRootLow: rootValues.fx.low,
    runNullifierHigh: rootValues.nullifier.high,
    runNullifierLow: rootValues.nullifier.low,
    validityStart: input.validityStart.toString(),
    validityExpiry: input.validityExpiry.toString(),
  };
  return {
    witness: { circuitInputs: [makeShard(0), makeShard(1)] },
    publicInputs: [
      { ...commonInputs, shardIndex: "0" },
      { ...commonInputs, shardIndex: "1" },
    ],
    agreementRoot,
    manifestRoot,
    policyRoot: policyCatalog.root,
    fxRoot: fxCatalog.root,
    runNullifier: nullifier,
    calculatedLines: prepared.map(({ calculated }) => calculated),
  };
}
