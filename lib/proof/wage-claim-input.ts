import type { InputMap } from "@noir-lang/noir_js";
import { splitHashToU128 } from "@/lib/crypto/commitments";
import { normalizedHexBytes } from "@/lib/crypto/encoding";
import {
  wageClaimKinds,
  wageClaimNullifier,
  type WageClaimKind,
} from "@/lib/domain/wage-claim-commitment";
import type { PayrollTokenSymbol } from "@/lib/domain/payroll";
import { createProofCommitter, PAYO_PROOF_EMPTY_LEAF } from "./commitments";
import type { PayrollIntegrityInputBuild } from "./input-builder";
import type { PayrollIntegrityPublicInputs } from "./protocol";

const ZERO_BYTES = Array(32).fill(0) as number[];

type CircuitRecord = Record<string, unknown>;

function source(input: InputMap): CircuitRecord {
  if (!input || typeof input !== "object") throw new Error("PayrollIntegrity source shard is missing.");
  return input as CircuitRecord;
}

function recordArray(input: CircuitRecord, field: string): CircuitRecord[] {
  const value = input[field];
  if (!Array.isArray(value)) throw new Error(`PayrollIntegrity source is missing ${field}.`);
  return value as CircuitRecord[];
}

function stringArray(input: CircuitRecord, field: string): string[] {
  const value = input[field];
  if (!Array.isArray(value)) throw new Error(`PayrollIntegrity source is missing ${field}.`);
  return value.map(String);
}

function canonicalField(value: string): `0x${string}` {
  const field = BigInt(value);
  if (field < 0n) throw new Error("Proof field cannot be negative.");
  return `0x${field.toString(16).padStart(64, "0")}`;
}

function bytes32(value: string): number[] {
  return [...normalizedHexBytes(value, 32)];
}

function limbs(value: string) {
  const split = splitHashToU128(value);
  return { high: split.high.toString(), low: split.low.toString() };
}

function numberField(input: CircuitRecord, field: string): bigint {
  const value = input[field];
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "bigint") {
    throw new Error(`Claim witness is missing ${field}.`);
  }
  return BigInt(value);
}

function emptyPayrollLine() {
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

export type WageClaimInputBuild = {
  witness: { circuitInputs: [InputMap, InputMap] };
  publicInputs: readonly [PayrollIntegrityPublicInputs, PayrollIntegrityPublicInputs];
  claimKind: WageClaimKind;
  claimSalt: `0x${string}`;
  claimNullifier: `0x${string}`;
  originalRunNullifier: `0x${string}`;
  agreementRoot: `0x${string}`;
  disputedManifestRoot: `0x${string}`;
  agreementLeaf: `0x${string}`;
  agreementLeaves: readonly string[];
  targetIndex: number;
  shortfallAtomic: string;
  token: PayrollTokenSymbol;
};

/** Builds a private claim against a deliberately disputed manifest derived
 * from an authoritative PayrollIntegrity witness. No plaintext claim fact is
 * included in the returned public inputs. */
export async function buildWageClaimInputs(input: {
  payroll: PayrollIntegrityInputBuild;
  agreementId: string;
  claimKind: WageClaimKind;
  claimSalt: `0x${string}`;
  validityStart: bigint;
  validityExpiry: bigint;
  disputedReferenceValueAtomic?: string;
  disputedFinalIncludedMask?: number;
}): Promise<WageClaimInputBuild> {
  if (
    input.validityStart < 0n
    || input.validityExpiry < input.validityStart
    || input.validityExpiry - input.validityStart > 3_600n
  ) {
    throw new Error("Wage-claim validity must be ordered and no longer than one hour.");
  }
  const targetIndex = input.payroll.calculatedLines.findIndex((line) => line.agreementId === input.agreementId);
  if (targetIndex < 0) throw new Error("The claim agreement is absent from the authoritative payroll witness.");
  const sources = input.payroll.witness.circuitInputs.map(source) as [CircuitRecord, CircuitRecord];
  const shard = targetIndex < 25 ? sources[0] : sources[1];
  const localLineIndex = targetIndex < 25 ? targetIndex : targetIndex - 25;
  const localAgreementIndex = targetIndex < 25 ? targetIndex : targetIndex - 24;
  const agreement = structuredClone(recordArray(shard, "agreements")[localAgreementIndex]);
  const line = structuredClone(recordArray(shard, "lines")[localLineIndex]);
  const agreementLeaves = stringArray(sources[0], "agreement_leaves").map(canonicalField);
  const payrollLeaves = stringArray(sources[0], "payroll_leaves").map(canonicalField);
  const agreementLeaf = agreementLeaves[targetIndex];
  const gross = (agreement.earnings as unknown[]).slice(0, Number(numberField(agreement, "earnings_count")))
    .reduce<bigint>((total, amount) => total + BigInt(String(amount)), 0n);
  let shortfall: bigint;
  let disputedLine: CircuitRecord = line;
  if (input.claimKind === "missing_obligation") {
    shortfall = gross;
    payrollLeaves[targetIndex] = PAYO_PROOF_EMPTY_LEAF;
    disputedLine = emptyPayrollLine();
  } else if (input.claimKind === "below_committed_floor") {
    const floor = numberField(agreement, "fx_floor_atomic");
    const reference = BigInt(input.disputedReferenceValueAtomic ?? "0");
    if (floor <= 0n || reference < 0n || reference >= floor) {
      if (floor <= 0n) throw new Error("A below-floor claim requires a committed positive FX floor.");
      throw new Error("The disputed reference value must be below the committed FX floor.");
    }
    shortfall = floor - reference;
    disputedLine.reference_value_atomic = reference.toString();
  } else {
    if (agreement.final_pay_mode !== true) throw new Error("An incomplete-final-pay claim requires final-pay terms.");
    const required = Number(numberField(agreement, "final_required_mask"));
    const included = input.disputedFinalIncludedMask ?? 0;
    if (!Number.isInteger(included) || included < 0 || included > 31 || (included & required) === required) {
      throw new Error("The disputed final-pay mask must omit at least one required component.");
    }
    disputedLine.final_included_mask = String(included);
    const components = agreement.final_components as unknown[];
    shortfall = components.reduce<bigint>((total, amount, index) =>
      (required & (1 << index)) !== 0 && (included & (1 << index)) === 0
        ? total + BigInt(String(amount))
        : total, 0n);
  }
  if (shortfall <= 0n) throw new Error("The private claim has no positive shortfall.");

  const committer = await createProofCommitter();
  if (input.claimKind !== "missing_obligation") {
    const calculated = input.payroll.calculatedLines[targetIndex];
    payrollLeaves[targetIndex] = committer.proofPayrollCommitment(calculated, agreementLeaf, {
      classificationTreatment: Number(numberField(disputedLine, "classification_treatment")),
      finalIncludedMask: Number(numberField(disputedLine, "final_included_mask")),
      referenceValueAtomic: numberField(disputedLine, "reference_value_atomic"),
    });
  }
  const disputedManifestRoot = committer.buildProofFixedMerkleRoot(payrollLeaves.slice(0, 50));
  const claimNullifier = wageClaimNullifier({
    originalRunNullifier: input.payroll.runNullifier,
    disputedManifestRoot,
    agreementLeaf,
    claimKind: input.claimKind,
    shortfallAtomic: shortfall,
    claimSalt: input.claimSalt,
  });
  const nullifier = limbs(claimNullifier);
  const common: Omit<PayrollIntegrityPublicInputs, "shardIndex"> = {
    ...input.payroll.publicInputs[0],
    proofVersion: "3",
    manifestRootHigh: limbs(disputedManifestRoot).high,
    manifestRootLow: limbs(disputedManifestRoot).low,
    runNullifierHigh: nullifier.high,
    runNullifierLow: nullifier.low,
    validityStart: input.validityStart.toString(),
    validityExpiry: input.validityExpiry.toString(),
  };
  const makeShard = (shardIndex: 0 | 1): InputMap => ({
    chain_id: common.chainId,
    seal_address: common.sealAddress,
    proof_version: common.proofVersion,
    schema_version: common.schemaVersion,
    agreement_root_high: common.agreementRootHigh,
    agreement_root_low: common.agreementRootLow,
    manifest_root_high: common.manifestRootHigh,
    manifest_root_low: common.manifestRootLow,
    policy_root_high: common.policyRootHigh,
    policy_root_low: common.policyRootLow,
    fx_root_high: common.fxRootHigh,
    fx_root_low: common.fxRootLow,
    claim_nullifier_high: common.runNullifierHigh,
    claim_nullifier_low: common.runNullifierLow,
    validity_start: common.validityStart,
    validity_expiry: common.validityExpiry,
    shard_index: String(shardIndex),
    original_run_nullifier: bytes32(input.payroll.runNullifier),
    claim_kind: String(wageClaimKinds[input.claimKind]),
    claim_salt: bytes32(input.claimSalt),
    target_index: String(targetIndex),
    agreement_leaves: agreementLeaves,
    payroll_leaves: payrollLeaves,
    agreement,
    line: disputedLine,
  }) as unknown as InputMap;
  return {
    witness: { circuitInputs: [makeShard(0), makeShard(1)] },
    publicInputs: [
      { ...common, shardIndex: "0" },
      { ...common, shardIndex: "1" },
    ],
    claimKind: input.claimKind,
    claimSalt: input.claimSalt,
    claimNullifier,
    originalRunNullifier: input.payroll.runNullifier,
    agreementRoot: input.payroll.agreementRoot,
    disputedManifestRoot,
    agreementLeaf,
    agreementLeaves,
    targetIndex,
    shortfallAtomic: shortfall.toString(),
    token: input.payroll.calculatedLines[targetIndex].token,
  };
}

export async function buildWageRemediationInputs(input: {
  claim: WageClaimInputBuild;
  amountAtomic: string;
  token: PayrollTokenSymbol;
  remediationSalt: `0x${string}`;
  validityStart: bigint;
  validityExpiry: bigint;
}): Promise<{
  witness: { circuitInputs: [InputMap, InputMap] };
  publicInputs: readonly [PayrollIntegrityPublicInputs, PayrollIntegrityPublicInputs];
  remediationManifestRoot: `0x${string}`;
}> {
  const amount = BigInt(input.amountAtomic);
  if (amount < BigInt(input.claim.shortfallAtomic)) {
    throw new Error("Remediation is below the proved private shortfall.");
  }
  if (
    input.validityStart < 0n
    || input.validityExpiry < input.validityStart
    || input.validityExpiry - input.validityStart > 3_600n
  ) {
    throw new Error("Wage-remediation validity must be ordered and no longer than one hour.");
  }
  if (input.token !== input.claim.token) throw new Error("Remediation must use the claimed obligation token.");
  const committer = await createProofCommitter();
  const leaf = committer.proofRemediationCommitment({
    claimNullifier: input.claim.claimNullifier,
    agreementLeaf: input.claim.agreementLeaf,
    amountAtomic: amount,
    token: input.token === "STRK" ? 0 : 1,
    salt: input.remediationSalt,
  });
  const leaves = Array.from({ length: 50 }, (_, index) =>
    index === input.claim.targetIndex ? leaf : PAYO_PROOF_EMPTY_LEAF);
  const remediationManifestRoot = committer.buildProofFixedMerkleRoot(leaves);
  const root = limbs(remediationManifestRoot);
  const claimPublic = input.claim.publicInputs[0];
  const common: Omit<PayrollIntegrityPublicInputs, "shardIndex"> = {
    ...claimPublic,
    proofVersion: "4",
    manifestRootHigh: root.high,
    manifestRootLow: root.low,
    validityStart: input.validityStart.toString(),
    validityExpiry: input.validityExpiry.toString(),
  };
  const makeShard = (shardIndex: 0 | 1): InputMap => ({
    chain_id: common.chainId,
    seal_address: common.sealAddress,
    proof_version: common.proofVersion,
    schema_version: common.schemaVersion,
    agreement_root_high: common.agreementRootHigh,
    agreement_root_low: common.agreementRootLow,
    manifest_root_high: common.manifestRootHigh,
    manifest_root_low: common.manifestRootLow,
    policy_root_high: common.policyRootHigh,
    policy_root_low: common.policyRootLow,
    fx_root_high: common.fxRootHigh,
    fx_root_low: common.fxRootLow,
    claim_nullifier_high: common.runNullifierHigh,
    claim_nullifier_low: common.runNullifierLow,
    validity_start: common.validityStart,
    validity_expiry: common.validityExpiry,
    shard_index: String(shardIndex),
    claim_nullifier: bytes32(input.claim.claimNullifier),
    original_run_nullifier: bytes32(input.claim.originalRunNullifier),
    disputed_manifest_root: BigInt(input.claim.disputedManifestRoot).toString(),
    claim_kind: String(wageClaimKinds[input.claim.claimKind]),
    claim_shortfall: input.claim.shortfallAtomic,
    claim_salt: bytes32(input.claim.claimSalt),
    target_index: String(input.claim.targetIndex),
    agreement_leaves: input.claim.agreementLeaves,
    remediation_leaves: [...leaves, ...Array(14).fill(PAYO_PROOF_EMPTY_LEAF)],
    remediation_amount: amount.toString(),
    remediation_token: input.token === "STRK" ? "0" : "1",
    remediation_salt: bytes32(input.remediationSalt),
  }) as unknown as InputMap;
  return {
    witness: { circuitInputs: [makeShard(0), makeShard(1)] },
    publicInputs: [
      { ...common, shardIndex: "0" },
      { ...common, shardIndex: "1" },
    ],
    remediationManifestRoot,
  };
}
