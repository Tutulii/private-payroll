import type { InputMap } from "@noir-lang/noir_js";
import { encodeAdvancedObligation } from "@/lib/domain/advanced-obligation-commitment";
import { employmentAgreementSchema, type EmploymentAgreement } from "@/lib/domain/obligations";
import type { PayrollIntegrityInputBuild } from "./input-builder";
import type { PayrollIntegrityPublicInputs } from "./protocol";

const ZERO_BYTES = Array(32).fill(0) as number[];

function bytes32(value: string): number[] {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error("Advanced obligation commitment is not 32 bytes.");
  return Array.from({ length: 32 }, (_, index) => Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16));
}

function emptyPlan() {
  return {
    enabled: false,
    kind: "0",
    cadence: "0",
    flags: "0",
    occurrence: "0",
    release_sequence: "0",
    checkpoint_sequence: "0",
    minimum_checkpoint_seconds: "0",
    timestamps: Array(12).fill("0") as string[],
    amounts: Array(10).fill("0") as string[],
    required_mask: "0",
    included_mask: "0",
    commitments: Array.from({ length: 6 }, () => [...ZERO_BYTES]),
    salt: [...ZERO_BYTES],
  };
}

function planWitness(agreementInput: EmploymentAgreement) {
  const agreement = employmentAgreementSchema.parse(agreementInput);
  if (agreement.agreementVersion !== "payo-agreement-v2") {
    throw new Error(`Agreement ${agreement.id} is not an advanced PAYO v2 obligation.`);
  }
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

function sourceShard(input: InputMap): Record<string, unknown> {
  if (!input || typeof input !== "object") throw new Error("PayrollIntegrity shard input is missing.");
  return input as Record<string, unknown>;
}

export type AdvancedObligationInputBuild = {
  witness: { circuitInputs: [InputMap, InputMap] };
  publicInputs: readonly [PayrollIntegrityPublicInputs, PayrollIntegrityPublicInputs];
};

/**
 * Extends the exact PayrollIntegrity witness with encrypted v2 payment-plan
 * witnesses. The merged v2 circuit proves the complete calculator and advanced
 * schedule in one transaction-safe proof; it never relies on an unsubmitted v1
 * companion proof.
 */
export function buildAdvancedObligationInputs(input: {
  payroll: PayrollIntegrityInputBuild;
  agreements: readonly EmploymentAgreement[];
}): AdvancedObligationInputBuild {
  if (input.payroll.calculatedLines.length !== input.agreements.length) {
    throw new Error("Advanced obligation agreements do not cover the proved payroll manifest.");
  }
  const entries = input.agreements.map((candidate) => {
    const agreement = employmentAgreementSchema.parse(candidate);
    return [agreement.id, agreement] as const;
  });
  const byId = new Map(entries);
  if (byId.size !== input.agreements.length) throw new Error("Advanced agreement identifiers must be unique.");
  const ordered = input.payroll.calculatedLines.map((line) => {
    const agreement = byId.get(line.agreementId);
    if (!agreement) throw new Error(`The proved line ${line.agreementId} has no advanced agreement witness.`);
    return agreement;
  });
  const planWitnesses = [
    ...ordered.map(planWitness),
    ...Array.from({ length: 50 - ordered.length }, emptyPlan),
  ];
  const sources = input.payroll.witness.circuitInputs.map(sourceShard) as [Record<string, unknown>, Record<string, unknown>];
  const makeShard = (index: 0 | 1): InputMap => {
    const source = sources[index];
    const required = [
      "chain_id", "seal_address", "schema_version", "agreement_root_high", "agreement_root_low",
      "manifest_root_high", "manifest_root_low", "policy_root_high", "policy_root_low", "fx_root_high",
      "fx_root_low", "run_nullifier_high", "run_nullifier_low", "validity_start", "validity_expiry",
      "shard_index", "organization_secret", "cycle_id", "cycle_id_len", "revision",
      "agreement_leaves", "payroll_leaves", "agreements", "lines", "policies", "fx_snapshots",
    ];
    for (const field of required) {
      if (source[field] === undefined) throw new Error(`PayrollIntegrity input is missing ${field}.`);
    }
    return {
      ...source,
      proof_version: "2",
      plans: planWitnesses.slice(index === 0 ? 0 : 25, index === 0 ? 25 : 50),
    } as InputMap;
  };
  return {
    witness: { circuitInputs: [makeShard(0), makeShard(1)] },
    publicInputs: input.payroll.publicInputs.map((publicInputs) => ({
      ...publicInputs,
      proofVersion: "2",
    })) as [PayrollIntegrityPublicInputs, PayrollIntegrityPublicInputs],
  };
}
