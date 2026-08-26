import { keccak_256 } from "@noble/hashes/sha3.js";
import { concatBytes, encodeU32, encodeUint, normalizedHexBytes, toHex, utf8 } from "@/lib/crypto/encoding";
import { employmentAgreementSchema, type EmploymentAgreement } from "./obligations";

const ZERO_COMMITMENT = `0x${"00".repeat(32)}`;

function unixSeconds(value?: string): bigint {
  if (!value) return 0n;
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds)) throw new Error("Advanced obligation timestamp is invalid.");
  return BigInt(Math.floor(milliseconds / 1_000));
}

function componentMask(components: { accruedLeave: boolean; notice: boolean; severance: boolean }): number {
  return (components.accruedLeave ? 1 : 0)
    | (components.notice ? 2 : 0)
    | (components.severance ? 4 : 0);
}

export type AdvancedObligationEncoding = {
  kind: 0 | 1 | 2 | 3;
  cadence: 0 | 1 | 2;
  flags: number;
  occurrence: number;
  releaseSequence: number;
  checkpointSequence: number;
  minimumCheckpointSeconds: number;
  timestamps: readonly bigint[];
  amounts: readonly bigint[];
  requiredMask: number;
  includedMask: number;
  commitments: readonly string[];
  salt: string;
};

export function encodeAdvancedObligation(agreementInput: EmploymentAgreement): AdvancedObligationEncoding {
  const agreement = employmentAgreementSchema.parse(agreementInput);
  if (agreement.agreementVersion !== "payo-agreement-v2") {
    throw new Error("Only a PAYO v2 agreement has an advanced obligation commitment.");
  }
  const plan = agreement.paymentPlan;
  const kind = plan.kind === "recurring" ? 0 : plan.kind === "checkpoint_stream" ? 1 : plan.kind === "milestone" ? 2 : 3;
  const cadence = plan.kind === "recurring"
    ? plan.cadence === "weekly" ? 0 : plan.cadence === "biweekly" ? 1 : 2
    : 0;
  const termination = agreement.termination?.pay;
  const timestamps = [
    unixSeconds(plan.kind === "recurring" ? plan.anchorAt : undefined),
    unixSeconds(plan.kind === "recurring" ? plan.nextDueAt : undefined),
    unixSeconds(plan.kind === "recurring" ? plan.endsAt : plan.kind === "checkpoint_stream" || plan.kind === "private_vesting" ? plan.endsAt : undefined),
    unixSeconds(plan.kind === "checkpoint_stream" || plan.kind === "private_vesting" ? plan.startsAt : undefined),
    unixSeconds(plan.kind === "private_vesting" ? plan.cliffAt : undefined),
    unixSeconds(plan.kind === "checkpoint_stream" ? plan.checkpoint.checkpointAt : plan.kind === "private_vesting" ? plan.releaseAt : undefined),
    unixSeconds(plan.kind === "checkpoint_stream" ? plan.lastCheckpointAt : undefined),
    unixSeconds(plan.kind === "milestone" ? plan.dueAt : undefined),
    unixSeconds(plan.kind === "milestone" ? plan.approvedAt : undefined),
    unixSeconds(plan.kind === "milestone" ? plan.revokedAt : undefined),
    unixSeconds(plan.kind === "milestone" ? plan.settledAt : undefined),
    unixSeconds(agreement.termination?.terminatedAt),
  ];
  const amounts = [
    BigInt(plan.kind === "checkpoint_stream" || plan.kind === "private_vesting" ? plan.totalAtomic : 0),
    BigInt(plan.kind === "checkpoint_stream" ? plan.settledAtomic : plan.kind === "private_vesting" ? plan.releasedAtomic : 0),
    BigInt(plan.kind === "checkpoint_stream" ? plan.checkpoint.cumulativeEntitlementAtomic : 0),
    BigInt(agreement.adjustment?.amountAtomic ?? 0),
    BigInt(termination?.ordinaryPayAtomic ?? 0),
    BigInt(termination?.accruedLeaveAtomic ?? 0),
    BigInt(termination?.noticeAtomic ?? 0),
    BigInt(termination?.severanceAtomic ?? 0),
    BigInt(termination?.adjustmentsAtomic ?? 0),
    BigInt(termination?.deductionsAtomic ?? 0),
  ];
  return {
    kind,
    cadence,
    flags: (agreement.termination ? 1 : 0) | (agreement.adjustment ? 2 : 0),
    occurrence: plan.kind === "recurring" ? plan.occurrence : 0,
    releaseSequence: plan.kind === "private_vesting" ? plan.releaseSequence : 0,
    checkpointSequence: plan.kind === "checkpoint_stream" ? plan.checkpoint.sequence : 0,
    minimumCheckpointSeconds: plan.kind === "checkpoint_stream" ? plan.minimumCheckpointSeconds : 0,
    timestamps,
    amounts,
    requiredMask: termination ? componentMask(termination.requiredComponents) : 0,
    includedMask: termination ? componentMask(termination.includedComponents) : 0,
    commitments: [
      plan.kind === "milestone" ? plan.milestoneCommitment : ZERO_COMMITMENT,
      plan.kind === "milestone" ? plan.approverCommitment : ZERO_COMMITMENT,
      plan.kind === "checkpoint_stream"
        ? plan.checkpoint.attestationCommitment
        : plan.kind === "milestone" ? plan.attestationCommitment ?? ZERO_COMMITMENT : ZERO_COMMITMENT,
      agreement.termination?.reasonCommitment ?? ZERO_COMMITMENT,
      agreement.adjustment?.reasonCommitment ?? ZERO_COMMITMENT,
      agreement.adjustment?.approverCommitment ?? ZERO_COMMITMENT,
    ],
    salt: agreement.planSalt,
  };
}

export function advancedObligationCommitment(agreementInput: EmploymentAgreement): `0x${string}` {
  const encoded = encodeAdvancedObligation(agreementInput);
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_ADVANCED_OBLIGATION_V1"),
    Uint8Array.of(1, encoded.kind, encoded.cadence, encoded.flags),
    encodeU32(encoded.occurrence),
    encodeU32(encoded.releaseSequence),
    encodeU32(encoded.checkpointSequence),
    encodeU32(encoded.minimumCheckpointSeconds),
    ...encoded.timestamps.map((value) => encodeUint(value, 8)),
    ...encoded.amounts.map((value) => encodeUint(value, 16)),
    Uint8Array.of(encoded.requiredMask, encoded.includedMask),
    ...encoded.commitments.map((value) => normalizedHexBytes(value, 32)),
    normalizedHexBytes(encoded.salt, 32),
  )));
}
