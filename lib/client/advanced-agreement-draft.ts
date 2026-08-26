import { advancedPaymentPlanSchema, type AdvancedPaymentPlan } from "@/lib/domain/obligations";

const COMMITMENT = /^0x[0-9a-fA-F]{64}$/;

function iso(value: string, label: string): string {
  const parsed = new Date(value);
  if (!value || Number.isNaN(parsed.getTime())) throw new Error(`${label} is not a valid date and time.`);
  return parsed.toISOString();
}

function commitment(value: string, label: string): `0x${string}` {
  const normalized = value.trim();
  if (!COMMITMENT.test(normalized)) {
    throw new Error(`${label} must be a 32-byte 0x commitment.`);
  }
  return normalized.toLowerCase() as `0x${string}`;
}

function linearEntitlement(input: {
  totalAtomic: bigint;
  startsAt: string;
  endsAt: string;
  checkpointAt: string;
}): bigint {
  const start = BigInt(new Date(input.startsAt).getTime());
  const end = BigInt(new Date(input.endsAt).getTime());
  const checkpoint = BigInt(new Date(input.checkpointAt).getTime());
  if (end <= start) throw new Error("The plan end must follow its start.");
  if (checkpoint < start || checkpoint > end) throw new Error("The checkpoint must be inside the stream window.");
  if (checkpoint === start) return 0n;
  if (checkpoint === end) return input.totalAtomic;
  return input.totalAtomic * (checkpoint - start) / (end - start);
}

export function buildAdvancedPaymentPlanDraft(input:
  | {
      kind: "recurring";
      cadence: "weekly" | "biweekly" | "monthly";
      nextDueAt: string;
    }
  | {
      kind: "checkpoint_stream";
      startsAt: string;
      endsAt: string;
      checkpointAt: string;
      totalAtomic: bigint;
      minimumCheckpointSeconds: number;
      attestationCommitment: string;
    }
  | {
      kind: "milestone";
      dueAt: string;
      approvedAt: string;
      milestoneCommitment: string;
      approverCommitment: string;
      attestationCommitment: string;
    }
  | {
      kind: "private_vesting";
      startsAt: string;
      cliffAt: string;
      releaseAt: string;
      endsAt: string;
      totalAtomic: bigint;
    }
): AdvancedPaymentPlan {
  if (input.kind === "recurring") {
    const nextDueAt = iso(input.nextDueAt, "First payment due");
    return advancedPaymentPlanSchema.parse({
      planVersion: "payo-payment-plan-v1",
      kind: "recurring",
      cadence: input.cadence,
      anchorAt: nextDueAt,
      nextDueAt,
      occurrence: 0,
    });
  }
  if (input.kind === "checkpoint_stream") {
    if (input.totalAtomic <= 0n) throw new Error("Stream total must be positive.");
    if (!Number.isInteger(input.minimumCheckpointSeconds) || input.minimumCheckpointSeconds <= 0) {
      throw new Error("Minimum checkpoint interval must be a positive whole number of seconds.");
    }
    const startsAt = iso(input.startsAt, "Stream start");
    const endsAt = iso(input.endsAt, "Stream end");
    const checkpointAt = iso(input.checkpointAt, "Checkpoint");
    const cumulativeEntitlementAtomic = linearEntitlement({
      totalAtomic: input.totalAtomic,
      startsAt,
      endsAt,
      checkpointAt,
    });
    if (cumulativeEntitlementAtomic <= 0n) {
      throw new Error("The checkpoint has not accrued a positive payment yet.");
    }
    return advancedPaymentPlanSchema.parse({
      planVersion: "payo-payment-plan-v1",
      kind: "checkpoint_stream",
      startsAt,
      endsAt,
      totalAtomic: input.totalAtomic.toString(),
      settledAtomic: "0",
      minimumCheckpointSeconds: input.minimumCheckpointSeconds,
      checkpoint: {
        sequence: 1,
        checkpointAt,
        cumulativeEntitlementAtomic: cumulativeEntitlementAtomic.toString(),
        attestationCommitment: commitment(input.attestationCommitment, "Checkpoint attestation"),
      },
    });
  }
  if (input.kind === "milestone") {
    const dueAt = iso(input.dueAt, "Milestone due time");
    const approvedAt = iso(input.approvedAt, "Milestone approval time");
    if (new Date(approvedAt) > new Date(dueAt)) {
      throw new Error("Milestone approval must occur no later than its due time.");
    }
    return advancedPaymentPlanSchema.parse({
      planVersion: "payo-payment-plan-v1",
      kind: "milestone",
      dueAt,
      milestoneCommitment: commitment(input.milestoneCommitment, "Milestone"),
      approverCommitment: commitment(input.approverCommitment, "Milestone approver"),
      attestationCommitment: commitment(input.attestationCommitment, "Milestone approval"),
      approvedAt,
    });
  }
  if (input.totalAtomic <= 0n) throw new Error("Vesting total must be positive.");
  return advancedPaymentPlanSchema.parse({
    planVersion: "payo-payment-plan-v1",
    kind: "private_vesting",
    startsAt: iso(input.startsAt, "Vesting start"),
    cliffAt: iso(input.cliffAt, "Vesting cliff"),
    releaseAt: iso(input.releaseAt, "Vesting release"),
    endsAt: iso(input.endsAt, "Vesting end"),
    totalAtomic: input.totalAtomic.toString(),
    releasedAtomic: "0",
    releaseSequence: 1,
  });
}

