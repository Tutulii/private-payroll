import { z } from "zod";
import {
  classificationAssessmentSchema,
  classificationFactsCommitment,
} from "./classification";
import { atomicAmountSchema, payrollTokenSchema } from "./payroll";

const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);

export const payScheduleSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("recurring"),
    cadence: z.enum(["weekly", "biweekly", "monthly"]),
    nextDueAt: z.string().datetime(),
  }).strict(),
  z.object({
    kind: z.literal("stream"),
    startsAt: z.string().datetime(),
    endsAt: z.string().datetime(),
    totalAtomic: atomicAmountSchema,
    claimedAtomic: atomicAmountSchema,
  }).strict(),
  z.object({
    kind: z.literal("milestone"),
    milestoneCommitment: commitmentSchema,
    approved: z.boolean(),
    dueAt: z.string().datetime(),
  }).strict(),
  z.object({
    kind: z.literal("vesting"),
    startsAt: z.string().datetime(),
    cliffAt: z.string().datetime(),
    endsAt: z.string().datetime(),
    totalAtomic: atomicAmountSchema,
    releasedAtomic: atomicAmountSchema,
  }).strict(),
]).superRefine((schedule, context) => {
  if (schedule.kind === "stream") {
    if (new Date(schedule.endsAt) <= new Date(schedule.startsAt)) {
      context.addIssue({ code: "custom", path: ["endsAt"], message: "Stream end must follow start." });
    }
    if (BigInt(schedule.claimedAtomic) > BigInt(schedule.totalAtomic)) {
      context.addIssue({ code: "custom", path: ["claimedAtomic"], message: "Claimed amount exceeds stream total." });
    }
  }
  if (schedule.kind === "vesting") {
    const start = new Date(schedule.startsAt);
    const cliff = new Date(schedule.cliffAt);
    const end = new Date(schedule.endsAt);
    if (cliff < start || end <= start || cliff > end) {
      context.addIssue({ code: "custom", path: ["cliffAt"], message: "Invalid vesting window." });
    }
    if (BigInt(schedule.releasedAtomic) > BigInt(schedule.totalAtomic)) {
      context.addIssue({ code: "custom", path: ["releasedAtomic"], message: "Released amount exceeds vesting total." });
    }
  }
});
export type PaySchedule = z.infer<typeof payScheduleSchema>;

export function isScheduleDue(scheduleInput: PaySchedule, at = new Date()): boolean {
  const schedule = payScheduleSchema.parse(scheduleInput);
  const timestamp = at.getTime();
  if (schedule.kind === "recurring") return timestamp >= new Date(schedule.nextDueAt).getTime();
  if (schedule.kind === "milestone") {
    return schedule.approved && timestamp >= new Date(schedule.dueAt).getTime();
  }
  if (schedule.kind === "stream") {
    return timestamp >= new Date(schedule.startsAt).getTime()
      && timestamp <= new Date(schedule.endsAt).getTime()
      && streamAccruedAtomic(schedule, at) > BigInt(schedule.claimedAtomic);
  }
  return vestedAtomic(schedule, at) > BigInt(schedule.releasedAtomic);
}

function addUtcMonthClamped(value: Date): Date {
  const year = value.getUTCFullYear();
  const month = value.getUTCMonth();
  const targetMonthStart = new Date(Date.UTC(
    year,
    month + 1,
    1,
    value.getUTCHours(),
    value.getUTCMinutes(),
    value.getUTCSeconds(),
    value.getUTCMilliseconds(),
  ));
  const lastTargetDay = new Date(Date.UTC(year, month + 2, 0)).getUTCDate();
  targetMonthStart.setUTCDate(Math.min(value.getUTCDate(), lastTargetDay));
  return targetMonthStart;
}

export function advanceRecurringSchedule(
  scheduleInput: Extract<PaySchedule, { kind: "recurring" }>,
): Extract<PaySchedule, { kind: "recurring" }> {
  const schedule = payScheduleSchema.parse(scheduleInput);
  if (schedule.kind !== "recurring") throw new Error("Only a recurring schedule can advance by cadence.");
  const currentDueAt = new Date(schedule.nextDueAt);
  const nextDueAt = schedule.cadence === "monthly"
    ? addUtcMonthClamped(currentDueAt)
    : new Date(currentDueAt.getTime() + (schedule.cadence === "weekly" ? 7 : 14) * 24 * 60 * 60 * 1_000);
  return { ...schedule, nextDueAt: nextDueAt.toISOString() };
}

function linearAccrual(total: bigint, startsAt: string, endsAt: string, at: Date): bigint {
  const start = BigInt(new Date(startsAt).getTime());
  const end = BigInt(new Date(endsAt).getTime());
  const now = BigInt(at.getTime());
  if (end <= start) throw new Error("Schedule end must follow its start.");
  if (now <= start) return 0n;
  if (now >= end) return total;
  return total * (now - start) / (end - start);
}

export function streamAccruedAtomic(
  schedule: Extract<PaySchedule, { kind: "stream" }>,
  at = new Date(),
): bigint {
  return linearAccrual(BigInt(schedule.totalAtomic), schedule.startsAt, schedule.endsAt, at);
}

export function vestedAtomic(
  schedule: Extract<PaySchedule, { kind: "vesting" }>,
  at = new Date(),
): bigint {
  if (at.getTime() < new Date(schedule.cliffAt).getTime()) return 0n;
  return linearAccrual(BigInt(schedule.totalAtomic), schedule.startsAt, schedule.endsAt, at);
}

export const offboardingPaySchema = z.object({
  ordinaryPayAtomic: atomicAmountSchema,
  accruedLeaveAtomic: atomicAmountSchema,
  noticeAtomic: atomicAmountSchema,
  severanceAtomic: atomicAmountSchema,
  adjustmentsAtomic: atomicAmountSchema,
  deductionsAtomic: atomicAmountSchema,
  requiredComponents: z.object({
    accruedLeave: z.boolean(),
    notice: z.boolean(),
    severance: z.boolean(),
  }).strict(),
  includedComponents: z.object({
    accruedLeave: z.boolean(),
    notice: z.boolean(),
    severance: z.boolean(),
  }).strict(),
}).strict().superRefine((pay, context) => {
  for (const component of ["accruedLeave", "notice", "severance"] as const) {
    if (pay.requiredComponents[component] && !pay.includedComponents[component]) {
      context.addIssue({ code: "custom", path: ["includedComponents", component], message: `Required final-pay component is missing: ${component}.` });
    }
  }
  const gross = BigInt(pay.ordinaryPayAtomic)
    + BigInt(pay.accruedLeaveAtomic)
    + BigInt(pay.noticeAtomic)
    + BigInt(pay.severanceAtomic)
    + BigInt(pay.adjustmentsAtomic);
  if (BigInt(pay.deductionsAtomic) > gross) {
    context.addIssue({ code: "custom", path: ["deductionsAtomic"], message: "Final-pay deductions exceed gross pay." });
  }
});
export type OffboardingPay = z.infer<typeof offboardingPaySchema>;

export function calculateOffboardingNetAtomic(input: OffboardingPay): bigint {
  const pay = offboardingPaySchema.parse(input);
  for (const component of ["accruedLeave", "notice", "severance"] as const) {
    if (pay.requiredComponents[component] && !pay.includedComponents[component]) {
      throw new Error(`Required final-pay component is missing: ${component}.`);
    }
  }
  const gross = BigInt(pay.ordinaryPayAtomic)
    + BigInt(pay.accruedLeaveAtomic)
    + BigInt(pay.noticeAtomic)
    + BigInt(pay.severanceAtomic)
    + BigInt(pay.adjustmentsAtomic);
  const deductions = BigInt(pay.deductionsAtomic);
  if (deductions > gross) throw new Error("Final-pay deductions exceed gross pay.");
  return gross - deductions;
}

export function assertFxFloor(input: {
  settlementAtomic: string;
  rateNumerator: string;
  rateDenominator: string;
  minimumReferenceAtomic: string;
}): bigint {
  const settlement = BigInt(atomicAmountSchema.parse(input.settlementAtomic));
  const numerator = BigInt(atomicAmountSchema.parse(input.rateNumerator));
  const denominator = BigInt(atomicAmountSchema.parse(input.rateDenominator));
  const minimum = BigInt(atomicAmountSchema.parse(input.minimumReferenceAtomic));
  if (denominator === 0n) throw new Error("FX rate denominator must be positive.");
  if (settlement * numerator < minimum * denominator) {
    throw new Error("Settlement does not meet the committed reference-currency floor.");
  }
  return settlement * numerator / denominator;
}

const checkpointSchema = z.object({
  sequence: z.number().int().nonnegative().max(0xffff_ffff),
  checkpointAt: z.string().datetime(),
  cumulativeEntitlementAtomic: atomicAmountSchema,
  attestationCommitment: commitmentSchema,
}).strict();

/**
 * Phase 3 schedules are immutable obligation terms. Mutable settlement progress
 * is committed separately so advancing a plan cannot silently rewrite the
 * worker's underlying agreement.
 */
export const advancedPaymentPlanSchema = z.discriminatedUnion("kind", [
  z.object({
    planVersion: z.literal("payo-payment-plan-v1"),
    kind: z.literal("recurring"),
    cadence: z.enum(["weekly", "biweekly", "monthly"]),
    anchorAt: z.string().datetime(),
    nextDueAt: z.string().datetime(),
    occurrence: z.number().int().nonnegative().max(0xffff_ffff),
    endsAt: z.string().datetime().optional(),
  }).strict(),
  z.object({
    planVersion: z.literal("payo-payment-plan-v1"),
    kind: z.literal("checkpoint_stream"),
    startsAt: z.string().datetime(),
    endsAt: z.string().datetime(),
    totalAtomic: atomicAmountSchema,
    settledAtomic: atomicAmountSchema,
    minimumCheckpointSeconds: z.number().int().positive().max(31_536_000),
    lastCheckpointAt: z.string().datetime().optional(),
    checkpoint: checkpointSchema,
  }).strict(),
  z.object({
    planVersion: z.literal("payo-payment-plan-v1"),
    kind: z.literal("milestone"),
    dueAt: z.string().datetime(),
    milestoneCommitment: commitmentSchema,
    approverCommitment: commitmentSchema,
    attestationCommitment: commitmentSchema.optional(),
    approvedAt: z.string().datetime().optional(),
    revokedAt: z.string().datetime().optional(),
    settledAt: z.string().datetime().optional(),
  }).strict(),
  z.object({
    planVersion: z.literal("payo-payment-plan-v1"),
    kind: z.literal("private_vesting"),
    startsAt: z.string().datetime(),
    cliffAt: z.string().datetime(),
    releaseAt: z.string().datetime(),
    endsAt: z.string().datetime(),
    totalAtomic: atomicAmountSchema,
    releasedAtomic: atomicAmountSchema,
    releaseSequence: z.number().int().nonnegative().max(0xffff_ffff),
  }).strict(),
]).superRefine((plan, context) => {
  if (plan.kind === "recurring") {
    if (new Date(plan.nextDueAt) < new Date(plan.anchorAt)) {
      context.addIssue({ code: "custom", path: ["nextDueAt"], message: "Recurring due time precedes its anchor." });
    }
    if (plan.endsAt && new Date(plan.nextDueAt) > new Date(plan.endsAt)) {
      context.addIssue({ code: "custom", path: ["endsAt"], message: "Recurring due time exceeds the plan end." });
    }
    return;
  }
  if (plan.kind === "checkpoint_stream") {
    const start = new Date(plan.startsAt);
    const end = new Date(plan.endsAt);
    const checkpoint = new Date(plan.checkpoint.checkpointAt);
    if (end <= start || checkpoint < start || checkpoint > end) {
      context.addIssue({ code: "custom", path: ["checkpoint", "checkpointAt"], message: "Checkpoint is outside the stream window." });
    }
    if (BigInt(plan.settledAtomic) > BigInt(plan.totalAtomic)) {
      context.addIssue({ code: "custom", path: ["settledAtomic"], message: "Settled stream value exceeds its total." });
    }
    if (BigInt(plan.checkpoint.cumulativeEntitlementAtomic) > BigInt(plan.totalAtomic)) {
      context.addIssue({ code: "custom", path: ["checkpoint", "cumulativeEntitlementAtomic"], message: "Checkpoint entitlement exceeds the stream total." });
    }
    if (plan.lastCheckpointAt) {
      const last = new Date(plan.lastCheckpointAt);
      if (checkpoint < last) {
        context.addIssue({ code: "custom", path: ["checkpoint", "checkpointAt"], message: "Checkpoint cannot move backwards." });
      }
      if (
        checkpoint > last
        && (checkpoint.getTime() - last.getTime()) / 1_000 < plan.minimumCheckpointSeconds
      ) {
        context.addIssue({ code: "custom", path: ["checkpoint", "checkpointAt"], message: "Checkpoint is earlier than the committed interval." });
      }
      if (
        checkpoint.getTime() === last.getTime()
        && BigInt(plan.checkpoint.cumulativeEntitlementAtomic) > BigInt(plan.settledAtomic)
      ) {
        context.addIssue({ code: "custom", path: ["checkpoint", "cumulativeEntitlementAtomic"], message: "A settled checkpoint cannot retain unpaid entitlement." });
      }
    }
    return;
  }
  if (plan.kind === "milestone") {
    const hasApproval = Boolean(plan.approvedAt && plan.attestationCommitment);
    if (Boolean(plan.approvedAt) !== Boolean(plan.attestationCommitment)) {
      context.addIssue({ code: "custom", path: ["attestationCommitment"], message: "Milestone approval requires both a time and committed attestation." });
    }
    if (hasApproval && new Date(plan.approvedAt!) > new Date(plan.dueAt)) {
      context.addIssue({ code: "custom", path: ["approvedAt"], message: "Milestone approval occurred after its due time." });
    }
    if (plan.revokedAt && plan.approvedAt && new Date(plan.revokedAt) < new Date(plan.approvedAt)) {
      context.addIssue({ code: "custom", path: ["revokedAt"], message: "Milestone revocation precedes approval." });
    }
    if (plan.settledAt && (!plan.approvedAt || new Date(plan.settledAt) < new Date(plan.approvedAt))) {
      context.addIssue({ code: "custom", path: ["settledAt"], message: "Milestone settlement requires an earlier approval." });
    }
    return;
  }
  const start = new Date(plan.startsAt);
  const cliff = new Date(plan.cliffAt);
  const release = new Date(plan.releaseAt);
  const end = new Date(plan.endsAt);
  if (cliff < start || cliff > end || release < cliff || release > end || end <= start) {
    context.addIssue({ code: "custom", path: ["cliffAt"], message: "Invalid private vesting window." });
  }
  if (BigInt(plan.releasedAtomic) > BigInt(plan.totalAtomic)) {
    context.addIssue({ code: "custom", path: ["releasedAtomic"], message: "Released vesting value exceeds its total." });
  }
});
export type AdvancedPaymentPlan = z.infer<typeof advancedPaymentPlanSchema>;

export function proofScheduleForAdvancedPlan(planInput: AdvancedPaymentPlan): PaySchedule {
  const plan = advancedPaymentPlanSchema.parse(planInput);
  if (plan.kind === "recurring") {
    return payScheduleSchema.parse({ kind: "recurring", cadence: plan.cadence, nextDueAt: plan.nextDueAt });
  }
  if (plan.kind === "checkpoint_stream") {
    return payScheduleSchema.parse({
      kind: "stream",
      startsAt: plan.startsAt,
      endsAt: plan.endsAt,
      totalAtomic: plan.totalAtomic,
      claimedAtomic: plan.settledAtomic,
    });
  }
  if (plan.kind === "milestone") {
    return payScheduleSchema.parse({
      kind: "milestone",
      milestoneCommitment: plan.milestoneCommitment,
      approved: Boolean(plan.approvedAt && plan.attestationCommitment && !plan.revokedAt && !plan.settledAt),
      dueAt: plan.dueAt,
    });
  }
  return payScheduleSchema.parse({
    kind: "vesting",
    startsAt: plan.startsAt,
    cliffAt: plan.cliffAt,
    endsAt: plan.endsAt,
    totalAtomic: plan.totalAtomic,
    releasedAtomic: plan.releasedAtomic,
  });
}

export type AdvancedPlanEntitlement = {
  due: boolean;
  cumulativeEntitlementAtomic: bigint;
  settledAtomic: bigint;
  payableAtomic: bigint;
  sequence: number;
};

export function advancedPlanEntitlement(
  planInput: AdvancedPaymentPlan,
  at = new Date(),
): AdvancedPlanEntitlement {
  const plan = advancedPaymentPlanSchema.parse(planInput);
  if (plan.kind === "recurring") {
    const due = at >= new Date(plan.nextDueAt) && (!plan.endsAt || at <= new Date(plan.endsAt));
    return { due, cumulativeEntitlementAtomic: 0n, settledAtomic: 0n, payableAtomic: 0n, sequence: plan.occurrence };
  }
  if (plan.kind === "milestone") {
    const due = Boolean(
      plan.approvedAt
      && plan.attestationCommitment
      && !plan.revokedAt
      && !plan.settledAt
      && at >= new Date(plan.approvedAt)
      && at >= new Date(plan.dueAt),
    );
    return { due, cumulativeEntitlementAtomic: 0n, settledAtomic: 0n, payableAtomic: 0n, sequence: 0 };
  }
  if (plan.kind === "checkpoint_stream") {
    const checkpointAt = new Date(plan.checkpoint.checkpointAt);
    const settled = BigInt(plan.settledAtomic);
    const entitlement = BigInt(plan.checkpoint.cumulativeEntitlementAtomic);
    const earned = linearAccrual(BigInt(plan.totalAtomic), plan.startsAt, plan.endsAt, checkpointAt);
    if (entitlement !== earned) {
      throw new Error("Checkpoint entitlement does not equal deterministic stream accrual.");
    }
    const due = at >= checkpointAt && entitlement > settled;
    return {
      due,
      cumulativeEntitlementAtomic: entitlement,
      settledAtomic: settled,
      payableAtomic: due ? entitlement - settled : 0n,
      sequence: plan.checkpoint.sequence,
    };
  }
  const settled = BigInt(plan.releasedAtomic);
  const releaseAt = new Date(plan.releaseAt);
  const entitlement = vestedAtomic({
    kind: "vesting",
    startsAt: plan.startsAt,
    cliffAt: plan.cliffAt,
    endsAt: plan.endsAt,
    totalAtomic: plan.totalAtomic,
    releasedAtomic: plan.releasedAtomic,
  }, releaseAt);
  const due = at >= releaseAt && entitlement > settled;
  return {
    due,
    cumulativeEntitlementAtomic: entitlement,
    settledAtomic: settled,
    payableAtomic: due ? entitlement - settled : 0n,
    sequence: plan.releaseSequence,
  };
}

export function settleAdvancedPaymentPlan(input: {
  plan: AdvancedPaymentPlan;
  paidAtomic: string;
  at?: Date;
}): AdvancedPaymentPlan {
  const plan = advancedPaymentPlanSchema.parse(input.plan);
  const paid = BigInt(atomicAmountSchema.parse(input.paidAtomic));
  const at = input.at ?? new Date();
  const entitlement = advancedPlanEntitlement(plan, at);
  if (!entitlement.due) throw new Error("Payment plan has no due entitlement.");
  if (plan.kind === "recurring") {
    if (paid === 0n) throw new Error("Recurring settlement must be positive.");
    const advanced = advanceRecurringSchedule({ kind: "recurring", cadence: plan.cadence, nextDueAt: plan.nextDueAt });
    return advancedPaymentPlanSchema.parse({
      ...plan,
      nextDueAt: advanced.nextDueAt,
      occurrence: plan.occurrence + 1,
    });
  }
  if (plan.kind === "milestone") {
    if (paid === 0n) throw new Error("Milestone settlement must be positive.");
    return advancedPaymentPlanSchema.parse({ ...plan, settledAt: at.toISOString() });
  }
  if (paid !== entitlement.payableAtomic) {
    throw new Error("Settlement does not equal the proof-bound plan entitlement.");
  }
  if (plan.kind === "checkpoint_stream") {
    return advancedPaymentPlanSchema.parse({
      ...plan,
      settledAtomic: entitlement.cumulativeEntitlementAtomic.toString(),
      lastCheckpointAt: plan.checkpoint.checkpointAt,
    });
  }
  return advancedPaymentPlanSchema.parse({
    ...plan,
    releasedAtomic: entitlement.cumulativeEntitlementAtomic.toString(),
    releaseSequence: plan.releaseSequence + 1,
  });
}

const employmentAgreementBaseSchema = z.object({
  id: z.string().min(1).max(160),
  organizationId: z.string().min(8).max(128),
  principalKind: z.enum(["human", "agent"]),
  classification: z.enum(["employee", "contractor", "agent_service"]),
  classificationFactsCommitment: commitmentSchema,
  classificationAssessment: classificationAssessmentSchema.optional(),
  jurisdictionCode: z.string().regex(/^[A-Z]{2}(-[A-Z0-9]{1,3})?$/),
  settlementToken: payrollTokenSchema,
  earningsAtomic: z.array(atomicAmountSchema).min(1).max(8),
  schedule: payScheduleSchema,
  statutoryPolicy: z.object({
    catalogRoot: commitmentSchema,
    policyId: z.string().min(1).max(160),
    policyVersion: z.number().int().positive(),
  }).strict(),
  fxProtection: z.object({
    referenceCurrency: z.string().regex(/^[A-Z]{3}$/),
    minimumReferenceAtomic: atomicAmountSchema,
    // Legacy records may carry a snapshot commitment. New agreements commit
    // the worker's floor and freshness policy; the actual fresh snapshot is
    // selected later and bound by the payroll proof's FX root.
    oracleSnapshotCommitment: commitmentSchema.optional(),
    maximumAgeSeconds: z.number().int().positive().max(86_400),
  }).strict().optional(),
});

const employmentAgreementV1Schema = employmentAgreementBaseSchema.extend({
  agreementVersion: z.literal("payo-agreement-v1"),
}).strict();

const employmentAgreementV2Schema = employmentAgreementBaseSchema.extend({
  agreementVersion: z.literal("payo-agreement-v2"),
  paymentPlan: advancedPaymentPlanSchema,
  planSalt: commitmentSchema,
  termination: z.object({
    terminatedAt: z.string().datetime(),
    reasonCommitment: commitmentSchema,
    pay: offboardingPaySchema,
  }).strict().optional(),
  adjustment: z.object({
    amountAtomic: atomicAmountSchema,
    reasonCommitment: commitmentSchema,
    approverCommitment: commitmentSchema,
  }).strict().optional(),
}).strict().superRefine((agreement, context) => {
  const plan = agreement.paymentPlan;
  const schedule = agreement.schedule;
  const projectionMatches = plan.kind === "recurring"
    ? schedule.kind === "recurring"
      && schedule.cadence === plan.cadence
      && schedule.nextDueAt === plan.nextDueAt
    : plan.kind === "checkpoint_stream"
      ? schedule.kind === "stream"
        && schedule.startsAt === plan.startsAt
        && schedule.endsAt === plan.endsAt
        && schedule.totalAtomic === plan.totalAtomic
        && schedule.claimedAtomic === plan.settledAtomic
      : plan.kind === "milestone"
        ? schedule.kind === "milestone"
          && schedule.milestoneCommitment === plan.milestoneCommitment
          && schedule.approved === Boolean(plan.approvedAt && plan.attestationCommitment && !plan.revokedAt && !plan.settledAt)
          && schedule.dueAt === plan.dueAt
        : schedule.kind === "vesting"
          && schedule.startsAt === plan.startsAt
          && schedule.cliffAt === plan.cliffAt
          && schedule.endsAt === plan.endsAt
          && schedule.totalAtomic === plan.totalAtomic
          && schedule.releasedAtomic === plan.releasedAtomic;
  if (!projectionMatches) {
    context.addIssue({ code: "custom", path: ["schedule"], message: "The proof schedule does not match the advanced payment plan." });
  }
  if (agreement.termination) {
    const components = [
      agreement.termination.pay.ordinaryPayAtomic,
      agreement.termination.pay.accruedLeaveAtomic,
      agreement.termination.pay.noticeAtomic,
      agreement.termination.pay.severanceAtomic,
      agreement.termination.pay.adjustmentsAtomic,
    ];
    if (
      components.length !== agreement.earningsAtomic.length
      || components.some((amount, index) => amount !== agreement.earningsAtomic[index])
    ) {
      context.addIssue({ code: "custom", path: ["earningsAtomic"], message: "Final-pay earnings must preserve all five committed components." });
    }
  }
  if (agreement.adjustment && !agreement.earningsAtomic.includes(agreement.adjustment.amountAtomic)) {
    context.addIssue({ code: "custom", path: ["adjustment", "amountAtomic"], message: "The approved adjustment must be included in earnings." });
  }
});

export const employmentAgreementSchema = z.union([
  employmentAgreementV1Schema,
  employmentAgreementV2Schema,
]).superRefine((agreement, context) => {
  if (!agreement.classificationAssessment) return;
  if (agreement.classificationAssessment.treatment !== agreement.classification) {
    context.addIssue({ code: "custom", path: ["classificationAssessment", "treatment"], message: "The fact assessment does not match the agreement classification." });
  }
  const expected = classificationFactsCommitment({
    agreementId: agreement.id,
    assessment: agreement.classificationAssessment,
  });
  if (expected !== agreement.classificationFactsCommitment.toLowerCase()) {
    context.addIssue({ code: "custom", path: ["classificationFactsCommitment"], message: "The classification facts commitment is invalid." });
  }
});
export type EmploymentAgreement = z.infer<typeof employmentAgreementSchema>;

export function isAgreementDue(agreementInput: EmploymentAgreement, at = new Date()): boolean {
  const agreement = employmentAgreementSchema.parse(agreementInput);
  return agreement.agreementVersion === "payo-agreement-v2"
    ? advancedPlanEntitlement(agreement.paymentPlan, at).due
    : isScheduleDue(agreement.schedule, at);
}
