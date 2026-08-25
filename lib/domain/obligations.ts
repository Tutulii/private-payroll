import { z } from "zod";
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

export const employmentAgreementSchema = z.object({
  agreementVersion: z.literal("payo-agreement-v1"),
  id: z.string().min(1).max(160),
  organizationId: z.string().min(8).max(128),
  principalKind: z.enum(["human", "agent"]),
  classification: z.enum(["employee", "contractor", "agent_service"]),
  classificationFactsCommitment: commitmentSchema,
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
    oracleSnapshotCommitment: commitmentSchema,
    maximumAgeSeconds: z.number().int().positive().max(86_400),
  }).strict().optional(),
}).strict();
export type EmploymentAgreement = z.infer<typeof employmentAgreementSchema>;

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
}).strict();
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
