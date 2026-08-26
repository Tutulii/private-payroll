import { z } from "zod";
import { commitmentSchema, uuidV7Schema } from "./records";
import type { EmploymentAgreement } from "./obligations";

export const obligationScheduleItemSchema = z.object({
  agreementId: uuidV7Schema,
  agreementRevision: z.number().int().positive(),
  scheduleCommitment: commitmentSchema,
  dueAt: z.string().datetime(),
}).strict();

export const obligationScheduleBatchSchema = z.object({
  organizationId: uuidV7Schema,
  schedules: z.array(obligationScheduleItemSchema).min(1).max(100),
}).strict();

export type ObligationScheduleItem = z.infer<typeof obligationScheduleItemSchema>;

export type DueObligationSignal = ObligationScheduleItem & {
  materializedAt: string;
};

/**
 * Return the one operational timestamp the scheduler may see. Everything that
 * determines amount, eligibility and settlement remains in the encrypted
 * agreement and is checked locally and by the proof circuit.
 */
export function agreementOperationalDueAt(agreement: EmploymentAgreement): string {
  if (agreement.agreementVersion === "payo-agreement-v2") {
    const plan = agreement.paymentPlan;
    if (plan.kind === "recurring") return plan.nextDueAt;
    if (plan.kind === "checkpoint_stream") return plan.checkpoint.checkpointAt;
    if (plan.kind === "milestone") return plan.dueAt;
    return plan.releaseAt;
  }
  const schedule = agreement.schedule;
  if (schedule.kind === "recurring") return schedule.nextDueAt;
  if (schedule.kind === "milestone") return schedule.dueAt;
  if (schedule.kind === "stream") return schedule.startsAt;
  return schedule.cliffAt;
}
