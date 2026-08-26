import type { VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  CLASSIFICATION_EMPLOYEE_THRESHOLD,
  scoreClassificationFacts,
  type ClassificationFactsAnswers,
} from "@/lib/domain/classification";
import { parseTokenAmount, parseTokenAmountOrZero } from "@/lib/starknet/tokens";
import { buildAdvancedPaymentPlanDraft } from "./advanced-agreement-draft";
import {
  storeEncryptedAdvancedAgreement,
  type PayAgreementDirectoryRecord,
} from "./agreement-directory";
import type { PayeeDirectoryRecord } from "./payee-directory";
import type { PayoClient } from "./payo-client";

export type AgreementPlanKind =
  | "recurring"
  | "checkpoint_stream"
  | "milestone"
  | "private_vesting"
  | "approved_adjustment"
  | "final_pay";

export type AgreementClassification = "employee" | "contractor" | "agent_service";

export type AgreementFormDraft = {
  planKind: AgreementPlanKind;
  amount: string;
  classification: AgreementClassification;
  classificationAnswers: ClassificationFactsAnswers;
  cadence: "weekly" | "biweekly" | "monthly";
  nextDueAt: string;
  planStartsAt: string;
  planEndsAt: string;
  planCheckpointAt: string;
  planCliffAt: string;
  planTotalAmount: string;
  milestoneCommitment: string;
  approverCommitment: string;
  attestationCommitment: string;
  adjustmentReasonCommitment: string;
  terminationReasonCommitment: string;
  finalOrdinaryAmount: string;
  finalLeaveAmount: string;
  finalNoticeAmount: string;
  finalSeveranceAmount: string;
  finalAdjustmentAmount: string;
  finalDeductionsAmount: string;
  requireLeave: boolean;
  requireNotice: boolean;
  requireSeverance: boolean;
  policyId: string;
  policyVersion: number;
  fxFloorAmount: string;
  fxMaximumAgeSeconds: number;
};

export type StoreAgreementFromFormInput = {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  organizationId: string;
  payee: PayeeDirectoryRecord;
  principal: VaultPrincipalKeyPair;
  draft: AgreementFormDraft;
  now?: Date;
};

function assertClassificationConsistency(
  payee: PayeeDirectoryRecord,
  classification: AgreementClassification,
  answers: ClassificationFactsAnswers,
): void {
  if (payee.principalKind === "agent") {
    if (classification !== "agent_service") {
      throw new Error("An AI-agent contributor requires the agent-service classification.");
    }
    return;
  }
  if (classification === "agent_service") {
    throw new Error("A human contributor cannot use the agent-service classification.");
  }
  const score = scoreClassificationFacts(answers);
  const matches = classification === "employee"
    ? score >= CLASSIFICATION_EMPLOYEE_THRESHOLD
    : score < CLASSIFICATION_EMPLOYEE_THRESHOLD;
  if (!matches) {
    throw new Error("The selected treatment does not match the versioned classification fact rubric.");
  }
}

function exactCommitment(value: string): `0x${string}` {
  return value.trim().toLowerCase() as `0x${string}`;
}

/**
 * The production command behind Team's agreement form. Evidence generators and
 * integration tests call this command too, so a workflow cannot have a separate
 * fixture-only interpretation of the visible UI fields.
 */
export async function storeEncryptedAgreementFromForm(
  input: StoreAgreementFromFormInput,
): Promise<PayAgreementDirectoryRecord> {
  const { draft, payee } = input;
  assertClassificationConsistency(payee, draft.classification, draft.classificationAnswers);

  const common = {
    client: input.client,
    organizationId: input.organizationId,
    payee,
    token: payee.tokenPreference,
    classification: draft.classification,
    classificationAnswers: draft.classificationAnswers,
    policyId: draft.policyId,
    policyVersion: draft.policyVersion,
    principal: input.principal,
    now: input.now,
  } as const;

  if (draft.planKind === "recurring") {
    return storeEncryptedAdvancedAgreement({
      ...common,
      paymentPlan: buildAdvancedPaymentPlanDraft({
        kind: "recurring",
        cadence: draft.cadence,
        nextDueAt: draft.nextDueAt,
      }),
      fixedAmount: draft.amount,
      ...(draft.fxFloorAmount.trim() ? {
        fxProtection: {
          referenceCurrency: "USD" as const,
          minimumReferenceAtomic: parseTokenAmount(draft.fxFloorAmount, "USDC").toString(),
          maximumAgeSeconds: draft.fxMaximumAgeSeconds,
        },
      } : {}),
    });
  }

  if (draft.planKind === "checkpoint_stream") {
    return storeEncryptedAdvancedAgreement({
      ...common,
      paymentPlan: buildAdvancedPaymentPlanDraft({
        kind: "checkpoint_stream",
        startsAt: draft.planStartsAt,
        endsAt: draft.planEndsAt,
        checkpointAt: draft.planCheckpointAt,
        totalAtomic: parseTokenAmount(draft.planTotalAmount, payee.tokenPreference),
        minimumCheckpointSeconds: 900,
        attestationCommitment: draft.attestationCommitment,
      }),
    });
  }

  if (draft.planKind === "private_vesting") {
    return storeEncryptedAdvancedAgreement({
      ...common,
      paymentPlan: buildAdvancedPaymentPlanDraft({
        kind: "private_vesting",
        startsAt: draft.planStartsAt,
        cliffAt: draft.planCliffAt,
        releaseAt: draft.planCheckpointAt,
        endsAt: draft.planEndsAt,
        totalAtomic: parseTokenAmount(draft.planTotalAmount, payee.tokenPreference),
      }),
    });
  }

  const milestonePlan = buildAdvancedPaymentPlanDraft({
    kind: "milestone",
    dueAt: draft.nextDueAt,
    approvedAt: draft.nextDueAt,
    milestoneCommitment: draft.milestoneCommitment,
    approverCommitment: draft.approverCommitment,
    attestationCommitment: draft.attestationCommitment,
  });
  if (draft.planKind === "milestone") {
    return storeEncryptedAdvancedAgreement({
      ...common,
      paymentPlan: milestonePlan,
      fixedAmount: draft.amount,
    });
  }
  if (draft.planKind === "approved_adjustment") {
    return storeEncryptedAdvancedAgreement({
      ...common,
      paymentPlan: milestonePlan,
      fixedAmount: draft.amount,
      adjustment: {
        amount: draft.amount,
        reasonCommitment: exactCommitment(draft.adjustmentReasonCommitment),
        approverCommitment: exactCommitment(draft.approverCommitment),
      },
    });
  }

  const positiveAtomic = (amount: string) => parseTokenAmount(amount, payee.tokenPreference).toString();
  const optionalAtomic = (amount: string) => parseTokenAmountOrZero(amount, payee.tokenPreference).toString();
  return storeEncryptedAdvancedAgreement({
    ...common,
    paymentPlan: milestonePlan,
    termination: {
      terminatedAt: new Date(draft.nextDueAt).toISOString(),
      reasonCommitment: exactCommitment(draft.terminationReasonCommitment),
      pay: {
        ordinaryPayAtomic: positiveAtomic(draft.finalOrdinaryAmount),
        accruedLeaveAtomic: optionalAtomic(draft.finalLeaveAmount),
        noticeAtomic: optionalAtomic(draft.finalNoticeAmount),
        severanceAtomic: optionalAtomic(draft.finalSeveranceAmount),
        adjustmentsAtomic: optionalAtomic(draft.finalAdjustmentAmount),
        deductionsAtomic: optionalAtomic(draft.finalDeductionsAmount),
        requiredComponents: {
          accruedLeave: draft.requireLeave,
          notice: draft.requireNotice,
          severance: draft.requireSeverance,
        },
        includedComponents: {
          accruedLeave: draft.requireLeave,
          notice: draft.requireNotice,
          severance: draft.requireSeverance,
        },
      },
    },
  });
}
