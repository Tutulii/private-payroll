import { hashRecipientCommitment } from "@/lib/crypto/commitments";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { toHex } from "@/lib/crypto/encoding";
import type { VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { advancedObligationCommitment } from "@/lib/domain/advanced-obligation-commitment";
import {
  buildClassificationAssessment,
  classificationFactsCommitment,
  type ClassificationFactsAnswers,
} from "@/lib/domain/classification";
import { generateUuidV7, payAgreementRecordSchema } from "@/lib/domain/records";
import {
  agreementOperationalDueAt,
  type ObligationScheduleItem,
} from "@/lib/domain/obligation-schedule";
import {
  advanceRecurringSchedule,
  advancedPlanEntitlement,
  proofScheduleForAdvancedPlan,
  settleAdvancedPaymentPlan,
  type AdvancedPaymentPlan,
  type EmploymentAgreement,
  type OffboardingPay,
} from "@/lib/domain/obligations";
import {
  buildPolicyCatalogRoot,
  PAYO_NET_INVOICE_POLICY,
  randomCommitmentSalt,
} from "@/lib/proof/input-builder";
import { advancedPlanProofCommitment } from "@/lib/proof/advanced-plan-commitment";
import { parseTokenAmount, type PayrollTokenSymbol } from "@/lib/starknet/tokens";
import { resolveExecutionPolicy } from "@/lib/policy/execution-catalog";
import type { PayoClient } from "./payo-client";
import type { PayeeDirectoryRecord } from "./payee-directory";
import {
  loadCanonicalEncryptedRecords,
  storeCanonicalEncryptedRecord,
} from "./encrypted-records";

export type PayAgreementDirectoryRecord = ReturnType<typeof payAgreementRecordSchema.parse>;

export function agreementScheduleCommitment(agreement: EmploymentAgreement): `0x${string}` {
  if (agreement.agreementVersion === "payo-agreement-v2") {
    return advancedObligationCommitment(agreement);
  }
  return hashCanonicalJson({
    domain: "PAYO_SCHEDULE_V1",
    agreementId: agreement.id,
    schedule: agreement.schedule,
  });
}

export async function agreementProofScheduleCommitment(
  agreement: EmploymentAgreement,
): Promise<`0x${string}`> {
  return agreement.agreementVersion === "payo-agreement-v2"
    ? advancedPlanProofCommitment(agreement)
    : agreementScheduleCommitment(agreement);
}

export function recordProofScheduleCommitment(record: PayAgreementDirectoryRecord): `0x${string}` {
  return (record.proofScheduleCommitment ?? agreementScheduleCommitment(record.agreement)) as `0x${string}`;
}

export function obligationScheduleForRecord(record: PayAgreementDirectoryRecord): ObligationScheduleItem {
  return {
    agreementId: record.agreement.id,
    agreementRevision: record.revision,
    scheduleCommitment: recordProofScheduleCommitment(record),
    dueAt: agreementOperationalDueAt(record.agreement),
  };
}

export async function advanceEncryptedRecurringAgreement(input: {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  record: PayAgreementDirectoryRecord;
  expectedScheduleCommitment: string;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<PayAgreementDirectoryRecord> {
  const currentCommitment = await agreementProofScheduleCommitment(input.record.agreement);
  if (BigInt(currentCommitment) !== BigInt(input.expectedScheduleCommitment)) {
    throw new Error("The confirmed payroll does not match the agreement's current schedule revision.");
  }
  if (input.record.agreement.schedule.kind !== "recurring") {
    throw new Error("Only a recurring agreement can advance after one settled cycle.");
  }
  const now = input.now ?? new Date();
  const nextSchedule = advanceRecurringSchedule(input.record.agreement.schedule);
  const advancedPlan = input.record.agreement.agreementVersion === "payo-agreement-v2"
    ? (() => {
        if (input.record.agreement.paymentPlan.kind !== "recurring") {
          throw new Error("The advanced payment plan does not match its recurring proof schedule.");
        }
        return {
          ...input.record.agreement.paymentPlan,
          nextDueAt: nextSchedule.nextDueAt,
          occurrence: input.record.agreement.paymentPlan.occurrence + 1,
        };
      })()
    : undefined;
  const agreement = {
    ...input.record.agreement,
    schedule: nextSchedule,
    ...(advancedPlan ? { paymentPlan: advancedPlan } : {}),
  };
  const record = payAgreementRecordSchema.parse({
    ...input.record,
    revision: input.record.revision + 1,
    updatedAt: now.toISOString(),
    agreement,
    proofScheduleCommitment: await agreementProofScheduleCommitment(agreement),
    agreementCommitment: hashCanonicalJson({
      domain: "PAYO_ENCRYPTED_AGREEMENT_V1",
      agreement,
      recipientCommitment: input.record.recipientCommitment,
      agreementSalt: input.record.agreementSalt,
    }),
  });
  return storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: record.organizationId,
    recordType: "pay-agreement",
    record,
    principals: [input.principal],
  });
}

export type PayrollScheduleReference = {
  agreementId: string;
  scheduleCommitment: string;
  paidAtomic?: string;
};

export type PayrollScheduleRun = {
  state: string;
  updatedAt: string;
  dueAt?: string;
  lines: readonly PayrollScheduleReference[];
};

export function lockedPayrollScheduleCommitments(
  runs: readonly PayrollScheduleRun[],
): Set<string> {
  const retryableStates = new Set(["cancelled", "failed", "disputed"]);
  return new Set(runs.flatMap((run) => retryableStates.has(run.state)
    ? []
    : run.lines.map((line) => `${line.agreementId}:${line.scheduleCommitment.toLowerCase()}`)));
}

export async function synchronizeConfirmedRecurringAgreements(input: {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  agreements: readonly PayAgreementDirectoryRecord[];
  runs: readonly PayrollScheduleRun[];
  principal: VaultPrincipalKeyPair;
}): Promise<PayAgreementDirectoryRecord[]> {
  const currentByAgreementId = new Map(input.agreements.map((record) => [record.agreement.id, record]));
  const confirmedRuns = input.runs
    .filter(({ state }) => state === "confirmed" || state === "reconciled")
    .sort((left, right) => left.updatedAt.localeCompare(right.updatedAt));
  for (const run of confirmedRuns) {
    for (const line of run.lines) {
      const current = currentByAgreementId.get(line.agreementId);
      if (!current) continue;
      if (BigInt(await agreementProofScheduleCommitment(current.agreement)) !== BigInt(line.scheduleCommitment)) continue;
      if (current.agreement.agreementVersion === "payo-agreement-v2") {
        if (!line.paidAtomic) throw new Error("A confirmed advanced payment is missing its exact settled amount.");
        const settledAt = new Date(run.dueAt ?? run.updatedAt);
        const paymentPlan = settleAdvancedPaymentPlan({
          plan: current.agreement.paymentPlan,
          paidAtomic: line.paidAtomic,
          at: settledAt,
        });
        const updatedAt = new Date(run.updatedAt).toISOString();
        const agreement = {
          ...current.agreement,
          paymentPlan,
          schedule: proofScheduleForAdvancedPlan(paymentPlan),
        };
        const advanced = payAgreementRecordSchema.parse({
          ...current,
          revision: current.revision + 1,
          updatedAt,
          ...(current.agreement.termination ? { effectiveUntil: updatedAt } : {}),
          agreement,
          proofScheduleCommitment: await agreementProofScheduleCommitment(agreement),
          agreementCommitment: hashCanonicalJson({
            domain: "PAYO_ENCRYPTED_AGREEMENT_V1",
            agreement,
            recipientCommitment: current.recipientCommitment,
            agreementSalt: current.agreementSalt,
          }),
        });
        await storeCanonicalEncryptedRecord({
          client: input.client,
          organizationId: advanced.organizationId,
          recordType: "pay-agreement",
          record: advanced,
          principals: [input.principal],
        });
        currentByAgreementId.set(line.agreementId, advanced);
        continue;
      }
      if (current.agreement.schedule.kind !== "recurring") continue;
      const advanced = await advanceEncryptedRecurringAgreement({
        client: input.client,
        record: current,
        expectedScheduleCommitment: line.scheduleCommitment,
        principal: input.principal,
        now: new Date(run.updatedAt),
      });
      currentByAgreementId.set(line.agreementId, advanced);
    }
  }
  return input.agreements.map((record) => currentByAgreementId.get(record.agreement.id) ?? record);
}

export async function storeEncryptedRecurringAgreement(input: {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  organizationId: string;
  payee: PayeeDirectoryRecord;
  amount: string;
  token: PayrollTokenSymbol;
  classification: "employee" | "contractor" | "agent_service";
  classificationAnswers: ClassificationFactsAnswers;
  cadence: "weekly" | "biweekly" | "monthly";
  nextDueAt: string;
  policyId: string;
  policyVersion: number;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<PayAgreementDirectoryRecord> {
  if (input.payee.organizationId !== input.organizationId) {
    throw new Error("The selected contributor belongs to another organization.");
  }
  if (input.payee.tokenPreference !== input.token) {
    throw new Error("The agreement token must match the contributor's committed token preference.");
  }
  if (
    (input.payee.principalKind === "agent" && input.classification !== "agent_service")
    || (input.payee.principalKind === "human" && input.classification === "agent_service")
  ) {
    throw new Error("The agreement classification does not match the contributor kind.");
  }
  const now = input.now ?? new Date();
  const policy = resolveExecutionPolicy({
    policyId: input.policyId,
    policyVersion: input.policyVersion,
    jurisdictionCode: input.payee.jurisdictionCode,
    classification: input.classification,
    settlementToken: input.token,
    at: now,
  });
  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const agreementId = generateUuidV7(now.getTime() + 1);
  const recipientSalt = randomCommitmentSalt();
  const classificationAssessment = buildClassificationAssessment({
    answers: input.classificationAnswers,
    treatment: input.classification,
    principalKind: input.payee.principalKind,
    reviewedAt: timestamp,
    assessorCommitment: hashCanonicalJson({
      domain: "PAYO_CLASSIFICATION_ASSESSOR_V1",
      principalId: input.principal.principalId,
      publicKey: input.principal.publicKey,
    }),
    salt: randomCommitmentSalt(),
  });
  const classificationCommitment = classificationFactsCommitment({ agreementId, assessment: classificationAssessment });
  const agreementSalt = classificationCommitment;
  const policyCatalogRoot = await buildPolicyCatalogRoot([policy]);
  const recipientCommitment = toHex(hashRecipientCommitment(
    input.payee.recipientAddress,
    recipientSalt,
  ));
  const agreement = {
    agreementVersion: "payo-agreement-v1" as const,
    id: agreementId,
    organizationId: input.organizationId,
    principalKind: input.payee.principalKind,
    classification: input.classification,
    classificationFactsCommitment: classificationCommitment,
    classificationAssessment,
    jurisdictionCode: input.payee.jurisdictionCode,
    settlementToken: input.token,
    earningsAtomic: [parseTokenAmount(input.amount, input.token).toString()],
    schedule: {
      kind: "recurring" as const,
      cadence: input.cadence,
      nextDueAt: new Date(input.nextDueAt).toISOString(),
    },
    statutoryPolicy: {
      catalogRoot: policyCatalogRoot,
      policyId: input.policyId.trim(),
      policyVersion: input.policyVersion,
    },
  };
  const agreementCommitment = hashCanonicalJson({
    domain: "PAYO_ENCRYPTED_AGREEMENT_V1",
    agreement,
    recipientCommitment,
    agreementSalt,
  });
  const record = payAgreementRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    payeeId: input.payee.id,
    agreement,
    recipientCommitment,
    recipientSalt,
    agreementSalt,
    agreementCommitment,
    proofScheduleCommitment: agreementScheduleCommitment(agreement),
    effectiveFrom: timestamp,
  });
  return storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "pay-agreement",
    record,
    principals: [input.principal],
  });
}

export async function storeEncryptedAdvancedAgreement(input: {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  organizationId: string;
  payee: PayeeDirectoryRecord;
  token: PayrollTokenSymbol;
  classification: "employee" | "contractor" | "agent_service";
  classificationAnswers: ClassificationFactsAnswers;
  policyId?: string;
  policyVersion?: number;
  paymentPlan: AdvancedPaymentPlan;
  fixedAmount?: string;
  termination?: {
    terminatedAt: string;
    reasonCommitment: `0x${string}`;
    pay: OffboardingPay;
  };
  adjustment?: {
    amount: string;
    reasonCommitment: `0x${string}`;
    approverCommitment: `0x${string}`;
  };
  fxProtection?: {
    referenceCurrency: "USD";
    minimumReferenceAtomic: string;
    oracleSnapshotCommitment?: `0x${string}`;
    maximumAgeSeconds: number;
  };
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<PayAgreementDirectoryRecord> {
  if (input.payee.organizationId !== input.organizationId) {
    throw new Error("The selected contributor belongs to another organization.");
  }
  if (input.payee.tokenPreference !== input.token) {
    throw new Error("The advanced agreement token must match the contributor's committed preference.");
  }
  if (
    (input.payee.principalKind === "agent" && input.classification !== "agent_service")
    || (input.payee.principalKind === "human" && input.classification === "agent_service")
  ) throw new Error("The advanced agreement classification does not match the contributor kind.");

  const now = input.now ?? new Date();
  const policy = resolveExecutionPolicy({
    policyId: input.policyId ?? PAYO_NET_INVOICE_POLICY.id,
    policyVersion: input.policyVersion ?? PAYO_NET_INVOICE_POLICY.revision,
    jurisdictionCode: input.payee.jurisdictionCode,
    classification: input.classification,
    settlementToken: input.token,
    at: now,
  });

  const plan = input.paymentPlan;
  let earningsAtomic: string[];
  if (input.termination) {
    earningsAtomic = [
      input.termination.pay.ordinaryPayAtomic,
      input.termination.pay.accruedLeaveAtomic,
      input.termination.pay.noticeAtomic,
      input.termination.pay.severanceAtomic,
      input.termination.pay.adjustmentsAtomic,
    ];
  } else if (plan.kind === "checkpoint_stream" || plan.kind === "private_vesting") {
    const entitlementAt = new Date(plan.kind === "checkpoint_stream"
      ? plan.checkpoint.checkpointAt
      : plan.releaseAt);
    earningsAtomic = [advancedPlanEntitlement(plan, entitlementAt).payableAtomic.toString()];
  } else {
    if (!input.fixedAmount) throw new Error("Recurring and milestone plans require a fixed private amount.");
    earningsAtomic = [parseTokenAmount(input.fixedAmount, input.token).toString()];
  }
  let adjustment: {
    amountAtomic: string;
    reasonCommitment: `0x${string}`;
    approverCommitment: `0x${string}`;
  } | undefined;
  if (input.adjustment) {
    const amountAtomic = parseTokenAmount(input.adjustment.amount, input.token).toString();
    if (!earningsAtomic.includes(amountAtomic)) earningsAtomic.push(amountAtomic);
    adjustment = {
      amountAtomic,
      reasonCommitment: input.adjustment.reasonCommitment,
      approverCommitment: input.adjustment.approverCommitment,
    };
  }
  if (earningsAtomic.length > 8 || earningsAtomic.every((amount) => BigInt(amount) === 0n)) {
    throw new Error("An advanced agreement requires 1–8 non-zero earnings components.");
  }

  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const agreementId = generateUuidV7(now.getTime() + 1);
  const recipientSalt = randomCommitmentSalt();
  const classificationAssessment = buildClassificationAssessment({
    answers: input.classificationAnswers,
    treatment: input.classification,
    principalKind: input.payee.principalKind,
    reviewedAt: timestamp,
    assessorCommitment: hashCanonicalJson({
      domain: "PAYO_CLASSIFICATION_ASSESSOR_V1",
      principalId: input.principal.principalId,
      publicKey: input.principal.publicKey,
    }),
    salt: randomCommitmentSalt(),
  });
  const classificationCommitment = classificationFactsCommitment({ agreementId, assessment: classificationAssessment });
  const agreementSalt = classificationCommitment;
  const planSalt = randomCommitmentSalt();
  const policyCatalogRoot = await buildPolicyCatalogRoot([policy]);
  const recipientCommitment = toHex(hashRecipientCommitment(input.payee.recipientAddress, recipientSalt));
  const agreement = {
    agreementVersion: "payo-agreement-v2" as const,
    id: agreementId,
    organizationId: input.organizationId,
    principalKind: input.payee.principalKind,
    classification: input.classification,
    classificationFactsCommitment: classificationCommitment,
    classificationAssessment,
    jurisdictionCode: input.payee.jurisdictionCode,
    settlementToken: input.token,
    earningsAtomic,
    schedule: proofScheduleForAdvancedPlan(plan),
    paymentPlan: plan,
    planSalt,
    statutoryPolicy: {
      catalogRoot: policyCatalogRoot,
      policyId: policy.id,
      policyVersion: policy.revision,
    },
    ...(input.fxProtection ? { fxProtection: input.fxProtection } : {}),
    ...(input.termination ? { termination: input.termination } : {}),
    ...(adjustment ? { adjustment } : {}),
  };
  const agreementCommitment = hashCanonicalJson({
    domain: "PAYO_ENCRYPTED_AGREEMENT_V1",
    agreement,
    recipientCommitment,
    agreementSalt,
  });
  const record = payAgreementRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    payeeId: input.payee.id,
    agreement,
    recipientCommitment,
    recipientSalt,
    agreementSalt,
    agreementCommitment,
    proofScheduleCommitment: await agreementProofScheduleCommitment(agreement),
    effectiveFrom: timestamp,
  });
  return storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "pay-agreement",
    record,
    principals: [input.principal],
  });
}

export async function loadEncryptedPayAgreements(input: {
  client: Pick<PayoClient, "listEncryptedRecords" | "getEncryptedRecord">;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
}): Promise<PayAgreementDirectoryRecord[]> {
  const records = await loadCanonicalEncryptedRecords({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "pay-agreement",
    principal: input.principal,
  });
  const proofBoundRecords = await Promise.all(records.map(async (record) =>
    record.proofScheduleCommitment
      ? record
      : payAgreementRecordSchema.parse({
          ...record,
          proofScheduleCommitment: await agreementProofScheduleCommitment(record.agreement),
        })));
  return proofBoundRecords.sort((left, right) =>
    left.agreement.schedule.kind === "recurring"
    && right.agreement.schedule.kind === "recurring"
      ? left.agreement.schedule.nextDueAt.localeCompare(right.agreement.schedule.nextDueAt)
      : left.createdAt.localeCompare(right.createdAt));
}
