import { hashRecipientCommitment } from "@/lib/crypto/commitments";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { toHex } from "@/lib/crypto/encoding";
import type { VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { generateUuidV7, payAgreementRecordSchema } from "@/lib/domain/records";
import { advanceRecurringSchedule, type EmploymentAgreement } from "@/lib/domain/obligations";
import {
  buildPolicyCatalogRoot,
  PAYO_NET_INVOICE_POLICY,
  randomCommitmentSalt,
} from "@/lib/proof/input-builder";
import { parseTokenAmount, type PayrollTokenSymbol } from "@/lib/starknet/tokens";
import type { PayoClient } from "./payo-client";
import type { PayeeDirectoryRecord } from "./payee-directory";
import {
  loadCanonicalEncryptedRecords,
  storeCanonicalEncryptedRecord,
} from "./encrypted-records";

export type PayAgreementDirectoryRecord = ReturnType<typeof payAgreementRecordSchema.parse>;

export function agreementScheduleCommitment(agreement: EmploymentAgreement): `0x${string}` {
  return hashCanonicalJson({
    domain: "PAYO_SCHEDULE_V1",
    agreementId: agreement.id,
    schedule: agreement.schedule,
  });
}

export async function advanceEncryptedRecurringAgreement(input: {
  client: Pick<PayoClient, "storeEncryptedRecord">;
  record: PayAgreementDirectoryRecord;
  expectedScheduleCommitment: string;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<PayAgreementDirectoryRecord> {
  const currentCommitment = agreementScheduleCommitment(input.record.agreement);
  if (BigInt(currentCommitment) !== BigInt(input.expectedScheduleCommitment)) {
    throw new Error("The confirmed payroll does not match the agreement's current schedule revision.");
  }
  if (input.record.agreement.schedule.kind !== "recurring") {
    throw new Error("Only a recurring agreement can advance after one settled cycle.");
  }
  const now = input.now ?? new Date();
  const agreement = {
    ...input.record.agreement,
    schedule: advanceRecurringSchedule(input.record.agreement.schedule),
  };
  const record = payAgreementRecordSchema.parse({
    ...input.record,
    revision: input.record.revision + 1,
    updatedAt: now.toISOString(),
    agreement,
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
};

export type PayrollScheduleRun = {
  state: string;
  updatedAt: string;
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
      if (!current || current.agreement.schedule.kind !== "recurring") continue;
      if (BigInt(agreementScheduleCommitment(current.agreement)) !== BigInt(line.scheduleCommitment)) continue;
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
  if (input.classification === "employee" || input.policyId !== PAYO_NET_INVOICE_POLICY.id) {
    throw new Error("Phase 2 agreement execution currently supports only the contractor/agent net-invoice reference policy.");
  }
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const agreementId = generateUuidV7(now.getTime() + 1);
  const recipientSalt = randomCommitmentSalt();
  const agreementSalt = randomCommitmentSalt();
  const policyCatalogRoot = await buildPolicyCatalogRoot([PAYO_NET_INVOICE_POLICY]);
  const recipientCommitment = toHex(hashRecipientCommitment(
    input.payee.recipientAddress,
    recipientSalt,
  ));
  const classificationFactsCommitment = hashCanonicalJson({
    domain: "PAYO_CLASSIFICATION_FACTS_V1",
    agreementId,
    principalKind: input.payee.principalKind,
    classification: input.classification,
    salt: agreementSalt,
  });
  const agreement = {
    agreementVersion: "payo-agreement-v1" as const,
    id: agreementId,
    organizationId: input.organizationId,
    principalKind: input.payee.principalKind,
    classification: input.classification,
    classificationFactsCommitment,
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
  return records.sort((left, right) =>
    left.agreement.schedule.kind === "recurring"
    && right.agreement.schedule.kind === "recurring"
      ? left.agreement.schedule.nextDueAt.localeCompare(right.agreement.schedule.nextDueAt)
      : left.createdAt.localeCompare(right.createdAt));
}
