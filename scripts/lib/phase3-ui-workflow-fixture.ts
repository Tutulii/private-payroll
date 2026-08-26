import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import {
  storeEncryptedAgreementFromForm,
  type AgreementFormDraft,
  type AgreementPlanKind,
} from "@/lib/client/agreement-form-workflow";
import { prepareEncryptedPayee } from "@/lib/client/payee-directory";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { decryptVaultRecord, encryptedVaultRecordSchema, generateVaultPrincipal } from "@/lib/crypto/vault";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { payAgreementRecordSchema, payeeRecordSchema } from "@/lib/domain/records";
import { PAYO_EMPLOYEE_POLICY_OPTIONS } from "@/lib/policy/execution-catalog";

export const phase3UiFixturePath = resolve(
  process.cwd(),
  "evidence/phase3-devnet-fixtures/advanced-matrix-ui-origin.json",
);
export const phase3UiOrganizationId = "018f1000-0000-7000-8000-000000000003";
export const phase3UiValidityStart = BigInt(Math.floor(Date.UTC(2026, 7, 26, 0, 0, 0) / 1_000));

const workflowNames = [
  "recurring",
  "checkpoint",
  "milestone",
  "vesting",
  "final-pay",
  "approved-adjustment",
  "statutory-fx-classification",
] as const;
export type Phase3UiWorkflowName = (typeof workflowNames)[number];

const artifactSchema = z.object({
  schemaVersion: z.literal("payo.phase3.ui-workflow-origin.v1"),
  generatedAt: z.string().datetime(),
  organizationId: z.string().uuid(),
  validityStart: z.string().regex(/^\d+$/),
  entries: z.array(z.object({
    workflow: z.enum(workflowNames),
    formInputCommitment: z.string().regex(/^0x[0-9a-f]{64}$/),
    payee: payeeRecordSchema,
    agreementRecord: payAgreementRecordSchema,
    encryptedEnvelope: encryptedVaultRecordSchema,
    checks: z.object({
      productionCommand: z.literal("storeEncryptedAgreementFromForm"),
      encryptedRoundTrip: z.literal(true),
      plaintextAbsentFromEnvelope: z.literal(true),
    }).strict(),
  }).strict()).length(workflowNames.length),
}).strict();

export type Phase3UiWorkflowFixture = z.infer<typeof artifactSchema>;

function iso(seconds: bigint): string {
  return new Date(Number(seconds) * 1_000).toISOString();
}

function commitment(byte: number): `0x${string}` {
  return `0x${byte.toString(16).padStart(2, "0").repeat(32)}`;
}

function baseDraft(planKind: AgreementPlanKind): AgreementFormDraft {
  return {
    planKind,
    amount: "1",
    classification: "contractor",
    classificationAnswers: referenceClassificationAnswers("contractor"),
    cadence: "monthly",
    nextDueAt: iso(phase3UiValidityStart),
    planStartsAt: iso(phase3UiValidityStart - 3_600n),
    planEndsAt: iso(phase3UiValidityStart + 3_600n),
    planCheckpointAt: iso(phase3UiValidityStart),
    planCliffAt: iso(phase3UiValidityStart - 1_800n),
    planTotalAmount: "1",
    milestoneCommitment: commitment(121),
    approverCommitment: commitment(131),
    attestationCommitment: commitment(141),
    adjustmentReasonCommitment: commitment(161),
    terminationReasonCommitment: commitment(160),
    finalOrdinaryAmount: "0.1",
    finalLeaveAmount: "0.02",
    finalNoticeAmount: "0.03",
    finalSeveranceAmount: "0.04",
    finalAdjustmentAmount: "0.01",
    finalDeductionsAmount: "0",
    requireLeave: true,
    requireNotice: true,
    requireSeverance: true,
    policyId: "payo-net-invoice-no-withholding-v1",
    policyVersion: 1,
    fxFloorAmount: "",
    fxMaximumAgeSeconds: 300,
  };
}

function draftFor(workflow: Phase3UiWorkflowName): AgreementFormDraft {
  if (workflow === "recurring") return baseDraft("recurring");
  if (workflow === "checkpoint") return {
    ...baseDraft("checkpoint_stream"),
    attestationCommitment: commitment(151),
  };
  if (workflow === "milestone") return {
    ...baseDraft("milestone"),
    amount: "0.3",
  };
  if (workflow === "vesting") return baseDraft("private_vesting");
  if (workflow === "final-pay") return {
    ...baseDraft("final_pay"),
    milestoneCommitment: commitment(122),
    approverCommitment: commitment(132),
    attestationCommitment: commitment(142),
  };
  if (workflow === "approved-adjustment") return {
    ...baseDraft("approved_adjustment"),
    amount: "0.25",
    milestoneCommitment: commitment(123),
    approverCommitment: commitment(162),
    attestationCommitment: commitment(143),
  };
  return {
    ...baseDraft("recurring"),
    amount: "10",
    classification: "employee",
    classificationAnswers: referenceClassificationAnswers("employee"),
    policyId: PAYO_EMPLOYEE_POLICY_OPTIONS.US.id,
    policyVersion: PAYO_EMPLOYEE_POLICY_OPTIONS.US.revision,
    fxFloorAmount: "7.8",
  };
}

export async function generatePhase3UiWorkflowFixture(): Promise<Phase3UiWorkflowFixture> {
  const principal = generateVaultPrincipal("phase3-ui-workflow-evidence");
  const entries: Phase3UiWorkflowFixture["entries"] = [];
  for (const [index, workflow] of workflowNames.entries()) {
    const at = new Date(Number(phase3UiValidityStart - 120n - BigInt(index)) * 1_000);
    const draft = draftFor(workflow);
    const preparedPayee = prepareEncryptedPayee({
      organizationId: phase3UiOrganizationId,
      displayName: `Synthetic ${workflow} worker`,
      principalKind: "human",
      recipientAddress: `0x${(0x500 + index).toString(16)}`,
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      now: at,
    });
    let encryptedEnvelope: unknown;
    const record = await storeEncryptedAgreementFromForm({
      client: {
        async storeEncryptedRecord(request: { envelope: unknown }) {
          encryptedEnvelope = request.envelope;
          return { record: {} };
        },
      } as never,
      organizationId: phase3UiOrganizationId,
      payee: preparedPayee.record,
      principal,
      draft,
      now: at,
    });
    const envelope = encryptedVaultRecordSchema.parse(encryptedEnvelope);
    const roundTrip = payAgreementRecordSchema.parse(decryptVaultRecord(envelope, principal));
    if (JSON.stringify(roundTrip) !== JSON.stringify(record)) {
      throw new Error(`Encrypted ${workflow} agreement did not round-trip exactly.`);
    }
    const envelopeJson = JSON.stringify(envelope);
    const privateValues = [preparedPayee.record.displayName, ...record.agreement.earningsAtomic];
    if (privateValues.some((value) => envelopeJson.includes(value))) {
      throw new Error(`Encrypted ${workflow} envelope exposed a private form value.`);
    }
    entries.push({
      workflow,
      formInputCommitment: hashCanonicalJson({
        domain: "PAYO_PHASE3_UI_FORM_V1",
        payeeId: preparedPayee.record.id,
        draft,
      }),
      payee: preparedPayee.record,
      agreementRecord: record,
      encryptedEnvelope: envelope,
      checks: {
        productionCommand: "storeEncryptedAgreementFromForm",
        encryptedRoundTrip: true,
        plaintextAbsentFromEnvelope: true,
      },
    });
  }
  return artifactSchema.parse({
    schemaVersion: "payo.phase3.ui-workflow-origin.v1",
    generatedAt: new Date().toISOString(),
    organizationId: phase3UiOrganizationId,
    validityStart: phase3UiValidityStart.toString(),
    entries,
  });
}

export async function writePhase3UiWorkflowFixture(): Promise<Phase3UiWorkflowFixture> {
  const fixture = await generatePhase3UiWorkflowFixture();
  await writeFile(phase3UiFixturePath, `${JSON.stringify(fixture, null, 2)}\n`, { mode: 0o600 });
  return fixture;
}

export async function loadPhase3UiWorkflowFixture(): Promise<Phase3UiWorkflowFixture> {
  return artifactSchema.parse(JSON.parse(await readFile(phase3UiFixturePath, "utf8")));
}
