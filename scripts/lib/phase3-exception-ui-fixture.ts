import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import { storeEncryptedAgreementFromForm, type AgreementFormDraft } from "@/lib/client/agreement-form-workflow";
import { createEncryptedRemediationDraft, createEncryptedWageClaimDraft } from "@/lib/client/claim-workflows";
import { prepareEncryptedPayee } from "@/lib/client/payee-directory";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { decryptVaultRecord, encryptedVaultRecordSchema, generateVaultPrincipal } from "@/lib/crypto/vault";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  payAgreementRecordSchema,
  payeeRecordSchema,
  remediationRecordSchema,
  wageClaimRecordSchema,
} from "@/lib/domain/records";
import { advancedPlanProofCommitment } from "@/lib/proof/advanced-plan-commitment";
import {
  buildPayrollIntegrityInputsFromSerialized,
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
  type SerializedPayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";
import { buildWageClaimInputs } from "@/lib/proof/wage-claim-input";

const artifactPath = resolve(
  process.cwd(),
  "evidence/phase3-devnet-fixtures/claim-remediation-ui-origin.json",
);
const organizationId = "018f1000-0000-7000-8000-000000000004";
const runId = "018f1000-0000-7000-8000-000000000005";
const proofBundleId = "018f1000-0000-7000-8000-000000000006";
const settlementId = "018f1000-0000-7000-8000-000000000007";
const validityStart = BigInt(process.env.PAYO_PHASE3_VALIDITY_START ?? "1000");
const validityExpiry = BigInt(process.env.PAYO_PHASE3_VALIDITY_EXPIRY ?? "2000");
if (
  validityStart < 0n
  || validityExpiry < validityStart
  || validityExpiry - validityStart > 3_600n
) {
  throw new Error("Phase 3 exception-fixture validity must be ordered and no longer than one hour.");
}
const now = new Date("2026-08-26T11:00:00.000Z");

const artifactSchema = z.object({
  schemaVersion: z.literal("payo.phase3.exception-ui-origin.v1"),
  generatedAt: z.string().datetime(),
  organizationId: z.string().uuid(),
  runId: z.string().uuid(),
  recipientAddress: z.string().min(1),
  formInputCommitments: z.object({
    agreement: z.string().regex(/^0x[0-9a-f]{64}$/),
    claim: z.string().regex(/^0x[0-9a-f]{64}$/),
    remediation: z.string().regex(/^0x[0-9a-f]{64}$/),
  }).strict(),
  payee: payeeRecordSchema,
  agreementRecord: payAgreementRecordSchema,
  agreementEnvelope: encryptedVaultRecordSchema,
  claimDraft: wageClaimRecordSchema,
  claimEnvelope: encryptedVaultRecordSchema,
  submittedClaim: wageClaimRecordSchema,
  remediationDraft: remediationRecordSchema,
  remediationEnvelope: encryptedVaultRecordSchema,
  payrollRequest: z.custom<SerializedPayrollIntegrityBuildRequest>((value) =>
    Boolean(value && typeof value === "object" && Array.isArray((value as SerializedPayrollIntegrityBuildRequest).lines))),
  checks: z.object({
    teamProductionCommand: z.literal("storeEncryptedAgreementFromForm"),
    claimProductionCommand: z.literal("createEncryptedWageClaimDraft"),
    remediationProductionCommand: z.literal("createEncryptedRemediationDraft"),
    encryptedRoundTrips: z.literal(true),
    plaintextAbsentFromEnvelopes: z.literal(true),
  }).strict(),
}).strict();

export type Phase3ExceptionUiFixture = z.infer<typeof artifactSchema>;

function captureStore() {
  let envelope: unknown;
  return {
    client: {
      async storeEncryptedRecord(request: { envelope: unknown }) {
        envelope = request.envelope;
        return { record: {} };
      },
    },
    envelope: () => encryptedVaultRecordSchema.parse(envelope),
  };
}

export async function generatePhase3ExceptionUiFixture(): Promise<Phase3ExceptionUiFixture> {
  const principal = generateVaultPrincipal("phase3-exception-ui-evidence");
  const recipientAddress = process.env.PAYO_PHASE3_RECIPIENT_ADDRESS ?? "0x456";
  const payee = prepareEncryptedPayee({
    organizationId,
    displayName: "Synthetic claimant",
    principalKind: "human",
    recipientAddress,
    tokenPreference: "STRK",
    jurisdictionCode: "US",
    principal,
    now,
  }).record;
  const agreementDraft: AgreementFormDraft = {
    planKind: "recurring",
    amount: "0.000000000000000003",
    classification: "contractor",
    classificationAnswers: referenceClassificationAnswers("contractor"),
    cadence: "monthly",
    nextDueAt: "1970-01-01T00:16:40.000Z",
    planStartsAt: "",
    planEndsAt: "",
    planCheckpointAt: "",
    planCliffAt: "",
    planTotalAmount: "",
    milestoneCommitment: "",
    approverCommitment: "",
    attestationCommitment: "",
    adjustmentReasonCommitment: "",
    terminationReasonCommitment: "",
    finalOrdinaryAmount: "",
    finalLeaveAmount: "0",
    finalNoticeAmount: "0",
    finalSeveranceAmount: "0",
    finalAdjustmentAmount: "0",
    finalDeductionsAmount: "0",
    requireLeave: false,
    requireNotice: false,
    requireSeverance: false,
    policyId: PAYO_NET_INVOICE_POLICY.id,
    policyVersion: PAYO_NET_INVOICE_POLICY.revision,
    fxFloorAmount: "",
    fxMaximumAgeSeconds: 300,
  };
  const agreementStore = captureStore();
  const agreementRecord = await storeEncryptedAgreementFromForm({
    client: agreementStore.client as never,
    organizationId,
    payee,
    principal,
    draft: agreementDraft,
    now,
  });
  const agreementEnvelope = agreementStore.envelope();

  const payrollRequest = serializePayrollIntegrityBuildRequest({
    chainId: process.env.PAYO_PHASE3_CHAIN_ID ?? "0x1",
    sealAddress: process.env.PAYO_PHASE3_SEAL_ADDRESS ?? "0x12345",
    organizationSecret: `0x${"15".repeat(32)}`,
    cycleId: "phase3-wage-claim-proof",
    revision: 2,
    validityStart,
    validityExpiry,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [buildFxSnapshot({
      baseToken: "STRK",
      referenceCurrency: "USD",
      quoteDecimals: 6,
      haircutBps: 0,
      maximumAgeSeconds: 300,
      minimumSources: 3,
      aggregatedSourceCount: 5,
      quotes: [{ source: "pragma-strk", priceAtomic: "250000", observedAt: "1970-01-01T00:16:30.000Z" }],
      now: new Date("1970-01-01T00:16:40.000Z"),
    })],
    lines: [{
      agreementId: agreementRecord.agreement.id,
      recipientAddress: payee.recipientAddress,
      recipientSalt: agreementRecord.recipientSalt as `0x${string}`,
      agreementSalt: agreementRecord.agreementSalt as `0x${string}`,
      lineSalt: `0x${"18".repeat(32)}`,
      token: "STRK",
      earningsAtomic: agreementRecord.agreement.earningsAtomic,
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment: await advancedPlanProofCommitment(agreementRecord.agreement),
      dueAt: validityStart,
      validUntil: validityExpiry,
      classification: { declared: 2, score: 2, employeeThreshold: 5 },
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
    }],
  });

  const claimStore = captureStore();
  const claimDraft = await createEncryptedWageClaimDraft({
    client: claimStore.client as never,
    organizationId,
    agreementId: agreementRecord.agreement.id,
    runId,
    claimKind: "missing_obligation",
    principal,
    now: new Date(now.getTime() + 10),
  });
  const claimEnvelope = claimStore.envelope();
  const payroll = await buildPayrollIntegrityInputsFromSerialized(payrollRequest);
  const claimInput = await buildWageClaimInputs({
    payroll,
    agreementId: claimDraft.agreementId,
    claimKind: claimDraft.claimKind,
    claimSalt: claimDraft.claimSalt as `0x${string}`,
    validityStart,
    validityExpiry,
  });
  const submittedClaim = wageClaimRecordSchema.parse({
    ...claimDraft,
    revision: 2,
    updatedAt: new Date(now.getTime() + 20).toISOString(),
    claimNullifier: claimInput.claimNullifier,
    shortfallAtomic: claimInput.shortfallAtomic,
    token: claimInput.token,
    proofBundleId,
    settlementId,
    state: "submitted",
  });
  const remediationStore = captureStore();
  const remediationDraft = await createEncryptedRemediationDraft({
    client: remediationStore.client as never,
    organizationId,
    claim: submittedClaim,
    principal,
    now: new Date(now.getTime() + 30),
  });
  const remediationEnvelope = remediationStore.envelope();

  for (const [record, envelope] of [
    [agreementRecord, agreementEnvelope],
    [claimDraft, claimEnvelope],
    [remediationDraft, remediationEnvelope],
  ] as const) {
    if (JSON.stringify(decryptVaultRecord(envelope, principal)) !== JSON.stringify(record)) {
      throw new Error("An exception UI record did not round-trip through its encrypted envelope.");
    }
  }
  const envelopeText = JSON.stringify([agreementEnvelope, claimEnvelope, remediationEnvelope]);
  if ([payee.displayName, payee.recipientAddress, claimDraft.claimKind]
    .some((value) => envelopeText.includes(value))) {
    throw new Error("An exception UI envelope exposed a private form value.");
  }

  return artifactSchema.parse({
    schemaVersion: "payo.phase3.exception-ui-origin.v1",
    generatedAt: new Date().toISOString(),
    organizationId,
    runId,
    recipientAddress: payee.recipientAddress,
    formInputCommitments: {
      agreement: hashCanonicalJson({ domain: "PAYO_PHASE3_UI_FORM_V1", payeeId: payee.id, draft: agreementDraft }),
      claim: hashCanonicalJson({ domain: "PAYO_PHASE3_CLAIM_FORM_V1", agreementId: claimDraft.agreementId, runId, claimKind: claimDraft.claimKind }),
      remediation: hashCanonicalJson({ domain: "PAYO_PHASE3_REMEDIATION_FORM_V1", claimId: submittedClaim.id, amountAtomic: claimInput.shortfallAtomic }),
    },
    payee,
    agreementRecord,
    agreementEnvelope,
    claimDraft,
    claimEnvelope,
    submittedClaim,
    remediationDraft,
    remediationEnvelope,
    payrollRequest,
    checks: {
      teamProductionCommand: "storeEncryptedAgreementFromForm",
      claimProductionCommand: "createEncryptedWageClaimDraft",
      remediationProductionCommand: "createEncryptedRemediationDraft",
      encryptedRoundTrips: true,
      plaintextAbsentFromEnvelopes: true,
    },
  });
}

export async function writePhase3ExceptionUiFixture(): Promise<Phase3ExceptionUiFixture> {
  const fixture = await generatePhase3ExceptionUiFixture();
  await writeFile(artifactPath, `${JSON.stringify(fixture, null, 2)}\n`, { mode: 0o600 });
  return fixture;
}

export async function loadPhase3ExceptionUiFixture(): Promise<Phase3ExceptionUiFixture> {
  return artifactSchema.parse(JSON.parse(await readFile(artifactPath, "utf8")));
}
