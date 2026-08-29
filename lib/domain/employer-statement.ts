import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import {
  payrollStatementCommitmentV2,
  payrollStatementV2Schema,
} from "./exception-protocol";
import { fxSnapshotSchema } from "./fx";
import { atomicAmountSchema } from "./payroll";
import { commitmentSchema, starknetAddressSchema, uuidV7Schema } from "./records";

const decimalSchema = z.string().regex(/^(0|[1-9][0-9]*)$/);
const merkleMembershipSchema = z.object({
  siblings: z.array(decimalSchema).length(6),
  pathBits: z.array(z.boolean()).length(6),
}).strict();

export const payrollStatementEvidencePrivateSchema = z.object({
  format: z.literal("payo-payroll-statement-evidence-v1"),
  schemaVersion: z.literal(1),
  id: uuidV7Schema,
  statementId: uuidV7Schema,
  claimAccessGrantId: uuidV7Schema,
  snapshotPlanId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  agreementId: z.string().min(1).max(160),
  statement: payrollStatementV2Schema.extend({
    source: z.literal("employer_statement"),
  }).strict(),
  statementCommitment: commitmentSchema,
  target: z.discriminatedUnion("kind", [
    z.object({
      kind: z.literal("empty"),
      manifestRoot: commitmentSchema,
      manifestMembership: merkleMembershipSchema,
    }).strict(),
    z.object({
      kind: z.literal("line"),
      deductionsAtomic: z.array(atomicAmountSchema).max(8),
      lineSalt: commitmentSchema,
      classificationTreatment: z.union([z.literal(1), z.literal(2)]),
      finalIncludedMask: z.number().int().min(0).max(31),
      referenceValueAtomic: atomicAmountSchema,
      manifestRoot: commitmentSchema,
      manifestMembership: merkleMembershipSchema,
    }).strict(),
  ]),
  fxSnapshots: z.array(fxSnapshotSchema).max(2),
  selectedFxIndex: z.number().int().min(0).max(1).optional(),
  issuerPrincipal: z.object({
    principalId: z.string().min(1).max(160),
    publicKey: z.string().min(16).max(256),
  }).strict(),
  createdAt: z.string().datetime(),
}).strict().superRefine((evidence, context) => {
  if (payrollStatementCommitmentV2(evidence.statement) !== evidence.statementCommitment) {
    context.addIssue({
      code: "custom",
      path: ["statementCommitment"],
      message: "Employer evidence does not match its immutable statement commitment.",
    });
  }
  if (BigInt(evidence.target.manifestRoot) !== BigInt(evidence.statement.manifestRoot)) {
    context.addIssue({
      code: "custom",
      path: ["target", "manifestRoot"],
      message: "Employer evidence manifest differs from its registered statement.",
    });
  }
  if (evidence.fxSnapshots.length === 0 && BigInt(evidence.statement.fxRoot) !== 0n) {
    context.addIssue({
      code: "custom",
      path: ["fxSnapshots"],
      message: "A non-zero statement FX root requires its encrypted catalog evidence.",
    });
  }
  if (evidence.selectedFxIndex !== undefined && evidence.selectedFxIndex >= evidence.fxSnapshots.length) {
    context.addIssue({
      code: "custom",
      path: ["selectedFxIndex"],
      message: "The selected statement FX observation is unavailable.",
    });
  }
});

export type PayrollStatementEvidencePrivate = z.infer<
  typeof payrollStatementEvidencePrivateSchema
>;

export const employerStatementPrivateSchema = z.object({
  format: z.literal("payo-employer-statement-v2"),
  schemaVersion: z.literal(2),
  id: uuidV7Schema,
  snapshotPlanId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  ownerAddress: starknetAddressSchema,
  statement: payrollStatementV2Schema.extend({
    source: z.literal("employer_statement"),
  }).strict(),
  statementCommitment: commitmentSchema,
  evidenceGrantIds: z.array(uuidV7Schema).min(1).max(50),
  createdAt: z.string().datetime(),
}).strict().superRefine((statement, context) => {
  if (payrollStatementCommitmentV2(statement.statement) !== statement.statementCommitment) {
    context.addIssue({
      code: "custom",
      path: ["statementCommitment"],
      message: "Employer statement commitment does not match its immutable fields.",
    });
  }
  if (new Set(statement.evidenceGrantIds).size !== statement.evidenceGrantIds.length) {
    context.addIssue({
      code: "custom",
      path: ["evidenceGrantIds"],
      message: "Employer statement evidence grants must be unique.",
    });
  }
});

export type EmployerStatementPrivate = z.infer<typeof employerStatementPrivateSchema>;

export const employerStatementCreateSchema = z.object({
  id: uuidV7Schema,
  snapshotPlanId: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  revision: z.literal(1),
  ownerAddress: starknetAddressSchema,
  statement: payrollStatementV2Schema.extend({
    source: z.literal("employer_statement"),
  }).strict(),
  statementCommitment: commitmentSchema,
  evidenceGrants: z.array(z.object({
    id: uuidV7Schema,
    claimAccessGrantId: uuidV7Schema,
    claimantPrincipalId: z.string().min(1).max(160),
    envelope: encryptedVaultRecordSchema,
  }).strict()).min(1).max(50),
  envelope: encryptedVaultRecordSchema,
}).strict().superRefine((statement, context) => {
  if (payrollStatementCommitmentV2(statement.statement) !== statement.statementCommitment) {
    context.addIssue({ code: "custom", path: ["statementCommitment"], message: "Statement commitment mismatch." });
  }
  if (new Set(statement.evidenceGrants.map(({ id }) => id)).size !== statement.evidenceGrants.length) {
    context.addIssue({ code: "custom", path: ["evidenceGrants"], message: "Evidence grant IDs must be unique." });
  }
  if (
    new Set(statement.evidenceGrants.map(({ claimAccessGrantId }) => claimAccessGrantId)).size
      !== statement.evidenceGrants.length
  ) {
    context.addIssue({
      code: "custom",
      path: ["evidenceGrants"],
      message: "Each worker claim-access grant can receive only one statement-evidence packet.",
    });
  }
  if (
    statement.envelope.aad.organizationId !== statement.organizationId
    || statement.envelope.aad.recordType !== "employer-statement-v2"
    || statement.envelope.aad.recordId !== statement.id
    || statement.envelope.aad.revision !== statement.revision
  ) {
    context.addIssue({ code: "custom", path: ["envelope"], message: "Employer statement envelope AAD is invalid." });
  }
  for (const grant of statement.evidenceGrants) {
    if (
      grant.envelope.aad.organizationId !== statement.organizationId
      || grant.envelope.aad.recordType !== "payroll-statement-evidence"
      || grant.envelope.aad.recordId !== grant.id
      || grant.envelope.aad.revision !== 1
      || grant.envelope.wrappedKeys.length !== 1
      || grant.envelope.wrappedKeys[0]?.principalId !== grant.claimantPrincipalId
    ) {
      context.addIssue({
        code: "custom",
        path: ["evidenceGrants"],
        message: "Each statement evidence packet must be encrypted only to its declared worker.",
      });
      break;
    }
  }
});

export type EmployerStatementCreate = z.infer<typeof employerStatementCreateSchema>;

export const employerStatementSubmissionSchema = z.object({
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
}).strict();

export type EmployerStatementState = "prepared" | "submitted" | "registered" | "failed";

export type EmployerStatementSummary = {
  id: string;
  snapshotPlanId: string;
  organizationId: string;
  runId: string;
  ownerAddress: string;
  statementFact: string;
  manifestRoot: string;
  fxRoot: string;
  availabilityCommitment: string;
  observedAt: string;
  source: "employer_statement";
  state: EmployerStatementState;
  registrationTransactionHash: string | null;
  registeredAt: string | null;
  createdAt: string;
  updatedAt: string;
  envelope?: unknown;
};

export type PayrollStatementEvidenceGrantSummary = {
  id: string;
  statementId: string;
  claimAccessGrantId: string;
  claimantPrincipalId: string;
  revokedAt: string | null;
  statement: Omit<EmployerStatementSummary, "envelope">;
  envelope: z.infer<typeof encryptedVaultRecordSchema>;
};
