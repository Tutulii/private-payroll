import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  encryptedVaultRecordSchema,
  type EncryptedVaultRecord,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import {
  assertReportingIdentityKeyPair,
  parsePayoReportingIdentity,
  payoReportingIdentitySchema,
  type PayoReportingIdentity,
} from "@/lib/crypto/reporting-identity";
import { commitmentSchema, generateUuidV7, uuidV7Schema } from "@/lib/domain/records";
import {
  createWorkerIncomeStatement,
  verifyWorkerIncomeStatement,
  workerIncomeStatementSchema,
  type CompletePayrollBookReport,
  type TrustedPayrollBookSnapshot,
} from "./payroll-book-report";

const workerStatementCoreSchema = workerIncomeStatementSchema.pick({
  organizationId: true,
  recipientAddress: true,
  recipientReference: true,
  checkpoint: true,
  opaqueBookEntries: true,
  lines: true,
});

export const workerStatementSourceSchema = z.object({
  sourceVersion: z.literal("payo-worker-statement-source-v1"),
  sourceId: uuidV7Schema,
  recipientIdentity: payoReportingIdentitySchema,
  statement: workerStatementCoreSchema,
  createdAt: z.string().datetime(),
}).strict();
export type WorkerStatementSource = z.infer<typeof workerStatementSourceSchema>;

const workerStatementSourceRecordSchema = z.object({
  schemaVersion: z.literal(1),
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  revision: z.literal(1),
  source: workerStatementSourceSchema,
  sourceCommitment: commitmentSchema,
  createdAt: z.string().datetime(),
}).strict();

export const encryptedWorkerStatementSourceSchema = z.object({
  packageVersion: z.literal("payo-encrypted-worker-statement-source-v1"),
  sourceId: uuidV7Schema,
  organizationId: uuidV7Schema,
  recipientIdentityFingerprint: commitmentSchema,
  sourceCommitment: commitmentSchema,
  envelope: encryptedVaultRecordSchema,
}).strict();
export type EncryptedWorkerStatementSource = z.infer<typeof encryptedWorkerStatementSourceSchema>;

function sameFelt(left: string, right: string): boolean {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

function sourceCommitment(source: WorkerStatementSource): `0x${string}` {
  return hashCanonicalJson({ domain: "PAYO_WORKER_STATEMENT_SOURCE_V1", source });
}

/**
 * Extracts a recipient-only source after the complete employer book has passed
 * verification, then encrypts it solely to that worker's reporting identity.
 * The worker—not the payer—chooses the final statement ID and generation time.
 */
export async function createEncryptedWorkerStatementSource(input: {
  completeReport: CompletePayrollBookReport;
  trustedSnapshot: TrustedPayrollBookSnapshot;
  recipientAddress: string;
  recipientReference: string;
  recipientIdentity: PayoReportingIdentity;
  sourceId?: string;
  now?: Date;
}): Promise<EncryptedWorkerStatementSource> {
  const recipientIdentity = parsePayoReportingIdentity(input.recipientIdentity);
  if (!sameFelt(recipientIdentity.context.recipientAddress, input.recipientAddress)) {
    throw new Error("The reporting identity is bound to another STRK20 recipient.");
  }
  const now = input.now ?? new Date();
  const sourceId = uuidV7Schema.parse(input.sourceId ?? generateUuidV7(now.getTime()));
  const provisional = await createWorkerIncomeStatement({
    reportId: generateUuidV7(now.getTime() + 1),
    completeReport: input.completeReport,
    trustedSnapshot: input.trustedSnapshot,
    recipientAddress: input.recipientAddress,
    recipientReference: input.recipientReference,
    generatedAt: now,
  });
  const source = workerStatementSourceSchema.parse({
    sourceVersion: "payo-worker-statement-source-v1",
    sourceId,
    recipientIdentity,
    statement: {
      organizationId: provisional.organizationId,
      recipientAddress: provisional.recipientAddress,
      recipientReference: provisional.recipientReference,
      checkpoint: provisional.checkpoint,
      opaqueBookEntries: provisional.opaqueBookEntries,
      lines: provisional.lines,
    },
    createdAt: now.toISOString(),
  });
  const commitment = sourceCommitment(source);
  const record = workerStatementSourceRecordSchema.parse({
    schemaVersion: 1,
    id: sourceId,
    organizationId: source.statement.organizationId,
    revision: 1,
    source,
    sourceCommitment: commitment,
    createdAt: now.toISOString(),
  });
  const envelope = encryptVaultRecord(record, {
    schemaVersion: 1,
    organizationId: source.statement.organizationId,
    recordType: "worker-statement-source",
    recordId: sourceId,
    revision: 1,
  }, [recipientIdentity]);
  return encryptedWorkerStatementSourceSchema.parse({
    packageVersion: "payo-encrypted-worker-statement-source-v1",
    sourceId,
    organizationId: source.statement.organizationId,
    recipientIdentityFingerprint: recipientIdentity.fingerprint,
    sourceCommitment: commitment,
    envelope,
  });
}

/** Generates and verifies the final report locally using the worker-held key. */
export async function generateWorkerIncomeStatementFromSource(input: {
  encryptedSource: EncryptedWorkerStatementSource;
  recipient: VaultPrincipalKeyPair;
  trustedSnapshot: TrustedPayrollBookSnapshot;
  reportId?: string;
  now?: Date;
}) {
  const opened = openEncryptedWorkerStatementSource({
    encryptedSource: input.encryptedSource,
    recipient: input.recipient,
  });
  const encryptedSource = opened.encryptedSource;
  const record = opened.record;
  const recipientIdentity = opened.recipientIdentity;

  const now = input.now ?? new Date();
  const statement = workerIncomeStatementSchema.parse({
    reportVersion: "payo-private-payroll-report-v1",
    reportType: "worker_income_statement",
    reportId: input.reportId ?? generateUuidV7(now.getTime()),
    organizationId: record.source.statement.organizationId,
    scope: "worker",
    recipientAddress: record.source.statement.recipientAddress,
    recipientReference: record.source.statement.recipientReference,
    checkpoint: record.source.statement.checkpoint,
    opaqueBookEntries: record.source.statement.opaqueBookEntries,
    lines: record.source.statement.lines,
    coverage: "worker-lines-included-in-complete-onchain-book",
    generatedAt: now.toISOString(),
  });
  const verification = await verifyWorkerIncomeStatement({
    statement,
    trustedSnapshot: input.trustedSnapshot,
  });
  return { statement, verification, sourceCommitment: encryptedSource.sourceCommitment, recipientIdentity };
}

/** Opens only the recipient-encrypted source; live checkpoint verification follows separately. */
export function openEncryptedWorkerStatementSource(input: {
  encryptedSource: EncryptedWorkerStatementSource;
  recipient: VaultPrincipalKeyPair;
}) {
  const encryptedSource = encryptedWorkerStatementSourceSchema.parse(input.encryptedSource);
  if (
    encryptedSource.envelope.aad.organizationId !== encryptedSource.organizationId
    || encryptedSource.envelope.aad.recordType !== "worker-statement-source"
    || encryptedSource.envelope.aad.recordId !== encryptedSource.sourceId
    || encryptedSource.envelope.aad.revision !== 1
  ) throw new Error("The encrypted worker source has invalid storage identity.");

  let record: z.infer<typeof workerStatementSourceRecordSchema>;
  try {
    record = workerStatementSourceRecordSchema.parse(
      decryptVaultRecord(
        encryptedSource.envelope as EncryptedVaultRecord,
        input.recipient,
      ),
    );
  } catch {
    throw new Error("The worker statement source is unauthorized, tampered, or unreadable.");
  }
  const recipientIdentity = parsePayoReportingIdentity(record.source.recipientIdentity);
  assertReportingIdentityKeyPair({ identity: recipientIdentity, principal: input.recipient });
  if (
    record.id !== encryptedSource.sourceId
    || record.organizationId !== encryptedSource.organizationId
    || record.source.sourceId !== encryptedSource.sourceId
    || record.source.statement.organizationId !== encryptedSource.organizationId
    || record.sourceCommitment !== encryptedSource.sourceCommitment
    || sourceCommitment(record.source) !== encryptedSource.sourceCommitment
    || recipientIdentity.fingerprint !== encryptedSource.recipientIdentityFingerprint
    || !sameFelt(recipientIdentity.context.recipientAddress, record.source.statement.recipientAddress)
  ) throw new Error("The worker statement source commitment or recipient binding is invalid.");
  return { encryptedSource, record, recipientIdentity };
}

export function workerStatementSourceFilename(input: {
  encryptedSource: EncryptedWorkerStatementSource;
  recipientReference?: string;
  year?: number;
}): string {
  const worker = input.recipientReference
    ?.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);
  const year = input.year ? `-${input.year}` : "";
  return `payo-worker-statement-source${worker ? `-${worker}` : ""}${year}-${input.encryptedSource.sourceId.slice(0, 8)}.json`;
}
