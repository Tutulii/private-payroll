import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  encryptedVaultRecordSchema,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { fromBase64, stableJson, toBase64, toHex, utf8 } from "@/lib/crypto/encoding";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { atomicAmountSchema, payrollTokenSchema, proofPackageSchema } from "@/lib/domain/payroll";
import { createProofCommitter } from "@/lib/proof/commitments";

const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const PROOF_PACKAGE_ARCHIVE_FILES = new Set([
  "manifest.json",
  "journal.csv",
  "proof.json",
  "verification.json",
  "starknet-receipt.json",
  "disclosure.json",
  "line-opening.json",
]);
const MAX_PROOF_PACKAGE_ARCHIVE_FILES = 7;
const MAX_PROOF_PACKAGE_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PROOF_PACKAGE_EXPANDED_BYTES = 16 * 1024 * 1024;
const PROOF_COMMON_PUBLIC_INPUT_KEYS = [
  "chainId",
  "sealAddress",
  "proofVersion",
  "schemaVersion",
  "agreementRootHigh",
  "agreementRootLow",
  "manifestRootHigh",
  "manifestRootLow",
  "policyRootHigh",
  "policyRootLow",
  "fxRootHigh",
  "fxRootLow",
  "runNullifierHigh",
  "runNullifierLow",
  "validityStart",
  "validityExpiry",
] as const;

export function proofPackagePublicInputsHash(
  publicInputs: Record<string, string>,
): `0x${string}` | undefined {
  if (PROOF_COMMON_PUBLIC_INPUT_KEYS.some((key) => {
    const value = publicInputs[key];
    if (typeof value !== "string") return true;
    if (key === "chainId" || key === "sealAddress") return !/^0x[0-9a-f]+$/.test(value);
    return !/^(0|[1-9]\d*)$/.test(value);
  })) return undefined;
  const common = Object.fromEntries(
    PROOF_COMMON_PUBLIC_INPUT_KEYS.map((key) => [key, publicInputs[key]]),
  );
  return hashCanonicalJson([
    { ...common, shardIndex: "0" },
    { ...common, shardIndex: "1" },
  ]);
}

function sameInteger(left: string, right: string): boolean {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

export const disclosureFieldSchema = z.enum([
  "identity",
  "gross",
  "deductions",
  "net",
  "token",
  "schedule",
  "classification",
  "aggregate",
  "settlement",
  "exception",
]);

const journalEntrySchema = z.object({
  date: z.string().date(),
  accountCode: z.string().min(1).max(80),
  debitAtomic: atomicAmountSchema,
  creditAtomic: atomicAmountSchema,
  token: payrollTokenSchema,
  memo: z.string().max(240),
}).strict().refine(
  (entry) => (BigInt(entry.debitAtomic) === 0n) !== (BigInt(entry.creditAtomic) === 0n),
  "A journal line must contain either a debit or a credit.",
);

export const proofPackageGrantSchema = z.object({
  grantVersion: z.literal("payo-proof-package-grant-v1"),
  id: z.string().min(8).max(128),
  organizationId: z.string().min(8).max(128),
  runId: z.string().min(8).max(128),
  scope: z.enum(["worker", "employer", "auditor", "tax"]),
  granteePrincipalId: z.string().min(1).max(160),
  fieldScope: z.array(disclosureFieldSchema).min(1).max(10),
  recipientEncryptionKey: z.string().min(16),
  validAfter: z.string().datetime(),
  expiresAt: z.string().datetime(),
  revokedAt: z.string().datetime().optional(),
}).strict().superRefine((grant, context) => {
  if (new Date(grant.validAfter) >= new Date(grant.expiresAt)) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "Disclosure expiry must follow activation." });
  }
  if (new Set(grant.fieldScope).size !== grant.fieldScope.length) {
    context.addIssue({ code: "custom", path: ["fieldScope"], message: "Disclosure fields must be unique." });
  }
  if (grant.scope === "worker" && grant.fieldScope.includes("aggregate")) {
    context.addIssue({ code: "custom", path: ["fieldScope"], message: "A worker package cannot reveal employer aggregates." });
  }
  if (grant.scope === "tax" && grant.fieldScope.includes("classification")) {
    context.addIssue({ code: "custom", path: ["fieldScope"], message: "A tax package cannot reveal classification facts without a separate auditor grant." });
  }
});
export type ProofPackageGrant = z.infer<typeof proofPackageGrantSchema>;

const proofPackageContentNameSchema = z.enum([
  "journal.csv",
  "proof.json",
  "verification.json",
  "starknet-receipt.json",
  "disclosure.json",
  "line-opening.json",
]);

const proofPackageManifestSchema = z.object({
  packageVersion: z.literal("payo-recipient-proof-package-v1"),
  grant: proofPackageGrantSchema,
  createdAt: z.string().datetime(),
  content: z.array(z.object({
    name: proofPackageContentNameSchema,
    sha256: commitmentSchema,
  }).strict()).min(5).max(6),
}).strict().superRefine((manifest, context) => {
  const names = manifest.content.map(({ name }) => name);
  if (new Set(names).size !== names.length) {
    context.addIssue({ code: "custom", path: ["content"], message: "Proof package manifest filenames must be unique." });
  }
  for (const required of ["journal.csv", "proof.json", "verification.json", "starknet-receipt.json", "disclosure.json"] as const) {
    if (!names.includes(required)) {
      context.addIssue({ code: "custom", path: ["content"], message: `Proof package manifest is missing ${required}.` });
    }
  }
  if (manifest.grant.scope === "worker" && !names.includes("line-opening.json")) {
    context.addIssue({ code: "custom", path: ["content"], message: "Worker manifest is missing its line opening." });
  }
  if (manifest.grant.scope !== "worker" && names.includes("line-opening.json")) {
    context.addIssue({ code: "custom", path: ["content"], message: "A non-worker manifest cannot disclose a line opening." });
  }
});

export const proofLineOpeningSchema = z.object({
  manifestRoot: commitmentSchema,
  lineCommitment: commitmentSchema,
  lineIndex: z.number().int().min(0).max(49),
  siblings: z.array(commitmentSchema).length(6),
  pathBits: z.array(z.boolean()).length(6),
}).strict();
export type ProofLineOpening = z.infer<typeof proofLineOpeningSchema>;

export const proofPackageVerificationSchema = z.object({
  verified: z.literal(true),
  verificationState: z.literal("onchain_verified"),
  verifierAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
  proofVersion: z.string().regex(/^[1-9]\d{0,9}$/),
  publicInputsHash: commitmentSchema,
  verificationTransactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
  checkedAt: z.string().datetime(),
}).strict();

export const proofPackageStarknetReceiptSchema = z.object({
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
}).passthrough();

export const recipientProofPackagePayloadSchema = z.object({
  packageVersion: z.literal("payo-recipient-proof-package-v1"),
  grant: proofPackageGrantSchema,
  journal: z.array(journalEntrySchema).min(2),
  proofPackage: proofPackageSchema,
  verification: proofPackageVerificationSchema,
  starknetReceipt: proofPackageStarknetReceiptSchema,
  disclosedFields: z.partialRecord(disclosureFieldSchema, z.unknown()),
  lineOpening: proofLineOpeningSchema.optional(),
}).strict().superRefine((payload, context) => {
  if (
    payload.proofPackage.organizationId !== payload.grant.organizationId
    || payload.proofPackage.runId !== payload.grant.runId
  ) {
    context.addIssue({ code: "custom", path: ["proofPackage"], message: "Proof package does not match its disclosure grant." });
  }
  const disclosed = Object.keys(payload.disclosedFields);
  if (disclosed.some((field) => !payload.grant.fieldScope.includes(field as never))) {
    context.addIssue({ code: "custom", path: ["disclosedFields"], message: "Package contains a field outside its grant." });
  }
  if (payload.grant.fieldScope.some((field) => !disclosed.includes(field))) {
    context.addIssue({ code: "custom", path: ["disclosedFields"], message: "Package omits a field named by its grant." });
  }
  if (payload.grant.scope === "worker" && !payload.lineOpening) {
    context.addIssue({ code: "custom", path: ["lineOpening"], message: "A worker package requires one manifest line opening." });
  }
  if (payload.grant.scope !== "worker" && payload.lineOpening) {
    context.addIssue({ code: "custom", path: ["lineOpening"], message: "A non-worker package cannot disclose a manifest line opening." });
  }
  if (!sameInteger(payload.proofPackage.verifier.contractAddress, payload.verification.verifierAddress)) {
    context.addIssue({ code: "custom", path: ["verification", "verifierAddress"], message: "Verification evidence names a different verifier contract." });
  }
  if (payload.proofPackage.proofVersion !== payload.verification.proofVersion) {
    context.addIssue({ code: "custom", path: ["verification", "proofVersion"], message: "Verification evidence names a different proof version." });
  }
  const expectedPublicInputsHash = proofPackagePublicInputsHash(payload.proofPackage.publicInputs);
  if (expectedPublicInputsHash) {
    const { publicInputs, verifier, proofVersion } = payload.proofPackage;
    if (!sameInteger(publicInputs.chainId, verifier.chainId)) {
      context.addIssue({ code: "custom", path: ["proofPackage", "verifier", "chainId"], message: "Proof public inputs name a different Starknet chain." });
    }
    if (!sameInteger(publicInputs.sealAddress, verifier.contractAddress)) {
      context.addIssue({ code: "custom", path: ["proofPackage", "verifier", "contractAddress"], message: "Proof public inputs name a different PAYO seal contract." });
    }
    if (publicInputs.proofVersion !== proofVersion) {
      context.addIssue({ code: "custom", path: ["proofPackage", "proofVersion"], message: "Proof public inputs name a different proof version." });
    }
  }
  if (
    expectedPublicInputsHash
    && expectedPublicInputsHash.toLowerCase() !== payload.verification.publicInputsHash.toLowerCase()
  ) {
    context.addIssue({ code: "custom", path: ["verification", "publicInputsHash"], message: "Verification evidence is not bound to the packaged proof public inputs." });
  }
  if (
    payload.proofPackage.transactionHash
    && !sameInteger(payload.proofPackage.transactionHash, payload.starknetReceipt.transactionHash)
  ) {
    context.addIssue({ code: "custom", path: ["starknetReceipt", "transactionHash"], message: "Settlement receipt does not match the proof package transaction." });
  }
  const totals = new Map<string, { debit: bigint; credit: bigint }>();
  for (const entry of payload.journal) {
    const total = totals.get(entry.token) ?? { debit: 0n, credit: 0n };
    total.debit += BigInt(entry.debitAtomic);
    total.credit += BigInt(entry.creditAtomic);
    totals.set(entry.token, total);
  }
  for (const [token, total] of totals) {
    if (total.debit !== total.credit) {
      context.addIssue({ code: "custom", path: ["journal"], message: `${token} journal is not balanced.` });
    }
  }
});
export type RecipientProofPackagePayload = z.infer<typeof recipientProofPackagePayloadSchema>;

export const encryptedProofPackageSchema = z.object({
  packageVersion: z.literal("payo-encrypted-proof-package-v1"),
  grantId: z.string().min(8).max(128),
  packageCommitment: commitmentSchema,
  envelope: encryptedVaultRecordSchema,
}).strict();
export type EncryptedRecipientProofPackage = z.infer<typeof encryptedProofPackageSchema>;

export type RecipientProofPackageInspection = {
  scope: ProofPackageGrant["scope"];
  fieldScope: ProofPackageGrant["fieldScope"];
  fileNames: string[];
  packageCommitment: string;
  manifestCreatedAt: string;
  grant: ProofPackageGrant;
  journal: RecipientProofPackagePayload["journal"];
  proofPackage: RecipientProofPackagePayload["proofPackage"];
  verification: RecipientProofPackagePayload["verification"];
  starknetReceipt: RecipientProofPackagePayload["starknetReceipt"];
  disclosedFields: RecipientProofPackagePayload["disclosedFields"];
  lineOpening?: ProofLineOpening;
  publicInputsBinding: "verified" | "legacy";
};

function csvCell(value: string): string {
  const safe = /^[=+\-@]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

function journalCsv(journal: RecipientProofPackagePayload["journal"]): string {
  return [
    "date,account_code,debit_atomic,credit_atomic,token,memo",
    ...journal.map((entry) => [
      entry.date,
      entry.accountCode,
      entry.debitAtomic,
      entry.creditAtomic,
      entry.token,
      entry.memo,
    ].map(csvCell).join(",")),
  ].join("\n");
}

function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (quoted) {
      if (char === '"' && input[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else if (char !== "\r") cell += char;
  }
  if (quoted) throw new Error("The proof package journal contains an unterminated CSV field.");
  row.push(cell);
  rows.push(row);
  return rows;
}

function parseJournal(input: string) {
  const rows = parseCsv(input);
  if (rows[0]?.join(",") !== "date,account_code,debit_atomic,credit_atomic,token,memo") {
    throw new Error("The proof package journal header is invalid.");
  }
  return rows.slice(1).filter((row) => row.some(Boolean)).map((row) => {
    if (row.length !== 6) throw new Error("The proof package journal row is malformed.");
    return journalEntrySchema.parse({
      date: row[0], accountCode: row[1], debitAtomic: row[2], creditAtomic: row[3], token: row[4], memo: row[5],
    });
  });
}

function unzipProofPackageArchive(archive: Uint8Array): Record<string, Uint8Array> {
  let count = 0;
  let expandedBytes = 0;
  const names = new Set<string>();
  try {
    return unzipSync(archive, {
      filter(file) {
        count += 1;
        if (count > MAX_PROOF_PACKAGE_ARCHIVE_FILES) {
          throw new Error("The proof package archive contains too many files.");
        }
        if (!PROOF_PACKAGE_ARCHIVE_FILES.has(file.name) || names.has(file.name)) {
          throw new Error("The proof package archive contains an unsupported or duplicate file.");
        }
        if (file.originalSize > MAX_PROOF_PACKAGE_FILE_BYTES) {
          throw new Error("The proof package archive contains a file that exceeds the safe size limit.");
        }
        names.add(file.name);
        expandedBytes += file.originalSize;
        if (expandedBytes > MAX_PROOF_PACKAGE_EXPANDED_BYTES) {
          throw new Error("The proof package archive exceeds the safe expansion limit.");
        }
        return true;
      },
    });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("The proof package archive")) throw error;
    throw new Error("The proof package archive is invalid or unreadable.");
  }
}

function assertGrantActive(grant: ProofPackageGrant, at: Date): void {
  const timestamp = at.getTime();
  if (grant.revokedAt && timestamp >= new Date(grant.revokedAt).getTime()) {
    throw new Error("The disclosure grant is revoked.");
  }
  if (timestamp < new Date(grant.validAfter).getTime()) throw new Error("The disclosure grant is not active yet.");
  if (timestamp > new Date(grant.expiresAt).getTime()) throw new Error("The disclosure grant is expired.");
}

function packageFiles(payload: RecipientProofPackagePayload): Record<string, string> {
  const files: Record<string, string> = {
    "journal.csv": journalCsv(payload.journal),
    "proof.json": `${stableJson(payload.proofPackage)}\n`,
    "verification.json": `${stableJson(payload.verification)}\n`,
    "starknet-receipt.json": `${stableJson(payload.starknetReceipt)}\n`,
    "disclosure.json": `${stableJson(payload.disclosedFields)}\n`,
  };
  if (payload.lineOpening) files["line-opening.json"] = `${stableJson(payload.lineOpening)}\n`;
  const manifest = {
    packageVersion: payload.packageVersion,
    grant: payload.grant,
    createdAt: payload.verification.checkedAt,
    content: Object.keys(files).sort().map((name) => ({
      name,
      sha256: toHex(sha256(utf8(files[name]))),
    })),
  };
  files["manifest.json"] = `${stableJson(manifest)}\n`;
  return files;
}

export function createRecipientEncryptedProofPackage(input: {
  payload: RecipientProofPackagePayload;
  recipient: VaultPrincipal;
  at?: Date;
}): EncryptedRecipientProofPackage {
  const payload = recipientProofPackagePayloadSchema.parse(input.payload);
  const at = input.at ?? new Date();
  assertGrantActive(payload.grant, at);
  if (
    input.recipient.principalId !== payload.grant.granteePrincipalId
    || input.recipient.publicKey !== payload.grant.recipientEncryptionKey
  ) throw new Error("The encryption recipient does not match the disclosure grant.");
  const files = packageFiles(payload);
  const archive = zipSync(
    Object.fromEntries(Object.entries(files).map(([name, contents]) => [name, strToU8(contents)])),
    { level: 6 },
  );
  const packageCommitment = toHex(sha256(archive));
  const envelope = encryptVaultRecord(
    { archiveBase64: toBase64(archive), packageCommitment },
    {
      schemaVersion: 1,
      organizationId: payload.grant.organizationId,
      recordType: "proof-package",
      recordId: payload.grant.id,
      revision: 1,
    },
    [input.recipient],
  );
  return encryptedProofPackageSchema.parse({
    packageVersion: "payo-encrypted-proof-package-v1",
    grantId: payload.grant.id,
    packageCommitment,
    envelope,
  });
}

export async function inspectRecipientProofPackageOffline(input: {
  encryptedPackage: EncryptedRecipientProofPackage;
  recipient: VaultPrincipalKeyPair;
  currentGrant: ProofPackageGrant;
  at?: Date;
}): Promise<RecipientProofPackageInspection> {
  const encrypted = encryptedProofPackageSchema.parse(input.encryptedPackage);
  const grant = proofPackageGrantSchema.parse(input.currentGrant);
  const at = input.at ?? new Date();
  assertGrantActive(grant, at);
  if (
    encrypted.grantId !== grant.id
    || encrypted.envelope.aad.recordId !== grant.id
    || encrypted.envelope.aad.organizationId !== grant.organizationId
    || encrypted.envelope.aad.recordType !== "proof-package"
    || encrypted.envelope.aad.revision !== 1
  ) {
    throw new Error("The encrypted package does not match the current disclosure grant.");
  }
  if (input.recipient.principalId !== grant.granteePrincipalId) {
    throw new Error("The recipient does not match the disclosure grant.");
  }
  if (input.recipient.publicKey !== grant.recipientEncryptionKey) {
    throw new Error("The recipient public key does not match the disclosure grant.");
  }
  let decrypted: { archiveBase64: string; packageCommitment: string };
  try {
    decrypted = decryptVaultRecord<{ archiveBase64: string; packageCommitment: string }>(
      encrypted.envelope,
      input.recipient,
    );
  } catch {
    throw new Error("The encrypted proof package ciphertext is tampered or unreadable.");
  }
  const archive = fromBase64(decrypted.archiveBase64);
  const commitment = toHex(sha256(archive));
  if (commitment !== encrypted.packageCommitment || commitment !== decrypted.packageCommitment) {
    throw new Error("The encrypted proof package commitment is invalid.");
  }
  const files = unzipProofPackageArchive(archive);
  const manifestBytes = files["manifest.json"];
  if (!manifestBytes) throw new Error("The proof package manifest is missing.");
  const manifest = proofPackageManifestSchema.parse(JSON.parse(strFromU8(manifestBytes)));
  if (stableJson(manifest.grant) !== stableJson(grant)) {
    throw new Error("The packaged disclosure grant differs from the current grant.");
  }
  const allowedFiles = new Set(["manifest.json", ...manifest.content.map(({ name }) => name)]);
  for (const name of Object.keys(files)) {
    if (!allowedFiles.has(name)) throw new Error(`The proof package contains an undeclared file: ${name}.`);
  }
  for (const entry of manifest.content) {
    const value = files[entry.name];
    if (!value || toHex(sha256(value)) !== entry.sha256) {
      throw new Error(`The proof package file failed integrity verification: ${entry.name}.`);
    }
  }
  const journal = parseJournal(strFromU8(files["journal.csv"]));
  const proofPackage = proofPackageSchema.parse(JSON.parse(strFromU8(files["proof.json"])));
  const verification = proofPackageVerificationSchema.parse(JSON.parse(strFromU8(files["verification.json"])));
  const disclosedFields = z.partialRecord(disclosureFieldSchema, z.unknown()).parse(
    JSON.parse(strFromU8(files["disclosure.json"])),
  );
  const starknetReceipt = proofPackageStarknetReceiptSchema.parse(
    JSON.parse(strFromU8(files["starknet-receipt.json"])),
  );
  const lineOpening = files["line-opening.json"]
    ? proofLineOpeningSchema.parse(JSON.parse(strFromU8(files["line-opening.json"])))
    : undefined;
  recipientProofPackagePayloadSchema.parse({
    packageVersion: "payo-recipient-proof-package-v1",
    grant,
    journal,
    proofPackage,
    verification,
    starknetReceipt,
    disclosedFields,
    ...(lineOpening ? { lineOpening } : {}),
  });
  if (lineOpening) {
    const committer = await createProofCommitter();
    let current = lineOpening.lineCommitment as `0x${string}`;
    for (const [level, sibling] of lineOpening.siblings.entries()) {
      current = lineOpening.pathBits[level]
        ? committer.proofMerkleNode(sibling, current)
        : committer.proofMerkleNode(current, sibling);
    }
    if (current.toLowerCase() !== lineOpening.manifestRoot.toLowerCase()) {
      throw new Error("The worker line opening does not reconstruct the proved manifest root.");
    }
    const publicManifestRoot = proofPackage.publicInputs.manifestRoot;
    if (typeof publicManifestRoot !== "string" || BigInt(publicManifestRoot) !== BigInt(lineOpening.manifestRoot)) {
      throw new Error("The worker line opening is not bound to the proof package manifest root.");
    }
  }
  return {
    scope: grant.scope,
    fieldScope: grant.fieldScope,
    fileNames: Object.keys(files).sort(),
    packageCommitment: commitment,
    manifestCreatedAt: manifest.createdAt,
    grant,
    journal,
    proofPackage,
    verification,
    starknetReceipt,
    disclosedFields,
    ...(lineOpening ? { lineOpening } : {}),
    publicInputsBinding: proofPackagePublicInputsHash(proofPackage.publicInputs) ? "verified" : "legacy",
  };
}

export async function verifyRecipientProofPackageOffline(input: {
  encryptedPackage: EncryptedRecipientProofPackage;
  recipient: VaultPrincipalKeyPair;
  currentGrant: ProofPackageGrant;
  at?: Date;
}): Promise<{ scope: ProofPackageGrant["scope"]; fieldScope: ProofPackageGrant["fieldScope"]; fileNames: string[] }> {
  const inspection = await inspectRecipientProofPackageOffline(input);
  return {
    scope: inspection.scope,
    fieldScope: inspection.fieldScope,
    fileNames: inspection.fileNames,
  };
}
