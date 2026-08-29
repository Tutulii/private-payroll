import { z } from "zod";
import { x25519 } from "@noble/curves/ed25519.js";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { fromBase64, stableJson } from "@/lib/crypto/encoding";
import type { VaultPrincipal, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  encryptedProofPackageSchema,
  inspectRecipientProofPackageOffline,
  proofPackageGrantSchema,
  type ProofPackageGrant,
  type RecipientProofPackageInspection,
} from "@/lib/disclosure/proof-package";
import { atomicAmountSchema, payrollTokenSchema } from "@/lib/domain/payroll";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";
import { deriveClaimCapabilitySecret } from "@/lib/crypto/claim-capability";
import { formatTokenAmount, PAYROLL_TOKENS, type PayrollTokenSymbol } from "@/lib/starknet/tokens";

const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);

export const payoProofPackageExportSchema = z.object({
  format: z.literal("payo-encrypted-proof-package-v1"),
  organizationId: z.string().min(8).max(128),
  runId: z.string().min(8).max(128),
  scope: z.enum(["worker", "employer", "auditor", "tax"]),
  grant: proofPackageGrantSchema,
  encryptedPackage: encryptedProofPackageSchema,
}).strict().superRefine((file, context) => {
  if (file.organizationId !== file.grant.organizationId) {
    context.addIssue({ code: "custom", path: ["organizationId"], message: "Export organization does not match its disclosure grant." });
  }
  if (file.runId !== file.grant.runId) {
    context.addIssue({ code: "custom", path: ["runId"], message: "Export payday does not match its disclosure grant." });
  }
  if (file.scope !== file.grant.scope) {
    context.addIssue({ code: "custom", path: ["scope"], message: "Export scope does not match its disclosure grant." });
  }
  if (file.encryptedPackage.grantId !== file.grant.id) {
    context.addIssue({ code: "custom", path: ["encryptedPackage", "grantId"], message: "Encrypted package does not match its disclosure grant." });
  }
});

export type PayoProofPackageExport = z.infer<typeof payoProofPackageExportSchema>;

const payoPublicIdentityV1Schema = z.object({
  format: z.literal("payo-public-identity-v1"),
  principalId: z.string().min(1).max(160),
  publicKey: z.string().min(16).max(160),
  fingerprint: commitmentSchema,
  createdAt: z.string().datetime(),
}).strict();

const payoPublicIdentityV2Schema = z.object({
  format: z.literal("payo-public-identity-v2"),
  principalId: z.string().min(1).max(160),
  publicKey: z.string().min(16).max(160),
  claimCapabilityCommitment: commitmentSchema,
  fingerprint: commitmentSchema,
  createdAt: z.string().datetime(),
}).strict();

export const payoPublicIdentitySchema = z.union([
  payoPublicIdentityV2Schema,
  payoPublicIdentityV1Schema,
]);

export type PayoPublicIdentity = z.infer<typeof payoPublicIdentitySchema>;

export type ProofPackageWorkflow = "payroll" | "wage_claim" | "wage_remediation";

export type ReadableProofPackageReport = {
  integrity: "verified";
  publicInputsBinding: "verified" | "legacy";
  packageCommitment: string;
  workflow: ProofPackageWorkflow;
  workflowLabel: string;
  scope: ProofPackageGrant["scope"];
  fieldScope: ProofPackageGrant["fieldScope"];
  grantId: string;
  validAfter: string;
  expiresAt: string;
  proofVersion: string;
  verifierAddress: string;
  verificationTransactionHash: string;
  settlementState: string;
  settlementTransactionHash?: string;
  onchainProofState?: {
    chainId: string;
    sealAddress: string;
    runNullifierHigh: string;
    runNullifierLow: string;
    proofVersion: string;
  };
  claim?: {
    type?: string;
    typeLabel?: string;
    id: string;
    agreementId?: string;
    amountAtomic?: string;
    amountLabel?: string;
    token?: PayrollTokenSymbol;
    settlementState: string;
  };
};

export type ProofPackageOpenFailure = {
  code: "expired" | "revoked" | "wrong_recipient" | "tampered" | "invalid";
  title: "Expired" | "Revoked" | "Wrong recipient" | "Tampered" | "Invalid";
  message: string;
};

const claimKindLabels: Record<string, string> = {
  missing_obligation: "Missing obligation",
  below_committed_floor: "Below committed floor",
  incomplete_final_pay: "Incomplete final pay",
};

const disclosedExceptionSchema = z.object({
  workflowType: z.enum(["wage_claim", "wage_remediation"]),
  subjectRecordId: z.string().min(8).max(128),
  claimId: z.string().min(8).max(128).optional(),
  claimKind: z.enum(["missing_obligation", "below_committed_floor", "incomplete_final_pay"]).optional(),
  agreementId: z.string().min(8).max(128).optional(),
  shortfallAtomic: atomicAmountSchema.optional(),
  amountAtomic: atomicAmountSchema.optional(),
  token: payrollTokenSchema,
}).passthrough().superRefine((exception, context) => {
  if (exception.workflowType === "wage_claim") {
    if (!exception.claimKind) context.addIssue({ code: "custom", path: ["claimKind"], message: "A wage claim requires its claim type." });
    if (!exception.shortfallAtomic) context.addIssue({ code: "custom", path: ["shortfallAtomic"], message: "A wage claim requires its proved shortfall." });
  }
  if (exception.workflowType === "wage_remediation") {
    if (!exception.claimId) context.addIssue({ code: "custom", path: ["claimId"], message: "A remediation requires its linked claim ID." });
    if (!exception.amountAtomic) context.addIssue({ code: "custom", path: ["amountAtomic"], message: "A remediation requires its settlement amount." });
  }
});

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function stringField(value: Record<string, unknown>, key: string): string | undefined {
  return typeof value[key] === "string" ? value[key] : undefined;
}

function workflowFromInspection(inspection: RecipientProofPackageInspection): ProofPackageWorkflow {
  if (inspection.proofPackage.proofType === "wage_claim") return "wage_claim";
  if (inspection.proofPackage.proofType === "wage_remediation") return "wage_remediation";
  return "payroll";
}

export function proofPackageIdentityFingerprint(
  identity: VaultPrincipal & {
    format?: "payo-public-identity-v1" | "payo-public-identity-v2";
    claimCapabilityCommitment?: string;
  },
): `0x${string}` {
  if (identity.format === "payo-public-identity-v2" || identity.claimCapabilityCommitment) {
    if (!identity.claimCapabilityCommitment) {
      throw new Error("A PAYO v2 identity requires its claim capability commitment.");
    }
    return hashCanonicalJson({
      domain: "PAYO_PUBLIC_IDENTITY_V2",
      principalId: identity.principalId,
      publicKey: identity.publicKey,
      claimCapabilityCommitment: identity.claimCapabilityCommitment,
    });
  }
  return hashCanonicalJson({
    domain: "PAYO_PUBLIC_IDENTITY_V1",
    principalId: identity.principalId,
    publicKey: identity.publicKey,
  });
}

function assertX25519PublicKey(publicKey: string): void {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(publicKey);
  } catch {
    throw new Error("The PAYO identity public key is not valid base64.");
  }
  if (bytes.length !== 32) throw new Error("The PAYO identity must contain a 32-byte X25519 public key.");
  try {
    const validationSecret = new Uint8Array(32).fill(1);
    const sharedSecret = x25519.getSharedSecret(validationSecret, bytes);
    validationSecret.fill(0);
    sharedSecret.fill(0);
  } catch {
    throw new Error("The PAYO identity contains an invalid X25519 public key.");
  }
}

export function createPayoPublicIdentity(
  principal: VaultPrincipalKeyPair,
  now = new Date(),
): PayoPublicIdentity {
  assertX25519PublicKey(principal.publicKey);
  const claimCapabilityCommitment = claimCapabilityCommitmentV2(
    deriveClaimCapabilitySecret(principal),
  );
  const identity = {
    format: "payo-public-identity-v2" as const,
    principalId: principal.principalId,
    publicKey: principal.publicKey,
    claimCapabilityCommitment,
    createdAt: now.toISOString(),
  };
  return payoPublicIdentitySchema.parse({
    ...identity,
    fingerprint: proofPackageIdentityFingerprint(identity),
  });
}

export function parsePayoPublicIdentity(value: unknown): PayoPublicIdentity {
  const parsed = payoPublicIdentitySchema.safeParse(value);
  if (!parsed.success) throw new Error("This file is not a valid PAYO public identity.");
  const identity = parsed.data;
  assertX25519PublicKey(identity.publicKey);
  if (identity.fingerprint !== proofPackageIdentityFingerprint(identity)) {
    throw new Error("The PAYO public identity fingerprint is invalid.");
  }
  return identity;
}

export function parsePayoProofPackageExport(value: unknown): PayoProofPackageExport {
  const parsed = payoProofPackageExportSchema.safeParse(value);
  if (!parsed.success) throw new Error("This file is not a valid PAYO encrypted proof package.");
  return parsed.data;
}

export function parsePayoJsonText(text: string, label: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

export function classifyProofPackageOpenFailure(error: unknown): ProofPackageOpenFailure {
  const detail = error instanceof Error ? error.message.toLowerCase() : "";
  if (detail.includes("revoked")) {
    return { code: "revoked", title: "Revoked", message: "The issuer revoked this disclosure grant. Ask for a new proof package." };
  }
  if (detail.includes("expired")) {
    return { code: "expired", title: "Expired", message: "This disclosure window has ended. Ask the issuer for a fresh package." };
  }
  if (
    detail.includes("recipient")
    || detail.includes("principal")
    || detail.includes("public key")
    || detail.includes("authorized")
  ) {
    return { code: "wrong_recipient", title: "Wrong recipient", message: "Unlock the PAYO vault whose public identity received this package." };
  }
  if (
    detail.includes("tamper")
    || detail.includes("commitment")
    || detail.includes("integrity")
    || detail.includes("manifest")
    || detail.includes("archive")
    || detail.includes("differs")
    || detail.includes("undeclared")
    || detail.includes("proof binding")
    || detail.includes("not bound")
    || detail.includes("proof public inputs")
    || detail.includes("different starknet chain")
    || detail.includes("different payo seal")
  ) {
    return { code: "tampered", title: "Tampered", message: "PAYO rejected this file because its encrypted contents or proof bindings changed." };
  }
  return { code: "invalid", title: "Invalid", message: "This is not a supported, complete PAYO proof package." };
}

export async function openPayoProofPackage(input: {
  value: unknown;
  recipient: VaultPrincipalKeyPair;
  currentGrant?: ProofPackageGrant;
  at?: Date;
}): Promise<{
  file: PayoProofPackageExport;
  inspection: RecipientProofPackageInspection;
  report: ReadableProofPackageReport;
  grantEvidence: "current" | "embedded";
}> {
  const file = parsePayoProofPackageExport(input.value);
  const currentGrant = input.currentGrant ?? file.grant;
  const inspection = await inspectRecipientProofPackageOffline({
    encryptedPackage: file.encryptedPackage,
    recipient: input.recipient,
    currentGrant,
    at: input.at,
  });
  return {
    file,
    inspection,
    report: createReadableProofPackageReport(inspection),
    grantEvidence: input.currentGrant ? "current" : "embedded",
  };
}

export function createReadableProofPackageReport(
  inspection: RecipientProofPackageInspection,
): ReadableProofPackageReport {
  const workflow = workflowFromInspection(inspection);
  const receipt = record(inspection.starknetReceipt);
  const settlementState = stringField(receipt, "state")
    ?? stringField(receipt, "finality")
    ?? stringField(receipt, "finality_status")
    ?? "Proof-bound";
  const exception = workflow === "payroll"
    ? undefined
    : disclosedExceptionSchema.parse(inspection.disclosedFields.exception);
  if (exception && exception.workflowType !== workflow) {
    throw new Error("The disclosed exception does not match the proof workflow.");
  }
  const token = exception?.token as PayrollTokenSymbol | undefined;
  const amountAtomic = exception?.amountAtomic ?? exception?.shortfallAtomic;
  const claimId = exception?.claimId ?? exception?.subjectRecordId;
  const claimType = exception?.claimKind;
  const claim = exception && claimId
    ? {
        ...(claimType ? { type: claimType, typeLabel: claimKindLabels[claimType] ?? claimType.replaceAll("_", " ") } : {}),
        id: claimId,
        ...(exception.agreementId ? { agreementId: exception.agreementId } : {}),
        ...(amountAtomic ? { amountAtomic } : {}),
        ...(amountAtomic && token ? {
          amountLabel: `${formatTokenAmount(BigInt(amountAtomic), PAYROLL_TOKENS[token])} ${token}`,
        } : {}),
        ...(token ? { token } : {}),
        settlementState,
      }
    : undefined;
  return {
    integrity: "verified",
    publicInputsBinding: inspection.publicInputsBinding,
    packageCommitment: inspection.packageCommitment,
    workflow,
    workflowLabel: workflow === "payroll" ? "Private payroll" : workflow === "wage_claim" ? "Private wage claim" : "Private wage remediation",
    scope: inspection.scope,
    fieldScope: inspection.fieldScope,
    grantId: inspection.grant.id,
    validAfter: inspection.grant.validAfter,
    expiresAt: inspection.grant.expiresAt,
    proofVersion: inspection.verification.proofVersion,
    verifierAddress: inspection.verification.verifierAddress,
    verificationTransactionHash: inspection.verification.verificationTransactionHash,
    settlementState,
    ...(inspection.publicInputsBinding === "verified" ? {
      onchainProofState: {
        chainId: inspection.proofPackage.publicInputs.chainId,
        sealAddress: inspection.proofPackage.publicInputs.sealAddress,
        runNullifierHigh: inspection.proofPackage.publicInputs.runNullifierHigh,
        runNullifierLow: inspection.proofPackage.publicInputs.runNullifierLow,
        proofVersion: inspection.proofPackage.publicInputs.proofVersion,
      },
    } : {}),
    ...(stringField(receipt, "transactionHash") ? { settlementTransactionHash: stringField(receipt, "transactionHash") } : {}),
    ...(claim ? { claim } : {}),
  };
}

function compactDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "undated";
  return date.toISOString().slice(0, 10).replaceAll("-", "");
}

export function proofPackageExportFilename(input: {
  workflow: ProofPackageWorkflow;
  scope: ProofPackageGrant["scope"];
  validAfter: string;
}): string {
  const workflow = input.workflow === "payroll"
    ? "payroll"
    : input.workflow === "wage_claim"
      ? "wage-claim"
      : "wage-remediation";
  return `payo-${workflow}-${input.scope}-${compactDate(input.validAfter)}.json`;
}

export function proofPackageFilename(report: ReadableProofPackageReport): string {
  return proofPackageExportFilename(report);
}

export function publicIdentityFilename(identity: PayoPublicIdentity): string {
  return `payo-public-identity-${identity.fingerprint.slice(2, 10)}.json`;
}

export function serializePayoJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function sameProofPackageGrant(left: ProofPackageGrant, right: ProofPackageGrant): boolean {
  return stableJson(left) === stableJson(right);
}
