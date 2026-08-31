import "server-only";

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import {
  decodeUtf8,
  fromBase64,
  normalizedHexBytes,
  stableJson,
  toBase64,
  toHex,
  utf8,
} from "@/lib/crypto/encoding";
import {
  directPrivacyPreparationSchema,
  directPrivacyPayrollAuthorizationSchema,
  directPrivacyProofDraftSchema,
  directPrivacyPreparedSubmissionSchema,
  directPrivacyReconciliationProofSchema,
  directPrivacyFinalizationSubmissionSchema,
  directPrivacyRunMaterialSchema,
  directPrivacySecretsSchema,
  directPrivacyStateSchema,
  type DirectPrivacyPreparation,
  type DirectPrivacyPayrollAuthorization,
  type DirectPrivacyProofDraft,
  type DirectPrivacyPreparedSubmission,
  type DirectPrivacyReconciliationProof,
  type DirectPrivacyFinalizationSubmission,
  type DirectPrivacyRunMaterial,
  type DirectPrivacySecrets,
  type DirectPrivacyState,
} from "@/lib/domain/direct-privacy";

export const encryptedDirectPrivacyPayloadSchema = z.object({
  version: z.literal(1),
  algorithm: z.literal("XCHACHA20-POLY1305"),
  keyId: z.string().regex(/^0x[0-9a-f]{16}$/),
  nonce: z.string().min(16),
  ciphertext: z.string().min(24),
}).strict();
export type EncryptedDirectPrivacyPayload = z.infer<typeof encryptedDirectPrivacyPayloadSchema>;

export type DirectPrivacyCryptoContext = {
  accountId: string;
  organizationId: string;
  capabilityId: string;
} & (
  | { purpose: "secrets" }
  | { purpose: "state"; stateVersion: number }
  | { purpose: "run"; runId: string; runVersion: number; materialCommitment: string }
  | { purpose: "preparation"; executionId: string; preparationCommitment: string }
  | {
    purpose: "payroll-authorization";
    executionId: string;
    authorizationCommitment: string;
  }
  | { purpose: "proof-draft"; executionId: string; draftCommitment: string }
  | { purpose: "submission"; executionId: string; submissionCommitment: string }
  | { purpose: "reconciliation"; executionId: string; proofCommitment: string }
  | {
    purpose: "finalization";
    executionId: string;
    chunkIndex: number;
    finalizationCommitment: string;
  }
);

type PayloadByPurpose = {
  secrets: DirectPrivacySecrets;
  state: DirectPrivacyState;
  run: DirectPrivacyRunMaterial;
  preparation: DirectPrivacyPreparation;
  "payroll-authorization": DirectPrivacyPayrollAuthorization;
  "proof-draft": DirectPrivacyProofDraft;
  submission: DirectPrivacyPreparedSubmission;
  reconciliation: DirectPrivacyReconciliationProof;
  finalization: DirectPrivacyFinalizationSubmission;
};

const schemas = {
  secrets: directPrivacySecretsSchema,
  state: directPrivacyStateSchema,
  run: directPrivacyRunMaterialSchema,
  preparation: directPrivacyPreparationSchema,
  "payroll-authorization": directPrivacyPayrollAuthorizationSchema,
  "proof-draft": directPrivacyProofDraftSchema,
  submission: directPrivacyPreparedSubmissionSchema,
  reconciliation: directPrivacyReconciliationProofSchema,
  finalization: directPrivacyFinalizationSubmissionSchema,
} as const;

function parseKey(rawKey = process.env.PAYO_PRIVACY_KEY_ENCRYPTION_KEY): Uint8Array {
  if (!rawKey) {
    throw new Error("PAYO_PRIVACY_KEY_ENCRYPTION_KEY is required for direct private accounts.");
  }
  let key: Uint8Array;
  try {
    key = rawKey.startsWith("0x") ? normalizedHexBytes(rawKey) : fromBase64(rawKey);
  } catch {
    throw new Error("PAYO_PRIVACY_KEY_ENCRYPTION_KEY must be 32-byte hexadecimal or base64.");
  }
  if (key.length !== 32) {
    key.fill(0);
    throw new Error("PAYO_PRIVACY_KEY_ENCRYPTION_KEY must contain exactly 32 bytes.");
  }
  return key;
}

function associatedData(context: DirectPrivacyCryptoContext): Uint8Array {
  return utf8(stableJson({ domain: "PAYO_DIRECT_PRIVACY_PAYLOAD_V1", ...context }));
}

export function encryptDirectPrivacyPayload<Purpose extends keyof PayloadByPurpose>(
  payloadInput: PayloadByPurpose[Purpose],
  context: Extract<DirectPrivacyCryptoContext, { purpose: Purpose }>,
  rawKey?: string,
): EncryptedDirectPrivacyPayload {
  const payload = schemas[context.purpose].parse(payloadInput);
  const key = parseKey(rawKey);
  const nonce = randomBytes(24);
  try {
    return encryptedDirectPrivacyPayloadSchema.parse({
      version: 1,
      algorithm: "XCHACHA20-POLY1305",
      keyId: toHex(sha256(key).subarray(0, 8)),
      nonce: toBase64(nonce),
      ciphertext: toBase64(xchacha20poly1305(key, nonce, associatedData(context)).encrypt(
        utf8(stableJson(payload)),
      )),
    });
  } finally {
    key.fill(0);
  }
}

export function decryptDirectPrivacyPayload<Purpose extends keyof PayloadByPurpose>(
  encryptedInput: unknown,
  context: Extract<DirectPrivacyCryptoContext, { purpose: Purpose }>,
  rawKey?: string,
): PayloadByPurpose[Purpose] {
  const encrypted = encryptedDirectPrivacyPayloadSchema.parse(encryptedInput);
  const key = parseKey(rawKey);
  try {
    if (encrypted.keyId !== toHex(sha256(key).subarray(0, 8))) {
      throw new Error("The direct-privacy encryption key does not match this record.");
    }
    const plaintext = xchacha20poly1305(
      key,
      fromBase64(encrypted.nonce),
      associatedData(context),
    ).decrypt(fromBase64(encrypted.ciphertext));
    return schemas[context.purpose].parse(JSON.parse(decodeUtf8(plaintext))) as PayloadByPurpose[Purpose];
  } catch (error) {
    if (error instanceof Error && error.message.includes("encryption key does not match")) throw error;
    throw new Error("The direct private account payload could not be decrypted or authenticated.");
  } finally {
    key.fill(0);
  }
}
