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
  signedCapabilitySchema,
  verifySignedCapability,
  type SignedCapability,
} from "@/lib/domain/capability";

export const encryptedCapabilityPolicySchema = z.object({
  version: z.literal(1),
  algorithm: z.literal("XCHACHA20-POLY1305"),
  keyId: z.string().regex(/^0x[0-9a-f]{16}$/),
  nonce: z.string().min(16),
  ciphertext: z.string().min(24),
}).strict();

export type EncryptedCapabilityPolicy = z.infer<typeof encryptedCapabilityPolicySchema>;

export type CapabilityPolicyContext = {
  capabilityId: string;
  organizationId: string;
  principalId: string;
  capabilityHash: string;
};

function parseKey(rawKey = process.env.PAYO_CAPABILITY_ENCRYPTION_KEY): Uint8Array {
  if (!rawKey) {
    throw new Error("PAYO_CAPABILITY_ENCRYPTION_KEY is required to protect authoritative agent policies.");
  }
  let key: Uint8Array;
  try {
    key = rawKey.startsWith("0x") ? normalizedHexBytes(rawKey) : fromBase64(rawKey);
  } catch {
    throw new Error("PAYO_CAPABILITY_ENCRYPTION_KEY must be 32-byte hexadecimal or base64.");
  }
  if (key.length !== 32) {
    key.fill(0);
    throw new Error("PAYO_CAPABILITY_ENCRYPTION_KEY must contain exactly 32 bytes.");
  }
  return key;
}

function associatedData(context: CapabilityPolicyContext): Uint8Array {
  return utf8(stableJson({
    domain: "PAYO_SERVER_CAPABILITY_POLICY_V1",
    ...context,
  }));
}

export function encryptCapabilityPolicy(
  signedCapabilityInput: SignedCapability,
  context: CapabilityPolicyContext,
  rawKey?: string,
): EncryptedCapabilityPolicy {
  const signedCapability = verifySignedCapability(signedCapabilityInput);
  const key = parseKey(rawKey);
  const nonce = randomBytes(24);
  try {
    return encryptedCapabilityPolicySchema.parse({
      version: 1,
      algorithm: "XCHACHA20-POLY1305",
      keyId: toHex(sha256(key).subarray(0, 8)),
      nonce: toBase64(nonce),
      ciphertext: toBase64(xchacha20poly1305(key, nonce, associatedData(context)).encrypt(
        utf8(stableJson(signedCapability)),
      )),
    });
  } finally {
    key.fill(0);
  }
}

export function decryptCapabilityPolicy(
  encryptedInput: unknown,
  context: CapabilityPolicyContext,
  rawKey?: string,
): SignedCapability {
  const encrypted = encryptedCapabilityPolicySchema.parse(encryptedInput);
  const key = parseKey(rawKey);
  try {
    if (encrypted.keyId !== toHex(sha256(key).subarray(0, 8))) {
      throw new Error("The capability policy encryption key does not match this record.");
    }
    const plaintext = xchacha20poly1305(
      key,
      fromBase64(encrypted.nonce),
      associatedData(context),
    ).decrypt(fromBase64(encrypted.ciphertext));
    return verifySignedCapability(signedCapabilitySchema.parse(JSON.parse(decodeUtf8(plaintext))));
  } catch (error) {
    if (error instanceof Error && error.message.includes("encryption key does not match")) throw error;
    throw new Error("The authoritative capability policy could not be decrypted or authenticated.");
  } finally {
    key.fill(0);
  }
}
