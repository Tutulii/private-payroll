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
  agentExecutionRequestSchema,
  type AgentExecutionRequest,
} from "@/lib/domain/capability";

export const encryptedAgentExecutionSchema = z.object({
  version: z.literal(1),
  algorithm: z.literal("XCHACHA20-POLY1305"),
  keyId: z.string().regex(/^0x[0-9a-f]{16}$/),
  nonce: z.string().min(16),
  ciphertext: z.string().min(24),
}).strict();
export type EncryptedAgentExecution = z.infer<typeof encryptedAgentExecutionSchema>;

export type AgentExecutionCryptoContext = {
  executionId: string;
  capabilityId: string;
  organizationId: string;
  requestCommitment: string;
};

function parseKey(rawKey = process.env.PAYO_CAPABILITY_ENCRYPTION_KEY): Uint8Array {
  if (!rawKey) throw new Error("PAYO_CAPABILITY_ENCRYPTION_KEY is required to protect agent executions.");
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

function associatedData(context: AgentExecutionCryptoContext): Uint8Array {
  return utf8(stableJson({ domain: "PAYO_SERVER_AGENT_EXECUTION_V1", ...context }));
}

export function encryptAgentExecutionRequest(
  requestInput: AgentExecutionRequest,
  context: AgentExecutionCryptoContext,
  rawKey?: string,
): EncryptedAgentExecution {
  const request = agentExecutionRequestSchema.parse(requestInput);
  const key = parseKey(rawKey);
  const nonce = randomBytes(24);
  try {
    return encryptedAgentExecutionSchema.parse({
      version: 1,
      algorithm: "XCHACHA20-POLY1305",
      keyId: toHex(sha256(key).subarray(0, 8)),
      nonce: toBase64(nonce),
      ciphertext: toBase64(xchacha20poly1305(key, nonce, associatedData(context)).encrypt(
        utf8(stableJson(request)),
      )),
    });
  } finally {
    key.fill(0);
  }
}

export function decryptAgentExecutionRequest(
  encryptedInput: unknown,
  context: AgentExecutionCryptoContext,
  rawKey?: string,
): AgentExecutionRequest {
  const encrypted = encryptedAgentExecutionSchema.parse(encryptedInput);
  const key = parseKey(rawKey);
  try {
    if (encrypted.keyId !== toHex(sha256(key).subarray(0, 8))) {
      throw new Error("The agent execution encryption key does not match this record.");
    }
    const plaintext = xchacha20poly1305(
      key,
      fromBase64(encrypted.nonce),
      associatedData(context),
    ).decrypt(fromBase64(encrypted.ciphertext));
    return agentExecutionRequestSchema.parse(JSON.parse(decodeUtf8(plaintext)));
  } catch (error) {
    if (error instanceof Error && error.message.includes("encryption key does not match")) throw error;
    throw new Error("The authoritative agent execution could not be decrypted or authenticated.");
  } finally {
    key.fill(0);
  }
}
