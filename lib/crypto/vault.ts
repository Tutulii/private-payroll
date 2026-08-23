import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import {
  decodeUtf8,
  fromBase64,
  stableJson,
  toBase64,
  utf8,
} from "./encoding";

export const VAULT_ALGORITHM = "XCHACHA20-POLY1305+X25519-HKDF-SHA256" as const;

export const vaultAssociatedDataSchema = z.object({
  schemaVersion: z.literal(1),
  organizationId: z.string().min(8).max(128),
  recordType: z.string().min(1).max(64),
  recordId: z.string().min(8).max(128),
  revision: z.number().int().positive(),
});
export type VaultAssociatedData = z.infer<typeof vaultAssociatedDataSchema>;

export type VaultPrincipal = {
  principalId: string;
  publicKey: string;
};

export type VaultPrincipalKeyPair = VaultPrincipal & {
  secretKey: string;
};

export type WrappedVaultKey = {
  principalId: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
};

export type EncryptedVaultRecord = {
  version: 1;
  algorithm: typeof VAULT_ALGORITHM;
  aad: VaultAssociatedData;
  nonce: string;
  ciphertext: string;
  wrappedKeys: WrappedVaultKey[];
};

export const encryptedVaultRecordSchema = z.object({
  version: z.literal(1),
  algorithm: z.literal(VAULT_ALGORITHM),
  aad: vaultAssociatedDataSchema,
  nonce: z.string().min(16),
  ciphertext: z.string().min(24),
  wrappedKeys: z.array(z.object({
    principalId: z.string().min(1).max(160),
    ephemeralPublicKey: z.string().min(16),
    nonce: z.string().min(16),
    ciphertext: z.string().min(24),
  }).strict()).min(1),
}).strict();

export function generateVaultPrincipal(principalId: string): VaultPrincipalKeyPair {
  if (!principalId.trim()) throw new Error("A principal ID is required.");
  const keyPair = x25519.keygen();
  return {
    principalId,
    publicKey: toBase64(keyPair.publicKey),
    secretKey: toBase64(keyPair.secretKey),
  };
}

function wrappingAad(aad: VaultAssociatedData, principalId: string): Uint8Array {
  return utf8(stableJson({ ...aad, principalId, purpose: "payo-dek-wrap-v1" }));
}

function wrappingKey(sharedSecret: Uint8Array, aad: VaultAssociatedData, principalId: string) {
  return hkdf(
    sha256,
    sharedSecret,
    utf8(`${aad.organizationId}:${aad.recordId}:${aad.revision}`),
    wrappingAad(aad, principalId),
    32,
  );
}

export function encryptVaultRecord<T>(
  plaintext: T,
  associatedData: VaultAssociatedData,
  principals: readonly VaultPrincipal[],
): EncryptedVaultRecord {
  const aad = vaultAssociatedDataSchema.parse(associatedData);
  if (principals.length === 0) throw new Error("At least one vault principal is required.");
  const uniquePrincipals = new Set(principals.map(({ principalId }) => principalId));
  if (uniquePrincipals.size !== principals.length) throw new Error("Vault principals must be unique.");

  const dataKey = randomBytes(32);
  const recordNonce = randomBytes(24);
  const encodedAad = utf8(stableJson(aad));
  const ciphertext = xchacha20poly1305(dataKey, recordNonce, encodedAad).encrypt(
    utf8(JSON.stringify(plaintext)),
  );

  const wrappedKeys = principals.map((principal) => {
    const ephemeral = x25519.keygen();
    const sharedSecret = x25519.getSharedSecret(ephemeral.secretKey, fromBase64(principal.publicKey));
    const key = wrappingKey(sharedSecret, aad, principal.principalId);
    const nonce = randomBytes(24);
    const encryptedKey = xchacha20poly1305(key, nonce, wrappingAad(aad, principal.principalId)).encrypt(
      dataKey,
    );
    sharedSecret.fill(0);
    key.fill(0);
    ephemeral.secretKey.fill(0);
    return {
      principalId: principal.principalId,
      ephemeralPublicKey: toBase64(ephemeral.publicKey),
      nonce: toBase64(nonce),
      ciphertext: toBase64(encryptedKey),
    };
  });

  dataKey.fill(0);
  return {
    version: 1,
    algorithm: VAULT_ALGORITHM,
    aad,
    nonce: toBase64(recordNonce),
    ciphertext: toBase64(ciphertext),
    wrappedKeys,
  };
}

export function decryptVaultRecord<T>(
  record: EncryptedVaultRecord,
  principal: VaultPrincipalKeyPair,
): T {
  if (record.version !== 1 || record.algorithm !== VAULT_ALGORITHM) {
    throw new Error("Unsupported PAYO vault envelope.");
  }
  const aad = vaultAssociatedDataSchema.parse(record.aad);
  const wrapped = record.wrappedKeys.find(({ principalId }) => principalId === principal.principalId);
  if (!wrapped) throw new Error("This principal is not authorized to decrypt the record.");

  const sharedSecret = x25519.getSharedSecret(
    fromBase64(principal.secretKey),
    fromBase64(wrapped.ephemeralPublicKey),
  );
  const key = wrappingKey(sharedSecret, aad, principal.principalId);
  const dataKey = xchacha20poly1305(
    key,
    fromBase64(wrapped.nonce),
    wrappingAad(aad, principal.principalId),
  ).decrypt(fromBase64(wrapped.ciphertext));
  sharedSecret.fill(0);
  key.fill(0);

  try {
    const plaintext = xchacha20poly1305(
      dataKey,
      fromBase64(record.nonce),
      utf8(stableJson(aad)),
    ).decrypt(fromBase64(record.ciphertext));
    return JSON.parse(decodeUtf8(plaintext)) as T;
  } finally {
    dataKey.fill(0);
  }
}
