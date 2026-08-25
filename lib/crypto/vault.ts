import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { argon2id } from "hash-wasm";
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

export type VaultRecoveryMaterial = {
  organizationSecret: string;
  principal: VaultPrincipalKeyPair;
};

export type VaultRecoveryPackage = {
  packageVersion: "payo-vault-recovery-v1";
  organizationId: string;
  algorithm: "ARGON2ID+XCHACHA20-POLY1305";
  kdf: {
    salt: string;
    memoryKiB: number;
    iterations: number;
    parallelism: number;
  };
  nonce: string;
  ciphertext: string;
  createdAt: string;
};

export type VaultSecondAdminEnrollment = {
  packageVersion: "payo-second-admin-enrollment-v1";
  organizationId: string;
  principalId: string;
  publicKey: string;
  algorithm: "ARGON2ID+XCHACHA20-POLY1305";
  kdf: VaultRecoveryPackage["kdf"];
  nonce: string;
  ciphertext: string;
  createdAt: string;
};

const recoveryMaterialSchema = z.object({
  organizationSecret: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  principal: z.object({
    principalId: z.string().min(1).max(160),
    publicKey: z.string().min(16),
    secretKey: z.string().min(16),
  }).strict(),
}).strict();

export const vaultRecoveryPackageSchema = z.object({
  packageVersion: z.literal("payo-vault-recovery-v1"),
  organizationId: z.string().min(8).max(128),
  algorithm: z.literal("ARGON2ID+XCHACHA20-POLY1305"),
  kdf: z.object({
    salt: z.string().min(16),
    memoryKiB: z.number().int().min(65_536).max(1_048_576),
    iterations: z.number().int().min(3).max(20),
    parallelism: z.number().int().min(1).max(8),
  }).strict(),
  nonce: z.string().min(16),
  ciphertext: z.string().min(24),
  createdAt: z.string().datetime(),
}).strict();

export const vaultSecondAdminEnrollmentSchema = z.object({
  packageVersion: z.literal("payo-second-admin-enrollment-v1"),
  organizationId: z.string().min(8).max(128),
  principalId: z.string().min(1).max(160),
  publicKey: z.string().min(16),
  algorithm: z.literal("ARGON2ID+XCHACHA20-POLY1305"),
  kdf: vaultRecoveryPackageSchema.shape.kdf,
  nonce: z.string().min(16),
  ciphertext: z.string().min(24),
  createdAt: z.string().datetime(),
}).strict();

const RECOVERY_MEMORY_KIB = 65_536;
const RECOVERY_ITERATIONS = 3;
const RECOVERY_PARALLELISM = 1;
const RECOVERY_KEY_BYTES = 32;

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

function unwrapDataKey(
  record: EncryptedVaultRecord,
  principal: VaultPrincipalKeyPair,
): Uint8Array {
  const aad = vaultAssociatedDataSchema.parse(record.aad);
  const wrapped = record.wrappedKeys.find(({ principalId }) => principalId === principal.principalId);
  if (!wrapped) throw new Error("This principal is not authorized to decrypt the record.");

  const sharedSecret = x25519.getSharedSecret(
    fromBase64(principal.secretKey),
    fromBase64(wrapped.ephemeralPublicKey),
  );
  const key = wrappingKey(sharedSecret, aad, principal.principalId);
  try {
    return xchacha20poly1305(
      key,
      fromBase64(wrapped.nonce),
      wrappingAad(aad, principal.principalId),
    ).decrypt(fromBase64(wrapped.ciphertext));
  } finally {
    sharedSecret.fill(0);
    key.fill(0);
  }
}

function wrapDataKey(
  dataKey: Uint8Array,
  aad: VaultAssociatedData,
  principal: VaultPrincipal,
): WrappedVaultKey {
  const ephemeral = x25519.keygen();
  const sharedSecret = x25519.getSharedSecret(ephemeral.secretKey, fromBase64(principal.publicKey));
  const key = wrappingKey(sharedSecret, aad, principal.principalId);
  const nonce = randomBytes(24);
  try {
    const encryptedKey = xchacha20poly1305(
      key,
      nonce,
      wrappingAad(aad, principal.principalId),
    ).encrypt(dataKey);
    return {
      principalId: principal.principalId,
      ephemeralPublicKey: toBase64(ephemeral.publicKey),
      nonce: toBase64(nonce),
      ciphertext: toBase64(encryptedKey),
    };
  } finally {
    sharedSecret.fill(0);
    key.fill(0);
    ephemeral.secretKey.fill(0);
  }
}

function validatePrincipals(principals: readonly VaultPrincipal[]): void {
  if (principals.length === 0) throw new Error("At least one vault principal is required.");
  const uniquePrincipals = new Set(principals.map(({ principalId }) => principalId));
  if (uniquePrincipals.size !== principals.length) throw new Error("Vault principals must be unique.");
  for (const principal of principals) {
    if (!principal.principalId.trim()) throw new Error("A vault principal ID is required.");
    const publicKey = fromBase64(principal.publicKey);
    if (publicKey.length !== 32) throw new Error("A vault principal must use a 32-byte X25519 public key.");
  }
}

export function encryptVaultRecord<T>(
  plaintext: T,
  associatedData: VaultAssociatedData,
  principals: readonly VaultPrincipal[],
): EncryptedVaultRecord {
  const aad = vaultAssociatedDataSchema.parse(associatedData);
  validatePrincipals(principals);

  const dataKey = randomBytes(32);
  const recordNonce = randomBytes(24);
  const encodedAad = utf8(stableJson(aad));
  const ciphertext = xchacha20poly1305(dataKey, recordNonce, encodedAad).encrypt(
    utf8(JSON.stringify(plaintext)),
  );

  const wrappedKeys = principals.map((principal) => wrapDataKey(dataKey, aad, principal));

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
  const dataKey = unwrapDataKey(record, principal);

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

/**
 * Adds or rotates recipients without decrypting the record body. Removing a recipient here only
 * prevents future envelope access; use rotateVaultRecordKey for cryptographic revocation.
 */
export function rewrapVaultRecord(
  recordInput: EncryptedVaultRecord,
  authorizingPrincipal: VaultPrincipalKeyPair,
  principals: readonly VaultPrincipal[],
): EncryptedVaultRecord {
  const record = encryptedVaultRecordSchema.parse(recordInput);
  validatePrincipals(principals);
  const dataKey = unwrapDataKey(record, authorizingPrincipal);
  try {
    return {
      ...record,
      wrappedKeys: principals.map((principal) => wrapDataKey(dataKey, record.aad, principal)),
    };
  } finally {
    dataKey.fill(0);
  }
}

/** Re-encrypts the body under a fresh random DEK so a removed grantee cannot decrypt revisions. */
export function rotateVaultRecordKey<T>(
  recordInput: EncryptedVaultRecord,
  authorizingPrincipal: VaultPrincipalKeyPair,
  principals: readonly VaultPrincipal[],
  nextRevision: number,
): EncryptedVaultRecord {
  const record = encryptedVaultRecordSchema.parse(recordInput);
  if (!Number.isInteger(nextRevision) || nextRevision <= record.aad.revision) {
    throw new Error("A rotated vault record must use a newer positive revision.");
  }
  const plaintext = decryptVaultRecord<T>(record, authorizingPrincipal);
  return encryptVaultRecord(
    plaintext,
    { ...record.aad, revision: nextRevision },
    principals,
  );
}

function recoveryAad(pkg: object): Uint8Array {
  return utf8(stableJson(pkg));
}

export async function createSecondAdminEnrollment(input: {
  organizationId: string;
  principalId: string;
  password: string;
  createdAt?: string;
}): Promise<VaultSecondAdminEnrollment> {
  if (input.organizationId.length < 8 || input.organizationId.length > 128) {
    throw new Error("A valid organization ID is required for second-admin enrollment.");
  }
  const principal = generateVaultPrincipal(input.principalId);
  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const header = {
    packageVersion: "payo-second-admin-enrollment-v1" as const,
    organizationId: input.organizationId,
    principalId: principal.principalId,
    publicKey: principal.publicKey,
    algorithm: "ARGON2ID+XCHACHA20-POLY1305" as const,
    kdf: {
      salt: toBase64(salt),
      memoryKiB: RECOVERY_MEMORY_KIB,
      iterations: RECOVERY_ITERATIONS,
      parallelism: RECOVERY_PARALLELISM,
    },
    nonce: toBase64(nonce),
    createdAt: input.createdAt ?? new Date().toISOString(),
  };
  const key = await deriveRecoveryKey(input.password, salt, header.kdf);
  try {
    const ciphertext = xchacha20poly1305(key, nonce, recoveryAad(header)).encrypt(
      utf8(stableJson(principal)),
    );
    return vaultSecondAdminEnrollmentSchema.parse({ ...header, ciphertext: toBase64(ciphertext) });
  } finally {
    key.fill(0);
  }
}

export async function recoverSecondAdminEnrollment(
  packageInput: VaultSecondAdminEnrollment,
  password: string,
): Promise<VaultPrincipalKeyPair> {
  const pkg = vaultSecondAdminEnrollmentSchema.parse(packageInput);
  const { ciphertext, ...header } = pkg;
  const key = await deriveRecoveryKey(password, fromBase64(pkg.kdf.salt), pkg.kdf);
  try {
    const plaintext = xchacha20poly1305(
      key,
      fromBase64(pkg.nonce),
      recoveryAad(header),
    ).decrypt(fromBase64(ciphertext));
    const principal = recoveryMaterialSchema.shape.principal.parse(JSON.parse(decodeUtf8(plaintext)));
    if (principal.principalId !== pkg.principalId || principal.publicKey !== pkg.publicKey) {
      throw new Error("Second-admin enrollment identity does not match its encrypted key.");
    }
    return principal;
  } catch {
    throw new Error("The second-admin enrollment package or password is invalid.");
  } finally {
    key.fill(0);
  }
}

async function deriveRecoveryKey(
  password: string,
  salt: Uint8Array,
  parameters: Pick<VaultRecoveryPackage["kdf"], "memoryKiB" | "iterations" | "parallelism">,
): Promise<Uint8Array> {
  if (password.length < 12 || password.length > 1024) {
    throw new Error("Recovery password must contain between 12 and 1024 characters.");
  }
  return argon2id({
    password: utf8(password),
    salt,
    iterations: parameters.iterations,
    parallelism: parameters.parallelism,
    memorySize: parameters.memoryKiB,
    hashLength: RECOVERY_KEY_BYTES,
    outputType: "binary",
  });
}

export async function createVaultRecoveryPackage(
  organizationId: string,
  materialInput: VaultRecoveryMaterial,
  password: string,
  createdAt = new Date().toISOString(),
): Promise<VaultRecoveryPackage> {
  if (organizationId.length < 8 || organizationId.length > 128) {
    throw new Error("A valid organization ID is required for recovery.");
  }
  const material = recoveryMaterialSchema.parse(materialInput);
  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const header = {
    packageVersion: "payo-vault-recovery-v1" as const,
    organizationId,
    algorithm: "ARGON2ID+XCHACHA20-POLY1305" as const,
    kdf: {
      salt: toBase64(salt),
      memoryKiB: RECOVERY_MEMORY_KIB,
      iterations: RECOVERY_ITERATIONS,
      parallelism: RECOVERY_PARALLELISM,
    },
    nonce: toBase64(nonce),
    createdAt,
  };
  const key = await deriveRecoveryKey(password, salt, header.kdf);
  try {
    const ciphertext = xchacha20poly1305(key, nonce, recoveryAad(header)).encrypt(
      utf8(stableJson(material)),
    );
    return vaultRecoveryPackageSchema.parse({ ...header, ciphertext: toBase64(ciphertext) });
  } finally {
    key.fill(0);
  }
}

export async function recoverVaultRecoveryPackage(
  packageInput: VaultRecoveryPackage,
  password: string,
): Promise<VaultRecoveryMaterial> {
  const pkg = vaultRecoveryPackageSchema.parse(packageInput);
  const { ciphertext, ...header } = pkg;
  const key = await deriveRecoveryKey(password, fromBase64(pkg.kdf.salt), pkg.kdf);
  try {
    const plaintext = xchacha20poly1305(
      key,
      fromBase64(pkg.nonce),
      recoveryAad(header),
    ).decrypt(fromBase64(ciphertext));
    return recoveryMaterialSchema.parse(JSON.parse(decodeUtf8(plaintext)));
  } catch {
    throw new Error("The recovery package or password is invalid.");
  } finally {
    key.fill(0);
  }
}
