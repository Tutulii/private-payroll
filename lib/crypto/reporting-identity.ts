import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ec } from "starknet";
import { z } from "zod";
import { hashCanonicalJson } from "./digest";
import {
  encodeUint,
  fromBase64,
  stableJson,
  toBase64,
  utf8,
} from "./encoding";
import type { VaultPrincipal, VaultPrincipalKeyPair } from "./vault";

const feltSchema = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/)
  .transform((value) => `0x${BigInt(value).toString(16)}` as `0x${string}`);
const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/)
  .transform((value) => value.toLowerCase() as `0x${string}`);
const STARK_FIELD_PRIME = (1n << 251n) + (17n << 192n) + 1n;

export const reportingIdentityContextSchema = z.object({
  chainId: feltSchema,
  poolAddress: feltSchema,
  recipientAddress: feltSchema,
}).strict();
export type ReportingIdentityContext = z.infer<typeof reportingIdentityContextSchema>;
export type ReportingIdentityContextInput = {
  chainId: string;
  poolAddress: string;
  recipientAddress: string;
};

const reportingIdentityBaseSchema = z.object({
  format: z.literal("payo-reporting-identity-v1"),
  principalId: z.string().min(1).max(160),
  publicKey: z.string().min(16).max(160),
  context: reportingIdentityContextSchema,
  fingerprint: commitmentSchema,
  createdAt: z.string().datetime(),
});

const directStrk20ReportingIdentitySchema = reportingIdentityBaseSchema.extend({
  mode: z.literal("direct_strk20_viewing_key"),
  viewingPublicKey: feltSchema,
  ownershipProof: z.object({
    scheme: z.literal("stark-ecdsa-v1"),
    r: feltSchema,
    s: feltSchema,
  }).strict(),
}).strict();

const readyReportingIdentitySchema = reportingIdentityBaseSchema.extend({
  mode: z.literal("ready_payo_x25519"),
  readyViewingKeyAccess: z.literal("not_available"),
}).strict();

export const payoReportingIdentitySchema = z.discriminatedUnion("mode", [
  directStrk20ReportingIdentitySchema,
  readyReportingIdentitySchema,
]);
export type PayoReportingIdentity = z.infer<typeof payoReportingIdentitySchema>;

export type PayoReportingIdentityKeyPair = {
  identity: PayoReportingIdentity;
  principal: VaultPrincipalKeyPair;
};

const DIRECT_REPORTING_SALT = utf8("PAYO_STRK20_REPORTING_X25519_SALT_V1");

function canonicalContext(input: ReportingIdentityContextInput): ReportingIdentityContext {
  const canonicalFelt = (value: string, label: string): `0x${string}` => {
    const trimmed = value.trim();
    if (!/^0x[0-9a-fA-F]{1,64}$/.test(trimmed)) {
      throw new Error(`${label} must be a Starknet felt.`);
    }
    const numeric = BigInt(trimmed);
    if (numeric >= STARK_FIELD_PRIME) {
      throw new Error(`${label} is outside the Starknet field.`);
    }
    return `0x${numeric.toString(16)}`;
  };
  return reportingIdentityContextSchema.parse({
    chainId: canonicalFelt(input.chainId, "The reporting chain ID"),
    poolAddress: canonicalFelt(input.poolAddress, "The reporting pool address"),
    recipientAddress: canonicalFelt(input.recipientAddress, "The reporting recipient address"),
  });
}

function assertX25519KeyPair(principal: VaultPrincipalKeyPair): void {
  let secretKey: Uint8Array;
  let publicKey: Uint8Array;
  try {
    secretKey = fromBase64(principal.secretKey);
    publicKey = fromBase64(principal.publicKey);
  } catch {
    throw new Error("A reporting identity requires valid base64 X25519 keys.");
  }
  if (secretKey.length !== 32 || publicKey.length !== 32) {
    throw new Error("A reporting identity requires a 32-byte X25519 key pair.");
  }
  const derived = x25519.getPublicKey(secretKey);
  let difference = 0;
  for (let index = 0; index < 32; index += 1) difference |= derived[index] ^ publicKey[index];
  secretKey.fill(0);
  publicKey.fill(0);
  derived.fill(0);
  if (difference !== 0) throw new Error("The reporting identity public and secret keys do not match.");
}

function assertX25519PublicKey(value: string): void {
  let publicKey: Uint8Array;
  try {
    publicKey = fromBase64(value);
  } catch {
    throw new Error("The reporting identity public key is not valid base64.");
  }
  if (publicKey.length !== 32) {
    throw new Error("The reporting identity must contain a 32-byte X25519 public key.");
  }
  try {
    const validationSecret = new Uint8Array(32).fill(1);
    const shared = x25519.getSharedSecret(validationSecret, publicKey);
    validationSecret.fill(0);
    shared.fill(0);
  } catch {
    throw new Error("The reporting identity contains an invalid X25519 public key.");
  } finally {
    publicKey.fill(0);
  }
}

function identityFingerprint(
  identity: Record<string, unknown>,
): `0x${string}` {
  return hashCanonicalJson({ domain: "PAYO_REPORTING_IDENTITY_V1", ...identity });
}

function ownershipChallenge(fingerprint: string): `0x${string}` {
  const reduced = BigInt(fingerprint) % ec.starkCurve.CURVE.n;
  return `0x${(reduced === 0n ? 1n : reduced).toString(16)}`;
}

function verifyDirectOwnership(input: {
  fingerprint: string;
  viewingPublicKey: string;
  ownershipProof: { r: string; s: string };
}): boolean {
  let signature: InstanceType<typeof ec.starkCurve.Signature>;
  try {
    signature = new ec.starkCurve.Signature(
      BigInt(input.ownershipProof.r),
      BigInt(input.ownershipProof.s),
    );
  } catch {
    return false;
  }
  const publicKeyX = BigInt(input.viewingPublicKey).toString(16).padStart(64, "0");
  return ["02", "03"].some((prefix) => {
    try {
      return ec.starkCurve.verify(
        signature,
        ownershipChallenge(input.fingerprint),
        `${prefix}${publicKeyX}`,
      );
    } catch {
      return false;
    }
  });
}

function directPrincipalId(input: {
  publicKey: string;
  viewingPublicKey: string;
  context: ReportingIdentityContext;
}): string {
  const digest = hashCanonicalJson({
    domain: "PAYO_STRK20_REPORTING_PRINCIPAL_V1",
    publicKey: input.publicKey,
    viewingPublicKey: input.viewingPublicKey,
    context: input.context,
  });
  return `payo:strk20-report:${digest.slice(2)}`;
}

/**
 * Derives a recoverable reporting-only X25519 identity from a direct STRK20
 * viewing key. The secret never leaves this function's caller; the returned
 * public identity contains only the registered Stark public key and X25519
 * encryption key. Ready wallets must use createReadyReportingIdentity instead.
 */
export function deriveDirectStrk20ReportingIdentity(input: {
  viewingKey: string;
  context: ReportingIdentityContextInput;
  createdAt?: Date;
}): PayoReportingIdentityKeyPair {
  let scalar: bigint;
  try {
    scalar = BigInt(input.viewingKey);
  } catch {
    throw new Error("The direct STRK20 viewing key is invalid.");
  }
  if (scalar <= 0n || scalar > ec.starkCurve.CURVE.n / 2n) {
    throw new Error("The direct STRK20 viewing key is outside the supported scalar range.");
  }
  const context = canonicalContext(input.context);
  const keyMaterial = encodeUint(scalar, 32);
  const contextBytes = utf8(stableJson({
    domain: "PAYO_STRK20_REPORTING_CONTEXT_V1",
    context,
  }));
  const secretKey = hkdf(sha256, keyMaterial, DIRECT_REPORTING_SALT, contextBytes, 32);
  keyMaterial.fill(0);
  const publicKeyBytes = x25519.getPublicKey(secretKey);
  const publicKey = toBase64(publicKeyBytes);
  const viewingPublicKey = `0x${BigInt(ec.starkCurve.getStarkKey(input.viewingKey)).toString(16)}`;
  const principalId = directPrincipalId({ publicKey, viewingPublicKey, context });
  const identityWithoutFingerprint = {
    format: "payo-reporting-identity-v1" as const,
    mode: "direct_strk20_viewing_key" as const,
    principalId,
    publicKey,
    viewingPublicKey,
    context,
  };
  const fingerprint = identityFingerprint(identityWithoutFingerprint);
  const signature = ec.starkCurve.sign(
    ownershipChallenge(fingerprint),
    input.viewingKey,
  );
  const identity = payoReportingIdentitySchema.parse({
    ...identityWithoutFingerprint,
    fingerprint,
    ownershipProof: {
      scheme: "stark-ecdsa-v1",
      r: `0x${signature.r.toString(16)}`,
      s: `0x${signature.s.toString(16)}`,
    },
    createdAt: (input.createdAt ?? new Date()).toISOString(),
  });
  const principal = {
    principalId,
    publicKey,
    secretKey: toBase64(secretKey),
  };
  secretKey.fill(0);
  publicKeyBytes.fill(0);
  return { identity, principal };
}

/** Public fallback identity for Ready, whose STRK20 viewing key PAYO cannot access. */
export function createReadyReportingPublicIdentity(input: {
  principal: VaultPrincipal;
  context: ReportingIdentityContextInput;
  createdAt?: Date;
}): PayoReportingIdentity {
  if (!input.principal.principalId.trim()) {
    throw new Error("A Ready reporting identity requires a principal ID.");
  }
  assertX25519PublicKey(input.principal.publicKey);
  const context = canonicalContext(input.context);
  const identityWithoutFingerprint = {
    format: "payo-reporting-identity-v1" as const,
    mode: "ready_payo_x25519" as const,
    principalId: input.principal.principalId,
    publicKey: input.principal.publicKey,
    context,
    readyViewingKeyAccess: "not_available" as const,
  };
  return payoReportingIdentitySchema.parse({
    ...identityWithoutFingerprint,
    fingerprint: identityFingerprint(identityWithoutFingerprint),
    createdAt: (input.createdAt ?? new Date()).toISOString(),
  });
}

/** Explicit local Ready key-pair fallback. */
export function createReadyReportingIdentity(input: {
  principal: VaultPrincipalKeyPair;
  context: ReportingIdentityContextInput;
  createdAt?: Date;
}): PayoReportingIdentityKeyPair {
  assertX25519KeyPair(input.principal);
  return {
    identity: createReadyReportingPublicIdentity(input),
    principal: input.principal,
  };
}

export function parsePayoReportingIdentity(value: unknown): PayoReportingIdentity {
  const parsed = payoReportingIdentitySchema.safeParse(value);
  if (!parsed.success) throw new Error("This file is not a valid PAYO reporting identity.");
  const identity = parsed.data;
  assertX25519PublicKey(identity.publicKey);
  const identityWithoutFingerprint = identity.mode === "direct_strk20_viewing_key"
    ? {
        format: identity.format,
        mode: identity.mode,
        principalId: identity.principalId,
        publicKey: identity.publicKey,
        viewingPublicKey: identity.viewingPublicKey,
        context: identity.context,
      }
    : {
        format: identity.format,
        mode: identity.mode,
        principalId: identity.principalId,
        publicKey: identity.publicKey,
        context: identity.context,
        readyViewingKeyAccess: identity.readyViewingKeyAccess,
      };
  if (identity.fingerprint !== identityFingerprint(identityWithoutFingerprint)) {
    throw new Error("The PAYO reporting identity fingerprint is invalid.");
  }
  if (identity.mode === "direct_strk20_viewing_key") {
    const expectedPrincipalId = directPrincipalId(identity);
    if (identity.principalId !== expectedPrincipalId) {
      throw new Error("The direct STRK20 reporting principal ID is invalid.");
    }
    if (!verifyDirectOwnership(identity)) {
      throw new Error("The direct STRK20 reporting identity has no valid viewing-key ownership proof.");
    }
  }
  return identity;
}

export function assertReportingIdentityKeyPair(input: PayoReportingIdentityKeyPair): void {
  const identity = parsePayoReportingIdentity(input.identity);
  assertX25519KeyPair(input.principal);
  if (
    identity.principalId !== input.principal.principalId
    || identity.publicKey !== input.principal.publicKey
  ) throw new Error("The reporting identity does not match this local key pair.");
}

export function reportingIdentityFilename(identity: PayoReportingIdentity): string {
  return `payo-${identity.mode === "direct_strk20_viewing_key" ? "strk20" : "ready"}-reporting-identity-${identity.fingerprint.slice(2, 10)}.json`;
}
