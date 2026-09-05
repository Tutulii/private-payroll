import { ed25519 } from "@noble/curves/ed25519.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { z } from "zod";
import {
  concatBytes,
  encodeUint,
  fromBase64,
  normalizedHexBytes,
  toBase64,
  toHex,
  utf8,
} from "@/lib/crypto/encoding";
import { createProofCommitter } from "@/lib/proof/commitments";
import { commitmentSchema, uuidV7Schema } from "./records";

export const PAYO_EXTERNAL_ATTESTATION_VERSION =
  "payo-external-attestation-v1" as const;
export const PAYO_EXTERNAL_ATTESTATION_PACKAGE_VERSION =
  "payo-external-attestation-package-v1" as const;

export const PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS = toHex(keccak_256(
  utf8("PAYO_EXTERNAL_ATTESTATION_STATUS_V1ACTIVE"),
));

export const externalAttestationFactMask = Object.freeze({
  residency: 1,
  employment_status: 2,
  tax_status: 4,
});
export const PAYO_EXTERNAL_ATTESTATION_ALL_FACTS = 7 as const;

const u64StringSchema = z.string().regex(/^(0|[1-9]\d*)$/).refine(
  (value) => BigInt(value) < 1n << 64n,
  "Timestamp must fit in u64.",
);

function base64Bytes(length: number) {
  return z.string().min(1).superRefine((value, context) => {
    try {
      if (fromBase64(value).length !== length) {
        context.addIssue({ code: "custom", message: `Value must decode to ${length} bytes.` });
      }
    } catch {
      context.addIssue({ code: "custom", message: "Value is not canonical base64." });
    }
  });
}

export const externalAttestationSchema = z.object({
  attestationVersion: z.literal(PAYO_EXTERNAL_ATTESTATION_VERSION),
  issuerPublicKey: base64Bytes(32),
  subjectCommitment: commitmentSchema,
  factMask: z.number().int().min(1).max(7),
  jurisdictionCode: z.string().regex(/^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/),
  jurisdictionCommitment: commitmentSchema,
  policyRoot: commitmentSchema,
  statusCommitment: commitmentSchema,
  validFrom: u64StringSchema,
  validUntil: u64StringSchema,
  nonce: commitmentSchema,
}).strict().superRefine((attestation, context) => {
  if (BigInt(attestation.validUntil) <= BigInt(attestation.validFrom)) {
    context.addIssue({ code: "custom", path: ["validUntil"], message: "Attestation expiry must follow activation." });
  }
  if (BigInt(attestation.subjectCommitment) === 0n) {
    context.addIssue({ code: "custom", path: ["subjectCommitment"], message: "Attestation subject is zero." });
  }
  if (BigInt(attestation.policyRoot) === 0n) {
    context.addIssue({ code: "custom", path: ["policyRoot"], message: "Attestation policy root is zero." });
  }
  if (BigInt(attestation.statusCommitment) !== BigInt(PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS)) {
    context.addIssue({ code: "custom", path: ["statusCommitment"], message: "Attestation status is not active." });
  }
  if (BigInt(attestation.nonce) === 0n) {
    context.addIssue({ code: "custom", path: ["nonce"], message: "Attestation nonce must be non-zero." });
  }
  if (attestation.jurisdictionCommitment !== jurisdictionCommitment(attestation.jurisdictionCode)) {
    context.addIssue({ code: "custom", path: ["jurisdictionCommitment"], message: "Jurisdiction commitment does not match its code." });
  }
});
export type ExternalAttestation = z.infer<typeof externalAttestationSchema>;

export const signedExternalAttestationSchema = z.object({
  attestation: externalAttestationSchema,
  commitment: commitmentSchema,
  signature: base64Bytes(64),
}).strict();
export type SignedExternalAttestation = z.infer<typeof signedExternalAttestationSchema>;

export const externalAttestationProofPackageSchema = z.object({
  packageVersion: z.literal(PAYO_EXTERNAL_ATTESTATION_PACKAGE_VERSION),
  agreementId: uuidV7Schema,
  catalogRoot: commitmentSchema.refine((value) => BigInt(value) !== 0n, {
    message: "External attestation catalog root is zero.",
  }),
  signed: signedExternalAttestationSchema,
  siblings: z.array(commitmentSchema).length(6),
  pathBits: z.array(z.boolean()).length(6),
}).strict();
export type ExternalAttestationProofPackage = z.infer<
  typeof externalAttestationProofPackageSchema
>;

export function jurisdictionCommitment(code: string): `0x${string}` {
  const parsed = z.string().regex(/^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/).parse(code);
  return toHex(keccak_256(concatBytes(utf8("PAYO_JURISDICTION_V1"), utf8(parsed))));
}

/** Fixed-width commitment recreated by the v3 circuit. */
export function externalAttestationCommitment(input: ExternalAttestation): `0x${string}` {
  const attestation = externalAttestationSchema.parse(input);
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_EXTERNAL_ATTESTATION_V1"),
    encodeUint(1n, 1),
    fromBase64(attestation.issuerPublicKey),
    normalizedHexBytes(attestation.subjectCommitment, 32),
    encodeUint(BigInt(attestation.factMask), 1),
    normalizedHexBytes(attestation.jurisdictionCommitment, 32),
    normalizedHexBytes(attestation.statusCommitment, 32),
    encodeUint(BigInt(attestation.validFrom), 8),
    encodeUint(BigInt(attestation.validUntil), 8),
    normalizedHexBytes(attestation.nonce, 32),
    normalizedHexBytes(attestation.policyRoot, 32),
  )));
}

export function signExternalAttestation(
  input: Omit<ExternalAttestation, "issuerPublicKey">,
  issuerSecretKey: Uint8Array,
): SignedExternalAttestation {
  const attestation = externalAttestationSchema.parse({
    ...input,
    issuerPublicKey: toBase64(ed25519.getPublicKey(issuerSecretKey)),
  });
  const commitment = externalAttestationCommitment(attestation);
  return {
    attestation,
    commitment,
    signature: toBase64(ed25519.sign(normalizedHexBytes(commitment, 32), issuerSecretKey)),
  };
}

export function verifySignedExternalAttestation(input: unknown, options?: {
  trustedIssuerPublicKeys?: readonly string[];
}): SignedExternalAttestation {
  const signed = signedExternalAttestationSchema.parse(input);
  const commitment = externalAttestationCommitment(signed.attestation);
  if (BigInt(commitment) !== BigInt(signed.commitment)) {
    throw new Error("External attestation commitment does not match its signed payload.");
  }
  if (options?.trustedIssuerPublicKeys
    && !options.trustedIssuerPublicKeys.includes(signed.attestation.issuerPublicKey)) {
    throw new Error("External attestation issuer is not approved.");
  }
  if (!ed25519.verify(
    fromBase64(signed.signature),
    normalizedHexBytes(commitment, 32),
    fromBase64(signed.attestation.issuerPublicKey),
    { zip215: false },
  )) throw new Error("External attestation signature is invalid.");
  return signed;
}

export function assertExternalAttestationUsable(input: SignedExternalAttestation, options: {
  subjectCommitment: string;
  policyRoot: string;
  requiredFactMask: number;
  at: bigint;
  revokedNonces?: ReadonlySet<string>;
}): SignedExternalAttestation {
  const signed = verifySignedExternalAttestation(input);
  const attestation = signed.attestation;
  if (BigInt(attestation.subjectCommitment) !== BigInt(options.subjectCommitment)) {
    throw new Error("External attestation belongs to another private subject.");
  }
  if (BigInt(attestation.policyRoot) !== BigInt(options.policyRoot)) {
    throw new Error("External attestation is bound to another payroll policy catalog.");
  }
  if ((attestation.factMask & options.requiredFactMask) !== options.requiredFactMask) {
    throw new Error("External attestation does not cover the required facts.");
  }
  if (options.at < BigInt(attestation.validFrom) || options.at > BigInt(attestation.validUntil)) {
    throw new Error("External attestation is outside its validity window.");
  }
  const revoked = options.revokedNonces;
  if (revoked && [...revoked].some((nonce) => BigInt(nonce) === BigInt(attestation.nonce))) {
    throw new Error("External attestation has been revoked.");
  }
  return signed;
}

export type ExternalAttestationCatalog = {
  root: `0x${string}`;
  entries: Array<{
    signed: SignedExternalAttestation;
    leaf: `0x${string}`;
    siblings: `0x${string}`[];
    pathBits: boolean[];
  }>;
};

/**
 * Builds the exact approved/non-revoked catalog committed through PAYO's
 * versioned policy-root registry. Signature verification happens before a
 * commitment can enter the root; the v3 proof then verifies private membership.
 */
export async function buildExternalAttestationCatalog(input: {
  attestations: readonly SignedExternalAttestation[];
  trustedIssuerPublicKeys: readonly string[];
  revokedNonces?: ReadonlySet<string>;
}): Promise<ExternalAttestationCatalog> {
  if (input.attestations.length < 1 || input.attestations.length > 50) {
    throw new Error("An external-attestation catalog requires 1–50 entries.");
  }
  const verified = input.attestations.map((value) => verifySignedExternalAttestation(value, {
    trustedIssuerPublicKeys: input.trustedIssuerPublicKeys,
  })).filter(({ attestation }) => !input.revokedNonces
    || ![...input.revokedNonces].some((nonce) => BigInt(nonce) === BigInt(attestation.nonce)));
  if (verified.length === 0) throw new Error("The attestation catalog has no approved, non-revoked entries.");
  const nonces = new Set<string>();
  const commitments = new Set<string>();
  for (const value of verified) {
    const nonce = BigInt(value.attestation.nonce).toString();
    const commitment = BigInt(value.commitment).toString();
    if (nonces.has(nonce) || commitments.has(commitment)) {
      throw new Error("The attestation catalog contains a duplicate nonce or commitment.");
    }
    nonces.add(nonce);
    commitments.add(commitment);
  }
  const committer = await createProofCommitter();
  const leaves = verified.map(({ commitment }) => committer.proofExternalAttestationLeaf(commitment));
  const root = committer.buildProofFixedMerkleRoot(leaves);
  return {
    root,
    entries: verified.map((signed, index) => {
      const opening = committer.buildProofFixedMerkleMembership(leaves, index);
      return { signed, leaf: opening.leaf, siblings: opening.siblings, pathBits: opening.pathBits };
    }),
  };
}

/** Creates the portable issuer package imported by the PAYO payroll composer. */
export function createExternalAttestationProofPackage(input: {
  agreementId: string;
  catalog: ExternalAttestationCatalog;
  entryIndex: number;
}): ExternalAttestationProofPackage {
  const entry = input.catalog.entries[input.entryIndex];
  if (!entry) throw new Error("External attestation package selects a missing catalog entry.");
  return externalAttestationProofPackageSchema.parse({
    packageVersion: PAYO_EXTERNAL_ATTESTATION_PACKAGE_VERSION,
    agreementId: input.agreementId,
    catalogRoot: input.catalog.root,
    signed: entry.signed,
    siblings: entry.siblings,
    pathBits: entry.pathBits,
  });
}

/**
 * Verifies the issuer signature and reconstructs the exact fixed-depth catalog
 * root before any package can enter an encrypted prover request.
 */
export async function openExternalAttestationProofPackage(
  input: unknown,
): Promise<ExternalAttestationProofPackage> {
  const parsed = externalAttestationProofPackageSchema.parse(input);
  const signed = verifySignedExternalAttestation(parsed.signed);
  if (signed.attestation.factMask !== PAYO_EXTERNAL_ATTESTATION_ALL_FACTS) {
    throw new Error("External attestation must cover residency, employment and tax status.");
  }
  const committer = await createProofCommitter();
  let current = committer.proofExternalAttestationLeaf(signed.commitment);
  for (const [level, sibling] of parsed.siblings.entries()) {
    current = parsed.pathBits[level]
      ? committer.proofMerkleNode(sibling, current)
      : committer.proofMerkleNode(current, sibling);
  }
  if (BigInt(current) !== BigInt(parsed.catalogRoot)) {
    throw new Error("External attestation membership does not reconstruct its catalog root.");
  }
  return { ...parsed, signed };
}
