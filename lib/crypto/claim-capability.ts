import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { VaultPrincipalKeyPair } from "./vault";
import { fromBase64, toHex, utf8 } from "./encoding";

const CLAIM_CAPABILITY_SALT = utf8("PAYO_CLAIM_CAPABILITY_KDF_V2");

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

/**
 * Derives the worker-only claim capability from the recoverable X25519 vault
 * key. The derivation is domain-separated and never exposes or reuses the
 * X25519 scalar directly inside a proof.
 */
export function deriveClaimCapabilitySecret(
  principal: VaultPrincipalKeyPair,
): `0x${string}` {
  const secretKey = fromBase64(principal.secretKey);
  const publicKey = fromBase64(principal.publicKey);
  if (secretKey.length !== 32 || publicKey.length !== 32) {
    throw new Error("A claim identity requires a 32-byte X25519 vault key pair.");
  }
  const derivedPublicKey = x25519.getPublicKey(secretKey);
  if (!equalBytes(derivedPublicKey, publicKey)) {
    secretKey.fill(0);
    derivedPublicKey.fill(0);
    throw new Error("The claim identity public and secret keys do not match.");
  }
  try {
    const capability = hkdf(
      sha256,
      secretKey,
      CLAIM_CAPABILITY_SALT,
      utf8(`PAYO_CLAIM_CAPABILITY_SECRET_V2:${principal.principalId}`),
      32,
    );
    try {
      return toHex(capability);
    } finally {
      capability.fill(0);
    }
  } finally {
    secretKey.fill(0);
    derivedPublicKey.fill(0);
  }
}
