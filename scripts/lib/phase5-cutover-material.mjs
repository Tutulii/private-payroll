import { randomBytes } from "node:crypto";
import { ec, hash, num, shortString, validateAndParseAddress } from "starknet";

const CURVE_ORDER = ec.starkCurve.CURVE.n;

function canonicalScalar(value, label, maximum = CURVE_ORDER - 1n) {
  let scalar;
  try { scalar = BigInt(value); } catch { throw new Error(`${label} is not a Stark scalar.`); }
  if (scalar <= 0n || scalar > maximum) throw new Error(`${label} is outside the supported range.`);
  return num.toHex(scalar);
}

function canonicalAddress(value, label) {
  try {
    const address = BigInt(validateAndParseAddress(value));
    if (address === 0n) throw new Error("zero");
    return num.toHex(address);
  } catch {
    throw new Error(`${label} is not a canonical Starknet address.`);
  }
}

function randomScalar(maximum) {
  for (let attempt = 0; attempt < 256; attempt += 1) {
    const candidate = BigInt(`0x${randomBytes(32).toString("hex")}`);
    if (candidate > 0n && candidate <= maximum) return num.toHex(candidate);
  }
  throw new Error("Secure randomness did not produce an in-range Stark scalar.");
}

export function derivePhase5CutoverMaterial(input) {
  const policyAccountAddress = canonicalAddress(input.policyAccountAddress, "Policy account");
  const currentOwnerPublicKey = canonicalScalar(input.currentOwnerPublicKey, "Current owner public key");
  const ownerPrivateKey = canonicalScalar(input.ownerPrivateKey, "New owner private key");
  const viewingKey = canonicalScalar(input.viewingKey, "Treasury viewing key", CURVE_ORDER / 2n);
  if (BigInt(ownerPrivateKey) === BigInt(viewingKey)) {
    throw new Error("Owner and treasury-viewing keys must be distinct.");
  }
  if (Buffer.byteLength(input.signerSecret ?? "") < 32) {
    throw new Error("The signer HMAC secret must contain at least 32 bytes.");
  }
  const ownerPublicKey = num.toHex(BigInt(ec.starkCurve.getStarkKey(ownerPrivateKey)));
  const viewingPublicKey = num.toHex(BigInt(ec.starkCurve.getStarkKey(viewingKey)));
  const acceptanceDigest = num.toHex(hash.computePoseidonHashOnElements([
    shortString.encodeShortString("StarkNet Message"),
    shortString.encodeShortString("accept_ownership"),
    policyAccountAddress,
    currentOwnerPublicKey,
  ]));
  const acceptanceSignature = ec.starkCurve.sign(acceptanceDigest, ownerPrivateKey);
  return {
    policyAccountAddress,
    currentOwnerPublicKey,
    ownerPrivateKey,
    ownerPublicKey,
    viewingKey,
    viewingPublicKey,
    signerSecret: input.signerSecret,
    acceptanceDigest,
    acceptanceSignature: {
      r: num.toHex(acceptanceSignature.r),
      s: num.toHex(acceptanceSignature.s),
    },
  };
}

export function generatePhase5CutoverMaterial(input) {
  return derivePhase5CutoverMaterial({
    policyAccountAddress: input.policyAccountAddress,
    currentOwnerPublicKey: input.currentOwnerPublicKey,
    ownerPrivateKey: randomScalar(CURVE_ORDER - 1n),
    viewingKey: randomScalar(CURVE_ORDER / 2n),
    signerSecret: randomBytes(48).toString("base64url"),
  });
}
