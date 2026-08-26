import { keccak_256 } from "@noble/hashes/sha3.js";
import { concatBytes, encodeUint, normalizedHexBytes, toHex, utf8 } from "@/lib/crypto/encoding";

export const wageClaimKinds = {
  missing_obligation: 0,
  below_committed_floor: 1,
  incomplete_final_pay: 2,
} as const;

export type WageClaimKind = keyof typeof wageClaimKinds;

export function wageClaimNullifier(input: {
  originalRunNullifier: string;
  disputedManifestRoot: string;
  agreementLeaf: string;
  claimKind: WageClaimKind;
  shortfallAtomic: bigint | string;
  claimSalt: string;
}): `0x${string}` {
  const shortfall = BigInt(input.shortfallAtomic);
  if (shortfall <= 0n || shortfall >= 1n << 128n) {
    throw new Error("A wage claim shortfall must fit in a positive u128.");
  }
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_WAGE_CLAIM_V1_BINARY"),
    normalizedHexBytes(input.originalRunNullifier, 32),
    normalizedHexBytes(input.disputedManifestRoot, 32),
    normalizedHexBytes(input.agreementLeaf, 32),
    Uint8Array.of(wageClaimKinds[input.claimKind]),
    encodeUint(shortfall, 16),
    normalizedHexBytes(input.claimSalt, 32),
  )));
}
