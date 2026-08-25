import { keccak_256 } from "@noble/hashes/sha3.js";
import { stableJson, toHex, utf8 } from "./encoding";

/** Canonical operational digest. This never substitutes for a protocol commitment domain. */
export function hashCanonicalJson(value: unknown): `0x${string}` {
  return toHex(keccak_256(utf8(stableJson(value))));
}
