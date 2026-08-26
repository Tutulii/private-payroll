import { splitHashToU128 } from "@/lib/crypto/commitments";
import { encodeAdvancedObligation } from "@/lib/domain/advanced-obligation-commitment";
import type { EmploymentAgreement } from "@/lib/domain/obligations";
import { createProofCommitter, PAYO_PROOF_DOMAIN_ADVANCED_PLAN } from "./commitments";

const TWO_POW_64 = 1n << 64n;
const TWO_POW_120 = 1n << 120n;

function limbs(value: string): [bigint, bigint] {
  const split = splitHashToU128(value);
  return [split.high, split.low];
}

function packAmountPair(left: bigint, right: bigint): bigint {
  if (left < 0n || right < 0n || left >= TWO_POW_120 || right >= TWO_POW_120) {
    throw new Error("Advanced obligation amount exceeds the proof packing limit.");
  }
  return left + right * TWO_POW_120;
}

/**
 * Circuit-internal Poseidon2 commitment. The encrypted record can retain the
 * external Keccak commitment, while PayrollIntegrity binds this proof-native
 * value into its authoritative agreement leaf.
 */
export async function advancedPlanProofCommitment(
  agreement: EmploymentAgreement,
): Promise<`0x${string}`> {
  const encoded = encodeAdvancedObligation(agreement);
  const metadata = 1n
    + BigInt(encoded.kind) * (1n << 8n)
    + BigInt(encoded.cadence) * (1n << 16n)
    + BigInt(encoded.flags) * (1n << 24n)
    + BigInt(encoded.occurrence) * (1n << 32n)
    + BigInt(encoded.releaseSequence) * (1n << 64n)
    + BigInt(encoded.checkpointSequence) * (1n << 96n)
    + BigInt(encoded.minimumCheckpointSeconds) * (1n << 128n);
  const fields = [
    metadata,
    ...Array.from({ length: 6 }, (_, index) =>
      encoded.timestamps[index * 2] + encoded.timestamps[index * 2 + 1] * TWO_POW_64),
    ...Array.from({ length: 5 }, (_, index) =>
      packAmountPair(encoded.amounts[index * 2], encoded.amounts[index * 2 + 1])),
    BigInt(encoded.requiredMask) + BigInt(encoded.includedMask) * 256n,
    ...encoded.commitments.flatMap(limbs),
    ...limbs(encoded.salt),
  ];
  return (await createProofCommitter()).proofHash(PAYO_PROOF_DOMAIN_ADVANCED_PLAN, fields);
}
