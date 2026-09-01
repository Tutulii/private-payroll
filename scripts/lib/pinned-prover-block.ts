const STARKNET_BLOCK_HASH_BOUND = 1n << 252n;
export const STARKNET_STORED_BLOCK_HASH_BUFFER = 10;
export const STARKNET_PROOF_SUBMISSION_MARGIN = 2;
export const STARKNET_PROOF_MATURITY_BLOCKS =
  STARKNET_STORED_BLOCK_HASH_BUFFER + STARKNET_PROOF_SUBMISSION_MARGIN;

export function proofMaturityBlock(proofFacts: readonly unknown[]): number {
  if (!Array.isArray(proofFacts) || proofFacts.length < 6) {
    throw new Error("The transaction prover returned incomplete proof facts.");
  }
  let baseBlock: bigint;
  try {
    baseBlock = BigInt(proofFacts[4] as string | number | bigint);
  } catch {
    throw new Error("The transaction prover returned an invalid proof block number.");
  }
  if (baseBlock < 0n || baseBlock > BigInt(Number.MAX_SAFE_INTEGER - STARKNET_PROOF_MATURITY_BLOCKS)) {
    throw new Error("The transaction prover returned an invalid proof block number.");
  }
  pinnedProverBlockHash(proofFacts[5]);
  return Number(baseBlock) + STARKNET_PROOF_MATURITY_BLOCKS;
}

export function pinnedProverBlockHash(value: unknown): { block_hash: `0x${string}` } {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) {
    throw new Error("The discovery service returned a malformed Starknet block hash.");
  }
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed >= STARKNET_BLOCK_HASH_BOUND) {
    throw new Error("The discovery service returned an out-of-range Starknet block hash.");
  }
  return { block_hash: `0x${parsed.toString(16)}` };
}
