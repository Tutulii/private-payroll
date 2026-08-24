import { beforeAll, describe, expect, it } from "vitest";
import { createProofCommitter, PAYO_PROOF_EMPTY_LEAF } from "./commitments";

describe("PAYO circuit-internal proof commitments", () => {
  let committer: Awaited<ReturnType<typeof createProofCommitter>>;

  beforeAll(async () => {
    committer = await createProofCommitter();
  });

  it("matches the Noir Poseidon2 fixed-sponge vectors", () => {
    expect(committer.proofHash(1n, [])).toBe(PAYO_PROOF_EMPTY_LEAF);
    expect(committer.proofHash(7n, [11n, 13n])).toBe(
      "0x1c7467e229cb2aadc6793686c07a90a4b96f2ee7c6b557e3c6ef5d92f1fa253c",
    );
  });

  it("uses a fixed 64-leaf tree and rejects more than 50 real leaves", () => {
    const root = committer.buildProofFixedMerkleRoot([PAYO_PROOF_EMPTY_LEAF]);
    expect(root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(() =>
      committer.buildProofFixedMerkleRoot(
        Array(51).fill(PAYO_PROOF_EMPTY_LEAF),
      ),
    ).toThrow("at most 50");
  });
});
