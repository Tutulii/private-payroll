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

  it("builds a line opening that reconstructs the fixed manifest root", () => {
    const leaves = [
      committer.proofHash(9n, [1n]),
      committer.proofHash(9n, [2n]),
      committer.proofHash(9n, [3n]),
    ];
    const opening = committer.buildProofFixedMerkleMembership(leaves, 1);
    let current = opening.leaf;
    for (const [level, sibling] of opening.siblings.entries()) {
      current = opening.pathBits[level]
        ? committer.proofMerkleNode(sibling, current)
        : committer.proofMerkleNode(current, sibling);
    }
    expect(current).toBe(opening.root);
    expect(opening.root).toBe(committer.buildProofFixedMerkleRoot(leaves));
    expect(() => committer.buildProofFixedMerkleMembership(leaves, 3)).toThrow(/real manifest leaf/);
  });

  it("builds distinct catalog memberships that reconstruct one shared root", () => {
    const commitments = [`0x${"11".repeat(32)}`, `0x${"22".repeat(32)}`];
    const catalog = committer.buildProofCatalog(commitments);
    for (const [entryIndex, commitment] of commitments.entries()) {
      let current = committer.proofCatalogLeaf(commitment);
      for (const [level, sibling] of catalog.memberships[entryIndex].siblings.entries()) {
        current = catalog.memberships[entryIndex].pathBits[level]
          ? committer.proofMerkleNode(sibling, current)
          : committer.proofMerkleNode(current, sibling);
      }
      expect(current).toBe(catalog.root);
    }
    expect(() => committer.buildProofCatalog([commitments[0], commitments[0]]))
      .toThrow("unique");
  });
});
