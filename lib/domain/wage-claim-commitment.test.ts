import { describe, expect, it } from "vitest";
import { wageClaimNullifier } from "./wage-claim-commitment";

describe("canonical wage-claim nullifier", () => {
  const input = {
    originalRunNullifier: `0x${"01".repeat(32)}`,
    disputedManifestRoot: `0x${"02".repeat(32)}`,
    agreementLeaf: `0x${"03".repeat(32)}`,
    claimKind: "below_committed_floor" as const,
    shortfallAtomic: 4n,
    claimSalt: `0x${"05".repeat(32)}`,
  };

  it("is deterministic and binds every private claim field", () => {
    const commitment = wageClaimNullifier(input);
    expect(commitment).toBe("0xc9462209fd700c373f134f11d04f2a52e98cf177ee68bdbbccd091a3c7029db4");
    expect(commitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(wageClaimNullifier(input)).toBe(commitment);
    expect(wageClaimNullifier({ ...input, shortfallAtomic: 5n })).not.toBe(commitment);
    expect(wageClaimNullifier({ ...input, claimKind: "missing_obligation" })).not.toBe(commitment);
    expect(wageClaimNullifier({ ...input, claimSalt: `0x${"06".repeat(32)}` })).not.toBe(commitment);
  });

  it("rejects zero and overflowing shortfalls", () => {
    expect(() => wageClaimNullifier({ ...input, shortfallAtomic: 0n })).toThrow(/positive u128/);
    expect(() => wageClaimNullifier({ ...input, shortfallAtomic: 1n << 128n })).toThrow(/positive u128/);
  });
});
