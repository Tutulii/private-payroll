import { describe, expect, it } from "vitest";
import { generateVaultPrincipal } from "./vault";
import { deriveClaimCapabilitySecret } from "./claim-capability";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";

describe("worker claim capability", () => {
  it("is deterministic, domain-bound to the principal, and never public", () => {
    const principal = generateVaultPrincipal("worker-one");
    const secret = deriveClaimCapabilitySecret(principal);
    expect(secret).toMatch(/^0x[0-9a-f]{64}$/);
    expect(deriveClaimCapabilitySecret(principal)).toBe(secret);
    expect(claimCapabilityCommitmentV2(secret)).not.toBe(secret);
    expect(deriveClaimCapabilitySecret({ ...principal, principalId: "worker-two" })).not.toBe(secret);
  });

  it("rejects a mismatched key pair", () => {
    const first = generateVaultPrincipal("worker-one");
    const second = generateVaultPrincipal("worker-two");
    expect(() => deriveClaimCapabilitySecret({ ...first, secretKey: second.secretKey })).toThrow(/do not match/i);
  });
});
