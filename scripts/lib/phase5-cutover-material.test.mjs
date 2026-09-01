import { describe, expect, it } from "vitest";
import { ec, hash, shortString } from "starknet";
import { derivePhase5CutoverMaterial } from "./phase5-cutover-material.mjs";

const POLICY_ACCOUNT = "0x656928a6f3aeb62c2e62ff7457d351a41ed987ceed07c514539165662ecb7e0";
const CURRENT_OWNER = "0x6e3e81271a762ead3ac1efc8c1193397882a7851f10ce7deea7ec83433da8ef";

describe("Phase 5 cutover material", () => {
  it("derives distinct owner/viewing identities and a valid owner-acceptance signature", () => {
    const material = derivePhase5CutoverMaterial({
      policyAccountAddress: POLICY_ACCOUNT,
      currentOwnerPublicKey: CURRENT_OWNER,
      ownerPrivateKey: "0x123456",
      viewingKey: "0x789abc",
      signerSecret: "x".repeat(32),
    });
    expect(material.ownerPublicKey).toBe(`0x${BigInt(ec.starkCurve.getStarkKey("0x123456")).toString(16)}`);
    expect(material.viewingPublicKey).toBe(`0x${BigInt(ec.starkCurve.getStarkKey("0x789abc")).toString(16)}`);
    const digest = hash.computePoseidonHashOnElements([
      shortString.encodeShortString("StarkNet Message"),
      shortString.encodeShortString("accept_ownership"),
      POLICY_ACCOUNT,
      CURRENT_OWNER,
    ]);
    const signature = new ec.starkCurve.Signature(
      BigInt(material.acceptanceSignature.r),
      BigInt(material.acceptanceSignature.s),
    );
    const x = BigInt(material.ownerPublicKey).toString(16).padStart(64, "0");
    expect(["02", "03"].some((prefix) => ec.starkCurve.verify(signature, digest, `${prefix}${x}`))).toBe(true);
  });

  it("rejects reused keys, short HMAC secrets, and invalid accounts", () => {
    const base = {
      policyAccountAddress: POLICY_ACCOUNT,
      currentOwnerPublicKey: CURRENT_OWNER,
      ownerPrivateKey: "0x123456",
      viewingKey: "0x789abc",
      signerSecret: "x".repeat(32),
    };
    expect(() => derivePhase5CutoverMaterial({ ...base, viewingKey: base.ownerPrivateKey })).toThrow(/distinct/);
    expect(() => derivePhase5CutoverMaterial({ ...base, signerSecret: "short" })).toThrow(/32 bytes/);
    expect(() => derivePhase5CutoverMaterial({ ...base, policyAccountAddress: "0x0" })).toThrow(/canonical/);
  });
});
