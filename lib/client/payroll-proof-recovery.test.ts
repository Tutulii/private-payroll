import { describe, expect, it } from "vitest";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { encryptedPayrollProofPayloadSchema } from "./payroll-proof-recovery";

const fixedWidth = (value: bigint) => `0x${value.toString(16).padStart(64, "0")}`;

function legacyPublicInputs(shardIndex: 0 | 1) {
  const names = [
    "chainId", "sealAddress", "proofVersion", "schemaVersion",
    "agreementRootHigh", "agreementRootLow", "manifestRootHigh", "manifestRootLow",
    "policyRootHigh", "policyRootLow", "fxRootHigh", "fxRootLow",
    "runNullifierHigh", "runNullifierLow", "validityStart", "validityExpiry",
    "shardIndex",
  ] as const;
  return Object.fromEntries(names.map((name, index) => [
    name,
    fixedWidth(name === "proofVersion"
      ? 2n
      : name === "schemaVersion"
        ? 1n
        : name === "shardIndex"
          ? BigInt(shardIndex)
          : BigInt(index + 1)),
  ]));
}

function legacyPayload() {
  return {
    schemaVersion: 1,
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
    verificationKeySha256: ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
    provingTimeMs: 1,
    shards: ([0, 1] as const).map((shardIndex) => ({
      shardIndex,
      proofBase64: "AA==",
      proofCalldata: Array.from({ length: 35 }, () => "0x1"),
      calldataHash: "0x1",
      publicInputs: legacyPublicInputs(shardIndex),
    })),
  };
}

describe("stored payroll proof recovery compatibility", () => {
  it("reopens fixed-width bb.js public inputs as the canonical durable ABI", () => {
    const parsed = encryptedPayrollProofPayloadSchema.parse(legacyPayload());

    expect(parsed.shards[0].publicInputs).toMatchObject({
      chainId: "0x1",
      sealAddress: "0x2",
      proofVersion: "2",
      schemaVersion: "1",
      agreementRootHigh: "5",
      validityExpiry: "16",
      shardIndex: "0",
    });
    expect(parsed.shards[1].publicInputs.shardIndex).toBe("1");
  });

  it("still rejects a non-numeric public input", () => {
    const payload = legacyPayload();
    payload.shards[0].publicInputs.agreementRootHigh = "not-a-field";
    expect(() => encryptedPayrollProofPayloadSchema.parse(payload)).toThrow();
  });
});
