import { describe, expect, it } from "vitest";
import { PAYROLL_INTEGRITY_CIRCUIT_SHA256 } from "./protocol";
import { decodeRemoteProofResponse, remoteProofResponseSchema } from "./remote-prover";

const publicInputs = {
  chainId: "1",
  sealAddress: "2",
  proofVersion: "1",
  schemaVersion: "1",
  agreementRootHigh: "3",
  agreementRootLow: "4",
  manifestRootHigh: "5",
  manifestRootLow: "6",
  policyRootHigh: "7",
  policyRootLow: "8",
  fxRootHigh: "9",
  fxRootLow: "10",
  runNullifierHigh: "11",
  runNullifierLow: "12",
  validityStart: "13",
  validityExpiry: "14",
  shardIndex: "0",
};

function responseWithHash(calldataHash: string) {
  return {
    version: 1,
    type: "proof-complete",
    requestId: "remote-proof-regression",
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    provingTimeMs: 1,
    shards: ([0, 1] as const).map((shardIndex) => ({
      shardIndex,
      proofBase64: "AA==",
      proofCalldata: ["0x1"],
      calldataHash,
      publicInputs: { ...publicInputs, shardIndex: shardIndex.toString() },
    })),
  };
}

describe("remote payroll prover response", () => {
  it("accepts the canonical variable-length Starknet felt returned for calldata hashes", () => {
    const calldataHash = "0x43e808ebc10232b8b641d1599fa83fa8b525f457767a4f70e697708fecbcbf9";
    expect(() => remoteProofResponseSchema.parse(responseWithHash(calldataHash))).not.toThrow();
    expect(decodeRemoteProofResponse(responseWithHash(calldataHash)).shards[0].calldataHash)
      .toBe(calldataHash);
  });

  it("rejects a non-canonical felt with a leading zero", () => {
    expect(() => remoteProofResponseSchema.parse(responseWithHash("0x01"))).toThrow();
  });
});
