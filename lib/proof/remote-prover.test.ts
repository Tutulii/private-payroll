import { describe, expect, it } from "vitest";
import {
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
} from "./protocol";
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

function responseWithHash(calldataHash: string, calldataLength = 1) {
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
      proofCalldata: Array.from({ length: calldataLength }, (_, index) => `0x${(index + 1).toString(16)}`),
      calldataHash,
      publicInputs: { ...publicInputs, shardIndex: shardIndex.toString() },
    })),
  };
}

describe("remote payroll prover response", () => {
  it("accepts the canonical variable-length Starknet felt returned for calldata hashes", () => {
    const calldataHash = "0x43e808ebc10232b8b641d1599fa83fa8b525f457767a4f70e697708fecbcbf9";
    expect(() => remoteProofResponseSchema.parse(responseWithHash(calldataHash))).not.toThrow();
    const decoded = decodeRemoteProofResponse(responseWithHash(calldataHash));
    expect(decoded.type).toBe("proof-complete");
    if (decoded.type !== "proof-complete") throw new Error("Expected a payroll proof.");
    expect(decoded.shards[0].calldataHash).toBe(calldataHash);
  });

  it("rejects a non-canonical felt with a leading zero", () => {
    expect(() => remoteProofResponseSchema.parse(responseWithHash("0x01"))).toThrow();
  });

  it("accepts the exact Mainnet-safe calldata boundary", () => {
    expect(() => remoteProofResponseSchema.parse(responseWithHash("0x1", PAYO_MAX_PROOF_CALLDATA_FELTS))).not.toThrow();
  });

  it("rejects a proof that would exceed the Mainnet invoke limit after wrapper overhead", () => {
    expect(() => remoteProofResponseSchema.parse(responseWithHash("0x1", PAYO_MAX_PROOF_CALLDATA_FELTS + 1))).toThrow();
  });
});

describe("remote exception prover response", () => {
  it("decodes a single v6 proof without pretending it has payroll shards", () => {
    const response = {
      version: 2,
      type: "exception-proof-complete",
      requestId: "remote-exception-regression",
      profile: "wage_claim_v6",
      scheme: "ultra_keccak_zk_honk",
      circuitSha256: WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
      provingTimeMs: 12,
      proof: {
        proofBase64: "AA==",
        proofCalldata: Array.from({ length: 35 }, () => "0x1"),
        calldataHash: "0x1",
        publicInputs: {
          chainId: "1",
          sealAddress: "2",
          proofVersion: "6",
          schemaVersion: "2",
          agreementRootHigh: "3",
          agreementRootLow: "4",
          manifestRootHigh: "5",
          manifestRootLow: "6",
          policyRootHigh: "7",
          policyRootLow: "8",
          fxRootHigh: "9",
          fxRootLow: "10",
          subjectNullifierHigh: "11",
          subjectNullifierLow: "12",
          parentNullifierHigh: "13",
          parentNullifierLow: "14",
          factCommitmentHigh: "15",
          factCommitmentLow: "16",
          parentFactCommitmentHigh: "17",
          parentFactCommitmentLow: "18",
          validityStart: "19",
          validityExpiry: "20",
          shardIndex: "0",
        },
      },
    } as const;
    const decoded = decodeRemoteProofResponse(response);
    expect(decoded).toMatchObject({
      type: "exception-proof-complete",
      profile: "wage_claim_v6",
      proof: { calldataHash: "0x1", proof: new Uint8Array([0]) },
    });
  });

  it("rejects a vNext response missing its parent and fact bindings", () => {
    const decoded = {
      version: 2,
      type: "exception-proof-complete",
      requestId: "bad",
      profile: "wage_claim_v6",
      scheme: "ultra_keccak_zk_honk",
      circuitSha256: WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
      provingTimeMs: 1,
      proof: {
        proofBase64: "AA==",
        proofCalldata: Array.from({ length: 35 }, () => "0x1"),
        calldataHash: "0x1",
        publicInputs,
      },
    };
    expect(() => remoteProofResponseSchema.parse(decoded)).toThrow();
  });
});
