import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { mapPayrollPublicInputs, type PayrollIntegrityShardProof } from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import {
  buildPayoSealedPayroll,
  buildVerifySealedShardCall,
  buildVerifySealedShardCalldataCall,
} from "./payo-seal";

const PUBLIC_INPUTS = [
  "0x1",
  "0x12345",
  "0x1",
  "0x1",
  "0x21ccf78b37818195a99011a0becd63c0",
  "0x2cd00396a065125a9fdbfa4fe694267f",
  "0x14bc023ba6616464d80762f3a3cd18cb",
  "0x402c1a1f63dcce95568decb9f442e19",
  "0x2268a0aded87d370810a4fa92f02dd24",
  "0xadf09af7b56c56d740df4ea601696b33",
  "0x1ed06ee71227267e051c4da3b3da51ea",
  "0xe7c38e7b0170fb183bbb36aa361d1049",
  "0x64142157a0d39df1051bf01190a707ef",
  "0x56c538e09b32afbef3ba098c37e630ba",
  "0x3f2",
  "0x7d0",
] as const;

function proof(shardIndex: 0 | 1): PayrollIntegrityShardProof {
  const proofCalldata = readFileSync(
    new URL(
      `../../contracts/integrity_verifier/tests/proof_calldata-shard-${shardIndex}.txt`,
      import.meta.url,
    ),
    "utf8",
  ).trim().split(/\s+/);
  return {
    shardIndex,
    proof: new Uint8Array(),
    proofCalldata,
    calldataHash: hashProofCalldata(proofCalldata),
    publicInputs: mapPayrollPublicInputs([...PUBLIC_INPUTS, `0x${shardIndex}`]),
  };
}

describe("PAYO sealed payroll Starknet calls", () => {
  it("builds the fixed-selector STRK20 action from two linked, hash-bound proofs", () => {
    const shards = [proof(0), proof(1)] as const;
    const sealed = buildPayoSealedPayroll({
      sealAddress: "0x12345",
      chainId: "0x1",
      shards,
      nowUnixSeconds: 1_500n,
    });

    expect(sealed.invokeAction.type).toBe("invoke");
    expect(BigInt(sealed.invokeAction.contract)).toBe(0x12345n);
    expect(sealed.invokeAction.calldata).toHaveLength(19);
    expect(sealed.invokeAction.calldata.slice(-4)).toEqual([
      "0x43e808ebc10232b8b641d1599fa83fa8b525f457767a4f70e697708fecbcbf9",
      "0x75174b257e0a37e992dbdae96d61d58b3d2feadcb3809e7dee01f9010bff51a",
      "0x0",
      "0x0",
    ]);
    expect(sealed.runNullifierHigh).toBe(PUBLIC_INPUTS[12]);
    expect(sealed.runNullifierLow).toBe(PUBLIC_INPUTS[13]);
  });

  it("builds each permissionless follow-up verification call with its Span length", () => {
    const shard = proof(1);
    const call = buildVerifySealedShardCall({
      sealAddress: "0x12345",
      runNullifierHigh: PUBLIC_INPUTS[12],
      runNullifierLow: PUBLIC_INPUTS[13],
      shard,
    });
    expect(call.entrypoint).toBe("verify_sealed_shard");
    expect(Array.isArray(call.calldata)).toBe(true);
    if (!Array.isArray(call.calldata)) throw new Error("Expected flattened calldata.");
    expect(call.calldata.slice(0, 4)).toEqual([
      PUBLIC_INPUTS[12],
      PUBLIC_INPUTS[13],
      "0x1",
      "0xc73",
    ]);
    expect(call.calldata).toHaveLength(3_191);

    expect(buildVerifySealedShardCalldataCall({
      sealAddress: "0x12345",
      runNullifierHigh: PUBLIC_INPUTS[12],
      runNullifierLow: PUBLIC_INPUTS[13],
      shardIndex: 1,
      proofCalldata: shard.proofCalldata,
      calldataHash: shard.calldataHash,
    })).toEqual(call);
  });

  it("fails closed on a wrong chain, expired proof, mismatched shard, or modified calldata", () => {
    const shardZero = proof(0);
    const shardOne = proof(1);
    expect(() => buildPayoSealedPayroll({
      sealAddress: "0x12345",
      chainId: "0x2",
      shards: [shardZero, shardOne],
      nowUnixSeconds: 1_500n,
    })).toThrow("different Starknet chain");
    expect(() => buildPayoSealedPayroll({
      sealAddress: "0x12345",
      chainId: "0x1",
      shards: [shardZero, shardOne],
      nowUnixSeconds: 2_001n,
    })).toThrow("not valid");

    shardOne.publicInputs = { ...shardOne.publicInputs, manifestRootLow: "0x99" };
    expect(() => buildPayoSealedPayroll({
      sealAddress: "0x12345",
      chainId: "0x1",
      shards: [shardZero, shardOne],
      nowUnixSeconds: 1_500n,
    })).toThrow("public input 7 does not match");

    const modified = proof(0);
    modified.proofCalldata[100] = "0x1";
    expect(() => buildVerifySealedShardCall({
      sealAddress: "0x12345",
      runNullifierHigh: PUBLIC_INPUTS[12],
      runNullifierLow: PUBLIC_INPUTS[13],
      shard: modified,
    })).toThrow("calldata hash does not match");
  });
});
