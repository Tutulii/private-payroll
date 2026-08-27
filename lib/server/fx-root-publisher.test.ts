import { describe, expect, it, vi } from "vitest";
import type { Call } from "starknet";
import { isFxRootActive, verifyFxPublicationProof } from "./fx-root-publisher";

const root = `0x${"12".repeat(32)}`;
const seal = "0x456";
const chainId = "0x123";
const verifier = "0x789";

function verifierResult(shardIndex: number, overrides: Partial<Record<number, bigint>> = {}) {
  const rootValue = BigInt(root);
  const inputs = [
    BigInt(chainId), BigInt(seal), 2n, 1n,
    1n, 2n, 3n, 4n, 5n, 6n,
    rootValue >> 128n, rootValue & ((1n << 128n) - 1n),
    7n, 8n, 900n, 1_500n, BigInt(shardIndex),
  ].map((value, index) => overrides[index] ?? value);
  return ["0x0", "0x11", ...inputs.flatMap((value) => [
    `0x${(value & ((1n << 128n) - 1n)).toString(16)}`,
    `0x${(value >> 128n).toString(16)}`,
  ])];
}

describe("FX root proof authorization", () => {
  it("accepts two verifier-checked shards bound to the configured root", async () => {
    const callContract = vi.fn(async (call: Call) => {
      if (call.entrypoint === "is_verifier_valid") return ["0x1"];
      if (call.entrypoint === "get_verifier") return [verifier];
      if (call.entrypoint === "verify_payroll_integrity_shard") {
        return verifierResult((call.calldata as string[] | undefined)?.at(-1) === "0xb" ? 1 : 0);
      }
      throw new Error("unexpected call");
    });
    const result = await verifyFxPublicationProof({
      rpc: {
        getBlockNumber: async () => 10,
        getBlockTimestamp: async () => 1_000,
        callContract,
      },
      deployment: { chainId, sealAddress: seal },
      policyRegistryAddress: "0xabc",
      catalogRoot: root,
      proofVersion: 2,
      shards: [["0xa"], ["0xb"]],
    });
    expect(result).toMatchObject({ blockNumber: 10, blockTimestamp: 1_000, verifierAddress: verifier });
  });

  it("rejects a valid-looking proof response bound to another FX root", async () => {
    const callContract = vi.fn(async (call: Call) => {
      if (call.entrypoint === "is_verifier_valid") return ["0x1"];
      if (call.entrypoint === "get_verifier") return [verifier];
      if (call.entrypoint === "verify_payroll_integrity_shard") {
        const shard = (call.calldata as string[] | undefined)?.at(-1) === "0xb" ? 1 : 0;
        return verifierResult(shard, { 10: 99n });
      }
      throw new Error("unexpected call");
    });
    await expect(verifyFxPublicationProof({
      rpc: { getBlockNumber: async () => 10, getBlockTimestamp: async () => 1_000, callContract },
      deployment: { chainId, sealAddress: seal },
      policyRegistryAddress: "0xabc",
      catalogRoot: root,
      proofVersion: 2,
      shards: [["0xa"], ["0xb"]],
    })).rejects.toThrow("not bound");
  });

  it("reads an already-active root idempotently", async () => {
    await expect(isFxRootActive({
      rpc: { callContract: async () => ["0x1"] },
      policyRegistryAddress: "0xabc",
      catalogRoot: root,
    })).resolves.toBe(true);
  });
});
