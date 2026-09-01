import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { RpcProvider } from "starknet";
import {
  derivePolicyOwnerPublicKey,
  readPolicyAccountActivationSnapshot,
} from "./direct-privacy-account-activation";

const encodedPolicy = [
  "0x1", "0x0", "0x333", "0x999", "0xaaa", "0x0", "0x1", "0x1",
  "0x12", "0x34", "0x444", "0x555", "0x666", "0x777", "0x888",
  "0x3e8", "0x7d0", "0x258", "0x2", "0x4", "0x3e8", "0x0", "0x0",
];

function provider(activeResult = ["0x1"]) {
  const observed: Array<{ entrypoint: string; block: unknown }> = [];
  return {
    observed,
    value: {
      getBlock: async (block: unknown) => {
        expect(block).toBe("latest");
        return { block_hash: "0xdef", block_number: 42, timestamp: 1_500 };
      },
      getChainId: async () => "0x534e5f5345504f4c4941",
      getClassHashAt: async (address: string, block: unknown) => {
        expect(address).toBe("0x111");
        expect(block).toBe("0xdef");
        return "0xabc";
      },
      callContract: async (call: { entrypoint: string }, block: unknown) => {
        observed.push({ entrypoint: call.entrypoint, block });
        if (call.entrypoint === "get_policy") return encodedPolicy;
        if (call.entrypoint === "is_policy_active") return activeResult;
        if (call.entrypoint === "is_policy_account_paused") return ["0x0"];
        throw new Error("unexpected call");
      },
    } as unknown as RpcProvider,
  };
}

describe("direct privacy policy-account chain reader", () => {
  it("pins class and every policy read to one exact block hash", async () => {
    const rpc = provider();
    const snapshot = await readPolicyAccountActivationSnapshot({
      provider: rpc.value,
      policyAccountAddress: "0x111",
      policyId: "0x222",
    });
    expect(snapshot).toMatchObject({
      classHash: "0xabc",
      blockNumber: 42n,
      blockHash: "0xdef",
      blockTimestamp: 1_500n,
      active: true,
      paused: false,
    });
    expect(rpc.observed).toEqual([
      { entrypoint: "get_policy", block: "0xdef" },
      { entrypoint: "is_policy_active", block: "0xdef" },
      { entrypoint: "is_policy_account_paused", block: "0xdef" },
    ]);
  });

  it("keeps owner secrets and fee-relayer fallbacks outside the web activation boundary", () => {
    const source = readFileSync(
      new URL("../../app/api/v1/direct-privacy-accounts/[id]/activation/route.ts", import.meta.url),
      "utf8",
    );
    expect(source).toContain("PolicyOwnerSignerClient.fromEnvironment()");
    expect(source).not.toMatch(/OWNER_PRIVATE_KEY|PROOF_RELAYER_PRIVATE_KEY|new Account\s*\(/);
  });

  it("fails closed on a non-Cairo boolean", async () => {
    const rpc = provider(["0x2"]);
    await expect(readPolicyAccountActivationSnapshot({
      provider: rpc.value,
      policyAccountAddress: "0x111",
      policyId: "0x222",
    })).rejects.toThrow("invalid Cairo boolean");
  });

  it("derives and validates the exact Stark owner public key", () => {
    expect(derivePolicyOwnerPublicKey("0x1")).toBe(
      "0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
    );
    expect(() => derivePolicyOwnerPublicKey("0x0")).toThrow("policy owner key is invalid");
    expect(() => derivePolicyOwnerPublicKey("not-a-key")).toThrow("policy owner key is invalid");
  });
});
