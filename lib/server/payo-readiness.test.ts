import { describe, expect, it, vi } from "vitest";
import { STRK20_MAINNET_POOL_ADDRESS } from "@/lib/starknet/deployment";
import { checkPayoDeploymentReadiness, type PayoReadinessRpc } from "./payo-readiness";

const sealAddress = "0x123";
const catalogAddress = "0x456";
const obligationAddress = "0x789";
const verifierAddress = "0xabc";
const root = `0x${"11".repeat(32)}`;

function rpc(overrides: Partial<Record<string, string>> = {}): PayoReadinessRpc {
  return {
    getChainId: vi.fn().mockResolvedValue("0x1"),
    getBlockNumber: vi.fn().mockResolvedValue(900),
    callContract: vi.fn().mockImplementation((call, blockIdentifier) => {
      expect(blockIdentifier).toBe(900);
      const responses: Record<string, string> = {
        get_pool: STRK20_MAINNET_POOL_ADDRESS,
        get_catalog_registry: catalogAddress,
        get_obligation_registry: obligationAddress,
        is_policy_root_valid: "0x1",
        is_fx_root_valid: "0x1",
        is_obligation_root_valid: "0x1",
        is_verifier_valid: "0x1",
        get_verifier: verifierAddress,
        ...overrides,
      };
      return Promise.resolve([responses[call.entrypoint]]);
    }),
  };
}

const request = {
  chainId: "0x1",
  sealAddress,
  mode: 0 as const,
  proofVersion: 1,
  agreementRoot: root,
  policyRoot: root,
  fxRoot: root,
};

describe("PAYO deployment readiness", () => {
  it("pins every registry read to one block and accepts only the canonical pool", async () => {
    const result = await checkPayoDeploymentReadiness({
      request,
      deployment: { chainId: "0x1", sealAddress },
      rpc: rpc(),
    });
    expect(result.ready).toBe(true);
    expect(result.blockNumber).toBe(900);
    expect(result.verifierAddress).toBe(verifierAddress);
    expect(result.checks).toHaveLength(7);
  });

  it("fails closed when one proof root is inactive", async () => {
    const result = await checkPayoDeploymentReadiness({
      request,
      deployment: { chainId: "0x1", sealAddress },
      rpc: rpc({ is_fx_root_valid: "0x0" }),
    });
    expect(result.ready).toBe(false);
    expect(result.checks.find(({ code }) => code === "fx_root")).toMatchObject({ ready: false });
  });

  it("fails closed on an RPC/deployment chain mismatch", async () => {
    const mismatched = rpc();
    mismatched.getChainId = vi.fn().mockResolvedValue("0x2");
    const result = await checkPayoDeploymentReadiness({
      request,
      deployment: { chainId: "0x1", sealAddress },
      rpc: mismatched,
    });
    expect(result.ready).toBe(false);
    expect(result.checks.find(({ code }) => code === "chain")).toMatchObject({ ready: false });
  });
});
