import { describe, expect, it, vi } from "vitest";
import {
  readPrivateExitReadiness,
  quotePrivateExit,
} from "./private-exit-quote";
import {
  PAYO_PRIVATE_STRK_USDC_POOL,
  STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
} from "@/lib/starknet/private-exit";
import { STARKNET_MAINNET_CHAIN_ID } from "@/lib/starknet/deployment";

const EXECUTOR = "0x12345";
const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const environment = {
  STARKNET_RPC_URL: "https://rpc.example",
  PAYO_EKUBO_ANONYMIZER_ADDRESS: EXECUTOR,
};

function provider(overrides: Partial<{
  getBlock: (block: unknown) => Promise<unknown>;
  getChainId: () => Promise<string>;
  getClassHashAt: (address: string, block: unknown) => Promise<string>;
}> = {}) {
  return {
    getBlock: vi.fn(async (block: unknown) => ({
      block_number: typeof block === "number" ? block : 14_379_180,
      block_hash: BLOCK_HASH,
    })),
    getChainId: vi.fn(async () => STARKNET_MAINNET_CHAIN_ID),
    getClassHashAt: vi.fn(async () => STRK20_EKUBO_ANONYMIZER_CLASS_HASH),
    ...overrides,
  } as never;
}

function quotePayload() {
  return {
    block_number: 14_379_176,
    block_hash: BLOCK_HASH,
    total_calculated: "27060",
    estimated_gas_cost: 4_000_000,
    price_impact: 0.000535,
    splits: [{
      amount_specified: "1000000000000000000",
      amount_calculated: "27060",
      route: [{
        pool_key: {
          token0: PAYO_PRIVATE_STRK_USDC_POOL.token0,
          token1: PAYO_PRIVATE_STRK_USDC_POOL.token1,
          fee: PAYO_PRIVATE_STRK_USDC_POOL.fee,
          tick_spacing: Number(PAYO_PRIVATE_STRK_USDC_POOL.tickSpacing),
          extension: PAYO_PRIVATE_STRK_USDC_POOL.extension,
        },
        sqrt_ratio_limit: "0x1",
        skip_ahead: 0,
      }],
    }],
  };
}

function fetchQuote(payload = quotePayload()) {
  return vi.fn(async () => new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  })) as unknown as typeof fetch;
}

describe("private-exit production quote boundary", () => {
  it("stays disabled when no reviewed anonymizer instance is configured", async () => {
    await expect(readPrivateExitReadiness({
      environment: { STARKNET_RPC_URL: "https://rpc.example" },
      provider: provider(),
    })).resolves.toMatchObject({
      enabled: false,
      code: "ANONYMIZER_NOT_CONFIGURED",
      executorAddress: null,
    });
  });

  it("enables only an on-chain instance of the pinned official class", async () => {
    await expect(readPrivateExitReadiness({ environment, provider: provider() }))
      .resolves.toMatchObject({
        enabled: true,
        code: "READY",
        executorAddress: EXECUTOR,
        executorClassHash: STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
        verifiedBlockNumber: 14_379_180,
      });

    await expect(readPrivateExitReadiness({
      environment,
      provider: provider({ getClassHashAt: async () => "0x999" }),
    })).resolves.toMatchObject({
      enabled: false,
      code: "ANONYMIZER_NOT_VERIFIED",
      message: expect.stringMatching(/not the reviewed/i),
    });
  });

  it("returns a short-lived quote bound to a canonical single-hop block", async () => {
    const fetched = fetchQuote();
    const result = await quotePrivateExit({
      fromToken: "STRK",
      toToken: "USDC",
      amountAtomic: 1_000_000_000_000_000_000n,
      slippageBps: 100,
    }, {
      environment,
      provider: provider(),
      fetch: fetched,
      now: () => 1_800_000_000_000,
    });
    expect(fetched).toHaveBeenCalledWith(
      expect.stringContaining("/1000000000000000000/"),
      expect.objectContaining({ cache: "no-store" }),
    );
    expect(result).toMatchObject({
      fromToken: "STRK",
      toToken: "USDC",
      expectedOutAtomic: "27060",
      minimumOutAtomic: "26789",
      quoteBlockNumber: 14_379_176,
      executorAddress: EXECUTOR,
      pool: PAYO_PRIVATE_STRK_USDC_POOL,
    });
    expect(result.expiresAt - result.quotedAt).toBe(45_000);
    expect(result.routeCommitment).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("rejects split, substituted, stale and noncanonical quotes", async () => {
    const baseInput = {
      fromToken: "STRK" as const,
      toToken: "USDC" as const,
      amountAtomic: 1_000_000_000_000_000_000n,
      slippageBps: 100,
    };
    const split = quotePayload();
    split.splits.push(structuredClone(split.splits[0]));
    await expect(quotePrivateExit(baseInput, {
      environment, provider: provider(), fetch: fetchQuote(split),
    })).rejects.toThrow(/split or multihop/i);

    const substituted = quotePayload();
    (substituted.splits[0].route[0].pool_key as { fee: string }).fee = "1";
    await expect(quotePrivateExit(baseInput, {
      environment, provider: provider(), fetch: fetchQuote(substituted),
    })).rejects.toThrow(/outside PAYO/i);

    await expect(quotePrivateExit(baseInput, {
      environment,
      provider: provider({
        getBlock: async (block) => ({
          block_number: typeof block === "number" ? block : 14_379_220,
          block_hash: BLOCK_HASH,
        }),
      }),
      fetch: fetchQuote(),
    })).rejects.toThrow(/stale/i);

    await expect(quotePrivateExit(baseInput, {
      environment,
      provider: provider({
        getBlock: async (block) => ({
          block_number: typeof block === "number" ? block : 14_379_180,
          block_hash: `0x${"cd".repeat(32)}`,
        }),
      }),
      fetch: fetchQuote(),
    })).rejects.toThrow(/canonical Starknet block/i);
  });
});
