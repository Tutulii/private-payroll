import { describe, expect, it } from "vitest";
import {
  PAYO_PRIVATE_EXIT_QUOTE_VERSION,
  PAYO_PRIVATE_EXIT_ROUTE_ID,
  PRIVATE_EXIT_BOUNDARIES,
  sealPrivateExitQuote,
} from "@/lib/domain/private-exit";
import { STARKNET_MAINNET_CHAIN_ID } from "./deployment";
import {
  buildPrivateSwapActions,
  buildPublicWithdrawalAction,
  EKUBO_MAINNET_ROUTER_ADDRESS,
  PAYO_PRIVATE_STRK_USDC_POOL,
  STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
} from "./private-exit";
import { PAYROLL_TOKENS } from "./tokens";

const NOW = 1_800_000_000_000;
const EXECUTOR = "0x12345";

function quote() {
  return sealPrivateExitQuote({
    version: PAYO_PRIVATE_EXIT_QUOTE_VERSION,
    routeId: PAYO_PRIVATE_EXIT_ROUTE_ID,
    chainId: STARKNET_MAINNET_CHAIN_ID,
    privacyMode: "anonymous-swap-to-open-private-note",
    fromToken: "STRK",
    toToken: "USDC",
    amountInAtomic: "1000000000000000000",
    expectedOutAtomic: "27060",
    minimumOutAtomic: "26789",
    slippageBps: 100,
    priceImpact: 0.0005,
    quoteBlockNumber: 14_379_176,
    quoteBlockHash: `0x${"ab".repeat(32)}`,
    quotedAt: NOW,
    expiresAt: NOW + 45_000,
    executorAddress: EXECUTOR,
    executorClassHash: STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
    routerAddress: EKUBO_MAINNET_ROUTER_ADDRESS,
    pool: PAYO_PRIVATE_STRK_USDC_POOL,
    skipAhead: "0",
  });
}

describe("private STRK20 exit boundary", () => {
  it("builds exactly one withdraw, open output note and pinned anonymizer invocation", () => {
    const result = buildPrivateSwapActions({
      quote: quote(),
      privateRecipient: "0x777",
      now: NOW + 1_000,
    });
    expect(result.actions).toHaveLength(3);
    expect(result.actions[0]).toEqual({
      type: "withdraw",
      token: PAYROLL_TOKENS.STRK.address,
      amount: "0xde0b6b3a7640000",
      recipient: EXECUTOR,
    });
    expect(result.actions[1]).toEqual({
      type: "transfer",
      token: PAYROLL_TOKENS.USDC.address,
      amount: "OPEN",
      recipient: "0x777",
    });
    expect(result.actions[2]).toEqual({
      type: "invoke",
      contract: EXECUTOR,
      calldata: [
        EKUBO_MAINNET_ROUTER_ADDRESS,
        PAYROLL_TOKENS.STRK.address,
        "0xde0b6b3a7640000",
        "0x0",
        PAYO_PRIVATE_STRK_USDC_POOL.token0,
        PAYO_PRIVATE_STRK_USDC_POOL.token1,
        "0x20c49ba5e353f80000000000000000",
        "0x3e8",
        "0x0",
        "0x68a5",
        "0x0",
        "0x0",
        "${openNoteIds[0]}",
      ],
    });
  });

  it("rejects expired, mutated, foreign-router and foreign-pool quotes", () => {
    const valid = quote();
    expect(() => buildPrivateSwapActions({
      quote: valid,
      privateRecipient: "0x777",
      now: valid.expiresAt + 1,
    })).toThrow(/expired/i);
    expect(() => buildPrivateSwapActions({
      quote: { ...valid, minimumOutAtomic: "1" },
      privateRecipient: "0x777",
      now: NOW,
    })).toThrow(/commitment/i);

    const { routeCommitment, ...body } = valid;
    expect(routeCommitment).toMatch(/^0x[0-9a-f]{64}$/);
    const foreignRouter = sealPrivateExitQuote({
      ...body,
      routerAddress: "0x999",
    });
    expect(() => buildPrivateSwapActions({
      quote: foreignRouter,
      privateRecipient: "0x777",
      now: NOW,
    })).toThrow(/router/i);

    const foreignPool = sealPrivateExitQuote({
      ...body,
      pool: { ...body.pool, fee: "1" },
    });
    expect(() => buildPrivateSwapActions({
      quote: foreignPool,
      privateRecipient: "0x777",
      now: NOW,
    })).toThrow(/single-hop pool/i);
  });

  it("requires explicit public disclosure acknowledgement", () => {
    expect(() => buildPublicWithdrawalAction({
      token: "USDC",
      amount: "1.25",
      recipient: "0x999",
      acknowledgedPublicDisclosure: false,
    })).toThrow(/publicly linkable/i);
    expect(buildPublicWithdrawalAction({
      token: "USDC",
      amount: "1.25",
      recipient: "0x999",
      acknowledgedPublicDisclosure: true,
    })).toEqual({
      action: {
        type: "withdraw",
        token: PAYROLL_TOKENS.USDC.address,
        amount: "0x1312d0",
        recipient: "0x999",
      },
      amountAtomic: 1_250_000n,
    });
  });

  it("states the privacy boundary without promising privacy after public exit", () => {
    expect(PRIVATE_EXIT_BOUNDARIES.find((item) => item.kind === "private_swap"))
      .toMatchObject({ privacyPreserved: true, executable: true });
    expect(PRIVATE_EXIT_BOUNDARIES.find((item) => item.kind === "public_withdrawal"))
      .toMatchObject({ privacyPreserved: false, executable: true });
    expect(PRIVATE_EXIT_BOUNDARIES.find((item) => item.kind === "unsupported"))
      .toMatchObject({ privacyPreserved: false, executable: false });
  });
});
