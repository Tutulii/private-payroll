import "server-only";

import { num, RpcProvider } from "starknet";
import { z } from "zod";
import {
  PAYO_PRIVATE_EXIT_QUOTE_VERSION,
  PAYO_PRIVATE_EXIT_ROUTE_ID,
  sealPrivateExitQuote,
  type PrivateExitQuote,
} from "@/lib/domain/private-exit";
import {
  EKUBO_MAINNET_CHAIN_ID_DECIMAL,
  EKUBO_MAINNET_CORE_ADDRESS,
  EKUBO_MAINNET_ROUTER_ADDRESS,
  PAYO_PRIVATE_STRK_USDC_POOL,
  PRIVATE_EXIT_MAX_QUOTE_BLOCK_LAG,
  PRIVATE_EXIT_QUOTE_TTL_MS,
  STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
} from "@/lib/starknet/private-exit";
import { STARKNET_MAINNET_CHAIN_ID } from "@/lib/starknet/deployment";
import { PAYROLL_TOKENS, type PayrollTokenSymbol } from "@/lib/starknet/tokens";

const EKUBO_QUOTER_ORIGIN = "https://prod-api-quoter.ekubo.org";
const QUOTER_TIMEOUT_MS = 8_000;
const feltSchema = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const decimalSchema = z.string().regex(/^(0|[1-9][0-9]{0,77})$/);

const rawPoolKeySchema = z.object({
  token0: feltSchema,
  token1: feltSchema,
  fee: decimalSchema,
  tick_spacing: z.number().int().positive(),
  extension: feltSchema,
}).strict();

const rawQuoteSchema = z.object({
  block_number: z.number().int().positive(),
  block_hash: feltSchema,
  total_calculated: decimalSchema,
  estimated_gas_cost: z.number().int().nonnegative(),
  price_impact: z.number().finite().min(0).max(1),
  splits: z.array(z.object({
    amount_specified: decimalSchema,
    amount_calculated: decimalSchema,
    route: z.array(z.object({
      pool_key: rawPoolKeySchema,
      sqrt_ratio_limit: feltSchema,
      skip_ahead: z.number().int().nonnegative(),
    }).strict()).min(1).max(8),
  }).strict()).min(1).max(8),
}).strict();

type PrivateExitProvider = Pick<RpcProvider, "getBlock" | "getChainId" | "getClassHashAt">;

export type PrivateExitReadiness = {
  enabled: boolean;
  code: "READY" | "ANONYMIZER_NOT_CONFIGURED" | "ANONYMIZER_NOT_VERIFIED";
  message: string;
  routeId: typeof PAYO_PRIVATE_EXIT_ROUTE_ID;
  executorAddress: string | null;
  executorClassHash: typeof STRK20_EKUBO_ANONYMIZER_CLASS_HASH;
  routerAddress: typeof EKUBO_MAINNET_ROUTER_ADDRESS;
  coreAddress: typeof EKUBO_MAINNET_CORE_ADDRESS;
  tokens: readonly ["STRK", "USDC"];
  verifiedBlockNumber: number | null;
  verifiedBlockHash: string | null;
};

type PrivateExitDependencies = {
  provider?: PrivateExitProvider;
  fetch?: typeof fetch;
  now?: () => number;
  environment?: Record<string, string | undefined>;
};

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

function canonicalFelt(value: string, label: string): `0x${string}` {
  try {
    const parsed = BigInt(value);
    if (parsed < 0n) throw new Error("negative");
    return num.toHex(parsed) as `0x${string}`;
  } catch {
    throw new Error(`${label} is not a canonical Starknet felt.`);
  }
}

function canonicalHash(value: string, label: string): `0x${string}` {
  const felt = canonicalFelt(value, label);
  const digits = felt.slice(2).padStart(64, "0");
  if (digits.length !== 64) throw new Error(`${label} is not a 32-byte hash.`);
  return `0x${digits}`;
}

function runtimeConfig(dependencies: PrivateExitDependencies) {
  const environment = dependencies.environment ?? process.env;
  const rpcUrl = environment.STARKNET_RPC_URL?.trim()
    || environment.NEXT_PUBLIC_STARKNET_RPC_URL?.trim();
  if (!rpcUrl) throw new Error("The Starknet Mainnet RPC is not configured.");
  const rawExecutor = environment.PAYO_EKUBO_ANONYMIZER_ADDRESS?.trim();
  if (!rawExecutor) return { rpcUrl, executorAddress: null };
  const executorAddress = canonicalFelt(rawExecutor, "PAYO Ekubo anonymizer address");
  if (BigInt(executorAddress) === 0n) {
    throw new Error("PAYO Ekubo anonymizer address cannot be zero.");
  }
  return { rpcUrl, executorAddress };
}

function providerFor(config: { rpcUrl: string }, dependencies: PrivateExitDependencies): PrivateExitProvider {
  return dependencies.provider ?? new RpcProvider({ nodeUrl: config.rpcUrl });
}

function acceptedBlock(value: unknown, label: string): { number: number; hash: `0x${string}` } {
  const block = value as { block_number?: unknown; block_hash?: unknown };
  if (!Number.isSafeInteger(block?.block_number) || Number(block.block_number) <= 0) {
    throw new Error(`${label} did not return an accepted block number.`);
  }
  if (typeof block.block_hash !== "string") {
    throw new Error(`${label} did not return an accepted block hash.`);
  }
  return {
    number: Number(block.block_number),
    hash: canonicalHash(block.block_hash, `${label} block hash`),
  };
}

async function verifyExecutorAtBlock(input: {
  provider: PrivateExitProvider;
  executorAddress: string;
  blockHash: string;
}): Promise<void> {
  const [chainId, classHash] = await Promise.all([
    input.provider.getChainId(),
    input.provider.getClassHashAt(input.executorAddress, input.blockHash),
  ]);
  if (!sameFelt(String(chainId), STARKNET_MAINNET_CHAIN_ID)) {
    throw new Error("The private-exit RPC is not connected to Starknet Mainnet.");
  }
  if (!sameFelt(String(classHash), STRK20_EKUBO_ANONYMIZER_CLASS_HASH)) {
    throw new Error("The configured private-exit executor is not the reviewed STRK20 Ekubo anonymizer class.");
  }
}

export async function readPrivateExitReadiness(
  dependencies: PrivateExitDependencies = {},
): Promise<PrivateExitReadiness> {
  const config = runtimeConfig(dependencies);
  const base = {
    routeId: PAYO_PRIVATE_EXIT_ROUTE_ID,
    executorClassHash: STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
    routerAddress: EKUBO_MAINNET_ROUTER_ADDRESS,
    coreAddress: EKUBO_MAINNET_CORE_ADDRESS,
    tokens: ["STRK", "USDC"] as const,
  };
  if (!config.executorAddress) {
    return {
      ...base,
      enabled: false,
      code: "ANONYMIZER_NOT_CONFIGURED",
      message: "Private swap is locked until a reviewed Mainnet anonymizer instance is configured and verified.",
      executorAddress: null,
      verifiedBlockNumber: null,
      verifiedBlockHash: null,
    };
  }
  try {
    const provider = providerFor(config, dependencies);
    const block = acceptedBlock(await provider.getBlock("latest"), "Starknet RPC");
    await verifyExecutorAtBlock({
      provider,
      executorAddress: config.executorAddress,
      blockHash: block.hash,
    });
    return {
      ...base,
      enabled: true,
      code: "READY",
      message: "The official STRK20 Ekubo anonymizer class is verified on Mainnet.",
      executorAddress: config.executorAddress,
      verifiedBlockNumber: block.number,
      verifiedBlockHash: block.hash,
    };
  } catch (error) {
    return {
      ...base,
      enabled: false,
      code: "ANONYMIZER_NOT_VERIFIED",
      message: error instanceof Error ? error.message : "The private swap executor could not be verified.",
      executorAddress: config.executorAddress,
      verifiedBlockNumber: null,
      verifiedBlockHash: null,
    };
  }
}

function assertPool(raw: z.infer<typeof rawPoolKeySchema>): void {
  const expected = PAYO_PRIVATE_STRK_USDC_POOL;
  if (
    !sameFelt(raw.token0, expected.token0)
    || !sameFelt(raw.token1, expected.token1)
    || BigInt(raw.fee) !== BigInt(expected.fee)
    || BigInt(raw.tick_spacing) !== BigInt(expected.tickSpacing)
    || !sameFelt(raw.extension, expected.extension)
  ) {
    throw new Error("Ekubo returned a pool outside PAYO's reviewed private route.");
  }
}

export async function quotePrivateExit(input: {
  fromToken: PayrollTokenSymbol;
  toToken: PayrollTokenSymbol;
  amountAtomic: bigint;
  slippageBps: number;
}, dependencies: PrivateExitDependencies = {}): Promise<PrivateExitQuote> {
  if (input.fromToken === input.toToken) throw new Error("Private swap tokens must differ.");
  if (input.amountAtomic <= 0n) throw new Error("Private swap amount must be greater than zero.");
  if (!Number.isInteger(input.slippageBps) || input.slippageBps < 10 || input.slippageBps > 500) {
    throw new Error("Private swap slippage must be between 0.10% and 5.00%.");
  }
  const config = runtimeConfig(dependencies);
  if (!config.executorAddress) {
    throw new Error("Private swap is locked until a reviewed Mainnet anonymizer instance is configured and verified.");
  }
  const provider = providerFor(config, dependencies);
  const fetcher = dependencies.fetch ?? fetch;
  const from = PAYROLL_TOKENS[input.fromToken];
  const to = PAYROLL_TOKENS[input.toToken];
  const url = `${EKUBO_QUOTER_ORIGIN}/${EKUBO_MAINNET_CHAIN_ID_DECIMAL}/${input.amountAtomic}/${from.address}/${to.address}`;
  const response = await fetcher(url, {
    headers: { accept: "application/json" },
    cache: "no-store",
    signal: AbortSignal.timeout(QUOTER_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`The official Ekubo quoter returned HTTP ${response.status}.`);
  const raw = rawQuoteSchema.parse(await response.json());
  if (raw.splits.length !== 1 || raw.splits[0]?.route.length !== 1) {
    throw new Error("Ekubo returned a split or multihop route that the reviewed private anonymizer cannot execute.");
  }
  const split = raw.splits[0];
  const hop = split.route[0];
  if (
    BigInt(split.amount_specified) !== input.amountAtomic
    || BigInt(split.amount_calculated) !== BigInt(raw.total_calculated)
    || BigInt(raw.total_calculated) <= 0n
  ) {
    throw new Error("Ekubo returned an inconsistent private swap amount.");
  }
  assertPool(hop.pool_key);
  if (hop.skip_ahead !== 0) throw new Error("Ekubo returned an unsupported private route optimization.");

  const [quoteBlockValue, latestBlockValue] = await Promise.all([
    provider.getBlock(raw.block_number),
    provider.getBlock("latest"),
  ]);
  const quoteBlock = acceptedBlock(quoteBlockValue, "Quoted Starknet block");
  const latestBlock = acceptedBlock(latestBlockValue, "Latest Starknet block");
  const rawBlockHash = canonicalHash(raw.block_hash, "Ekubo quote block hash");
  if (quoteBlock.hash !== rawBlockHash || quoteBlock.number !== raw.block_number) {
    throw new Error("The Ekubo quote is not bound to the canonical Starknet block.");
  }
  if (
    latestBlock.number < quoteBlock.number
    || latestBlock.number - quoteBlock.number > PRIVATE_EXIT_MAX_QUOTE_BLOCK_LAG
  ) {
    throw new Error("The Ekubo private swap quote is stale relative to Starknet Mainnet.");
  }
  await verifyExecutorAtBlock({
    provider,
    executorAddress: config.executorAddress,
    blockHash: quoteBlock.hash,
  });

  const expected = BigInt(raw.total_calculated);
  const minimum = expected * BigInt(10_000 - input.slippageBps) / 10_000n;
  if (minimum <= 0n) throw new Error("The private swap output is too small after slippage protection.");
  const quotedAt = (dependencies.now ?? Date.now)();
  return sealPrivateExitQuote({
    version: PAYO_PRIVATE_EXIT_QUOTE_VERSION,
    routeId: PAYO_PRIVATE_EXIT_ROUTE_ID,
    chainId: canonicalFelt(STARKNET_MAINNET_CHAIN_ID, "Starknet Mainnet chain ID"),
    privacyMode: "anonymous-swap-to-open-private-note",
    fromToken: input.fromToken,
    toToken: input.toToken,
    amountInAtomic: input.amountAtomic.toString(),
    expectedOutAtomic: expected.toString(),
    minimumOutAtomic: minimum.toString(),
    slippageBps: input.slippageBps,
    priceImpact: raw.price_impact,
    quoteBlockNumber: quoteBlock.number,
    quoteBlockHash: quoteBlock.hash,
    quotedAt,
    expiresAt: quotedAt + PRIVATE_EXIT_QUOTE_TTL_MS,
    executorAddress: config.executorAddress,
    executorClassHash: STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
    routerAddress: EKUBO_MAINNET_ROUTER_ADDRESS,
    pool: PAYO_PRIVATE_STRK_USDC_POOL,
    skipAhead: String(hop.skip_ahead),
  });
}
