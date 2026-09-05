import {
  num,
  validateAndParseAddress,
  type STRK20_ACTION,
} from "starknet";
import {
  assertPrivateExitQuoteIntegrity,
  type PrivateExitQuote,
} from "@/lib/domain/private-exit";
import {
  assertPrivacyTokenEnabled,
  parseTokenAmount,
  PAYROLL_TOKENS,
  type PayrollTokenSymbol,
} from "./tokens";
import { STARKNET_MAINNET_CHAIN_ID } from "./deployment";

export const EKUBO_MAINNET_CHAIN_ID_DECIMAL = "23448594291968334" as const;
export const EKUBO_MAINNET_CORE_ADDRESS =
  "0x5dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b" as const;
export const EKUBO_MAINNET_ROUTER_ADDRESS =
  "0x199741822c2dc722f6f605204f35e56dbc23bceed54818168c4c49e4fb8737e" as const;
export const STRK20_EKUBO_ANONYMIZER_CLASS_HASH =
  "0x2a4ac595283d4d64b9952f5ef5c0da1775bfdb7c9d92237524a21dd8d19ebd7" as const;

/**
 * One liquid, extension-free Mainnet pool currently selected by Ekubo's
 * official quoter in both STRK/USDC directions. PAYO intentionally supports
 * one pool: the upstream anonymizer accepts a single hop and cannot safely
 * execute a split or multihop quote.
 */
export const PAYO_PRIVATE_STRK_USDC_POOL = {
  token0: PAYROLL_TOKENS.USDC.address,
  token1: PAYROLL_TOKENS.STRK.address,
  fee: "170141183460469235273462165868118016",
  tickSpacing: "1000",
  extension: "0x0",
} as const;

export const PRIVATE_EXIT_QUOTE_TTL_MS = 45_000;
export const PRIVATE_EXIT_MAX_QUOTE_BLOCK_LAG = 20;

function canonicalAddress(value: string, label: string): string {
  try {
    const parsed = validateAndParseAddress(value);
    if (BigInt(parsed) === 0n) throw new Error("zero");
    return num.toHex(BigInt(parsed));
  } catch {
    throw new Error(`${label} is not a valid nonzero Starknet address.`);
  }
}

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

function assertPinnedPrivateRoute(quote: PrivateExitQuote): void {
  if (!sameFelt(quote.chainId, STARKNET_MAINNET_CHAIN_ID)) {
    throw new Error("The private-exit quote targets another Starknet network.");
  }
  if (!sameFelt(quote.executorClassHash, STRK20_EKUBO_ANONYMIZER_CLASS_HASH)) {
    throw new Error("The private-exit quote does not use the reviewed STRK20 anonymizer class.");
  }
  if (!sameFelt(quote.routerAddress, EKUBO_MAINNET_ROUTER_ADDRESS)) {
    throw new Error("The private-exit quote substituted the Ekubo router.");
  }
  const expectedPool = PAYO_PRIVATE_STRK_USDC_POOL;
  if (
    !sameFelt(quote.pool.token0, expectedPool.token0)
    || !sameFelt(quote.pool.token1, expectedPool.token1)
    || BigInt(quote.pool.fee) !== BigInt(expectedPool.fee)
    || BigInt(quote.pool.tickSpacing) !== BigInt(expectedPool.tickSpacing)
    || !sameFelt(quote.pool.extension, expectedPool.extension)
    || BigInt(quote.skipAhead) !== 0n
  ) {
    throw new Error("The private-exit quote substituted the reviewed single-hop pool.");
  }
}

export function assertPayoPrivateExitQuote(
  input: unknown,
  now = Date.now(),
): PrivateExitQuote {
  const quote = assertPrivateExitQuoteIntegrity(input, now);
  assertPinnedPrivateRoute(quote);
  return quote;
}

export function buildPrivateSwapActions(input: {
  quote: unknown;
  privateRecipient: string;
  now?: number;
}): { quote: PrivateExitQuote; actions: STRK20_ACTION[] } {
  const quote = assertPayoPrivateExitQuote(input.quote, input.now);
  const recipient = canonicalAddress(input.privateRecipient, "Private swap recipient");
  const from = PAYROLL_TOKENS[quote.fromToken];
  const to = PAYROLL_TOKENS[quote.toToken];
  assertPrivacyTokenEnabled(from.symbol);
  assertPrivacyTokenEnabled(to.symbol);

  const amount = BigInt(quote.amountInAtomic);
  const minimum = BigInt(quote.minimumOutAtomic);
  const lowMask = (1n << 128n) - 1n;

  const actions: STRK20_ACTION[] = [
    {
      type: "withdraw",
      token: from.address,
      amount: num.toHex(amount),
      recipient: canonicalAddress(quote.executorAddress, "Private swap executor"),
    },
    {
      type: "transfer",
      token: to.address,
      amount: "OPEN",
      recipient,
    },
    {
      type: "invoke",
      contract: canonicalAddress(quote.executorAddress, "Private swap executor"),
      calldata: [
        EKUBO_MAINNET_ROUTER_ADDRESS,
        from.address,
        num.toHex(amount),
        "0x0",
        PAYO_PRIVATE_STRK_USDC_POOL.token0,
        PAYO_PRIVATE_STRK_USDC_POOL.token1,
        num.toHex(BigInt(PAYO_PRIVATE_STRK_USDC_POOL.fee)),
        num.toHex(BigInt(PAYO_PRIVATE_STRK_USDC_POOL.tickSpacing)),
        PAYO_PRIVATE_STRK_USDC_POOL.extension,
        num.toHex(minimum & lowMask),
        num.toHex(minimum >> 128n),
        "0x0",
        "${openNoteIds[0]}",
      ],
    },
  ];
  return { quote, actions };
}

export function buildPublicWithdrawalAction(input: {
  token: PayrollTokenSymbol;
  amount: string;
  recipient: string;
  acknowledgedPublicDisclosure: boolean;
}): { action: STRK20_ACTION; amountAtomic: bigint } {
  if (!input.acknowledgedPublicDisclosure) {
    throw new Error("Acknowledge that this withdrawal becomes publicly linkable.");
  }
  const token = PAYROLL_TOKENS[input.token];
  assertPrivacyTokenEnabled(input.token);
  const amountAtomic = parseTokenAmount(input.amount, token);
  return {
    action: {
      type: "withdraw",
      token: token.address,
      amount: num.toHex(amountAtomic),
      recipient: canonicalAddress(input.recipient, "Public withdrawal recipient"),
    },
    amountAtomic,
  };
}
