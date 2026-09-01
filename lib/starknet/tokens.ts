export type PayrollTokenSymbol = "STRK" | "USDC";

export type PayrollToken = {
  symbol: PayrollTokenSymbol;
  name: string;
  address: string;
  decimals: number;
  feeBehavior: "passive-quote-wallet-deduction";
  privacyEnabled: boolean;
};

export const STRK_TOKEN_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

export const USDC_TOKEN_ADDRESS =
  "0x033068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb";

export const PAYROLL_TOKENS: Record<PayrollTokenSymbol, PayrollToken> = {
  STRK: {
    symbol: "STRK",
    name: "Starknet Token",
    address: STRK_TOKEN_ADDRESS,
    decimals: 18,
    feeBehavior: "passive-quote-wallet-deduction",
    privacyEnabled: true,
  },
  USDC: {
    symbol: "USDC",
    name: "USD Coin",
    address: USDC_TOKEN_ADDRESS,
    decimals: 6,
    feeBehavior: "passive-quote-wallet-deduction",
    privacyEnabled: true,
  },
};

export const PAYROLL_TOKEN_LIST = Object.values(PAYROLL_TOKENS);
export const PRIVACY_PAYROLL_TOKEN_LIST = PAYROLL_TOKEN_LIST.filter((token) => token.privacyEnabled);

export function assertPrivacyTokenEnabled(symbol: PayrollTokenSymbol): void {
  if (!PAYROLL_TOKENS[symbol].privacyEnabled) {
    throw new Error(
      `${symbol} private settlement is disabled until its live STRK20 pool compatibility test passes.`,
    );
  }
}

export type TokenBalanceMap = Record<PayrollTokenSymbol, bigint | null>;

export function emptyTokenBalances(): TokenBalanceMap {
  return { STRK: null, USDC: null };
}

export function zeroTokenBalances(): Record<PayrollTokenSymbol, bigint> {
  return { STRK: 0n, USDC: 0n };
}

export function tokenByAddress(address: string): PayrollToken | undefined {
  try {
    const normalized = BigInt(address);
    return PAYROLL_TOKEN_LIST.find((token) => BigInt(token.address) === normalized);
  } catch {
    return undefined;
  }
}

function parseTokenAmountValue(
  value: string,
  tokenOrSymbol: PayrollToken | PayrollTokenSymbol,
  allowZero: boolean,
): bigint {
  const token = typeof tokenOrSymbol === "string" ? PAYROLL_TOKENS[tokenOrSymbol] : tokenOrSymbol;
  const trimmed = value.trim();
  const pattern = new RegExp(`^\\d+(\\.\\d{0,${token.decimals}})?$`);
  if (!pattern.test(trimmed)) {
    throw new Error(`Enter a valid ${token.symbol} amount with no more than ${token.decimals} decimals.`);
  }

  const [whole, fraction = ""] = trimmed.split(".");
  const amount = BigInt(whole) * 10n ** BigInt(token.decimals)
    + BigInt(fraction.padEnd(token.decimals, "0") || "0");
  if (allowZero ? amount < 0n : amount <= 0n) {
    throw new Error(allowZero ? "Amount cannot be negative." : "Amount must be greater than zero.");
  }
  return amount;
}

export function parseTokenAmount(value: string, tokenOrSymbol: PayrollToken | PayrollTokenSymbol): bigint {
  return parseTokenAmountValue(value, tokenOrSymbol, false);
}

export function parseTokenAmountOrZero(
  value: string,
  tokenOrSymbol: PayrollToken | PayrollTokenSymbol,
): bigint {
  return parseTokenAmountValue(value, tokenOrSymbol, true);
}

export function formatTokenAmount(
  amount: bigint | null,
  tokenOrSymbol: PayrollToken | PayrollTokenSymbol,
  maximumFractionDigits = 6,
) {
  if (amount === null) return "—";
  const token = typeof tokenOrSymbol === "string" ? PAYROLL_TOKENS[tokenOrSymbol] : tokenOrSymbol;
  const unit = 10n ** BigInt(token.decimals);
  const whole = amount / unit;
  const rawFraction = (amount % unit).toString().padStart(token.decimals, "0");
  const fraction = rawFraction
    .slice(0, Math.min(maximumFractionDigits, token.decimals))
    .replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

export function tokenAmountLabel(amount: bigint | null, symbol: PayrollTokenSymbol, maximumFractionDigits = 6) {
  return `${formatTokenAmount(amount, symbol, maximumFractionDigits)} ${symbol}`;
}
