import {
  num,
  validateAndParseAddress,
  type STRK20_ACTION,
  type STRK20_INVOKE_ACTION,
} from "starknet";
import {
  assertPrivacyTokenEnabled,
  parseTokenAmount,
  PAYROLL_TOKENS,
  type PayrollTokenSymbol,
} from "./tokens";

export type PrivatePayrollRecipient = {
  address: string;
  amount: string;
  token: PayrollTokenSymbol;
};

export type PrivatePayrollActionBundle = {
  actions: STRK20_ACTION[];
  totals: Record<PayrollTokenSymbol, bigint>;
};

export function buildPrivatePayrollActions(
  recipients: PrivatePayrollRecipient[],
  payoAction: STRK20_INVOKE_ACTION,
  configuredSeal: string,
): PrivatePayrollActionBundle {
  if (recipients.length === 0) throw new Error("Add at least one recipient.");
  if (recipients.length > 50) throw new Error("A payroll can contain up to 50 recipients.");
  if (!configuredSeal) throw new Error("The proof-bound PAYO seal is not deployed/configured.");

  let normalizedSeal: string;
  try {
    normalizedSeal = validateAndParseAddress(configuredSeal);
  } catch {
    throw new Error("The configured PAYO seal address is invalid.");
  }
  if (
    payoAction.type !== "invoke"
    || num.toBigInt(validateAndParseAddress(payoAction.contract)) !== num.toBigInt(normalizedSeal)
  ) {
    throw new Error("Payroll contains an unapproved PAYO seal action.");
  }

  const seenDestinations = new Set<string>();
  const totals: Record<PayrollTokenSymbol, bigint> = { STRK: 0n, USDC: 0n };
  const actions: STRK20_ACTION[] = recipients.map((recipient, index) => {
    let parsedAddress: string;
    try {
      parsedAddress = validateAndParseAddress(recipient.address.trim());
    } catch {
      throw new Error(`Recipient ${index + 1} has an invalid Starknet address.`);
    }
    const token = PAYROLL_TOKENS[recipient.token];
    if (!token) throw new Error(`Recipient ${index + 1} uses an unsupported payroll token.`);
    assertPrivacyTokenEnabled(recipient.token);
    const destinationKey = `${num.toHex(num.toBigInt(parsedAddress))}:${token.symbol}`;
    if (seenDestinations.has(destinationKey)) {
      throw new Error(`Recipient ${index + 1} duplicates the same address and token.`);
    }
    seenDestinations.add(destinationKey);

    const atomicAmount = parseTokenAmount(recipient.amount, token);
    totals[token.symbol] += atomicAmount;
    return {
      type: "transfer",
      token: token.address,
      amount: num.toHex(atomicAmount),
      recipient: parsedAddress,
    };
  });
  actions.push(payoAction);
  return { actions, totals };
}

export function requiredPayrollReserves(
  totals: Readonly<Record<PayrollTokenSymbol, bigint>>,
  feeToken: PayrollTokenSymbol,
  feeAmount: bigint,
): Record<PayrollTokenSymbol, bigint> {
  if (feeAmount <= 0n) throw new Error("The wallet fee reserve must be greater than zero.");
  return {
    STRK: totals.STRK + (feeToken === "STRK" ? feeAmount : 0n),
    USDC: totals.USDC + (feeToken === "USDC" ? feeAmount : 0n),
  };
}

/**
 * Reserve a passive fee quote for every token used in a mixed payroll. The
 * Wallet API deliberately leaves final private-paymaster fee construction to
 * `wallet_strk20InvokeTransaction`; reserving each active token fails closed
 * without issuing a separate wallet preparation request just to preview it.
 */
export function requiredPayrollReservesForQuotes(
  totals: Readonly<Record<PayrollTokenSymbol, bigint>>,
  feeReserves: Readonly<Record<PayrollTokenSymbol, bigint>>,
): Record<PayrollTokenSymbol, bigint> {
  for (const token of ["STRK", "USDC"] as const) {
    if (totals[token] < 0n || feeReserves[token] < 0n) {
      throw new Error("Payroll totals and fee reserves cannot be negative.");
    }
    if (totals[token] > 0n && feeReserves[token] <= 0n) {
      throw new Error(`The ${token} payroll is missing a private fee reserve.`);
    }
  }
  return {
    STRK: totals.STRK + feeReserves.STRK,
    USDC: totals.USDC + feeReserves.USDC,
  };
}
