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
  /** Wallet-only value needed to assemble an action; it is not payroll value. */
  operationalReserves: Record<PayrollTokenSymbol, bigint>;
};

export type PrivateExceptionWorkflow = "wage_claim" | "wage_remediation";

function assertProofBoundAction(
  payoAction: STRK20_INVOKE_ACTION,
  configuredSeal: string,
  expectedMode: 0 | 2 | 3,
): string {
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
  let mode: bigint;
  try {
    mode = BigInt(String(payoAction.calldata[0]));
    for (const field of payoAction.calldata) {
      const value = BigInt(String(field));
      if (value < 0n) throw new Error("negative");
    }
  } catch {
    throw new Error("PAYO action calldata is not canonical.");
  }
  const legacyAction = payoAction.calldata.length === 19;
  const vNextAuthorizedAction = payoAction.calldata.length === 7
    && (expectedMode === 0 || expectedMode === 3);
  if (
    mode !== BigInt(expectedMode)
    || (!legacyAction && !vNextAuthorizedAction)
  ) {
    throw new Error(`PAYO action is not the expected proof mode ${expectedMode} or ABI.`);
  }
  return normalizedSeal;
}

export function buildPrivatePayrollActions(
  recipients: PrivatePayrollRecipient[],
  payoAction: STRK20_INVOKE_ACTION,
  configuredSeal: string,
): PrivatePayrollActionBundle {
  if (recipients.length === 0) throw new Error("Add at least one recipient.");
  if (recipients.length > 50) throw new Error("A payroll can contain up to 50 recipients.");
  assertProofBoundAction(payoAction, configuredSeal, 0);

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
  return { actions, totals, operationalReserves: { STRK: 0n, USDC: 0n } };
}

/**
 * Builds the only two non-payroll actions accepted by the Phase 3 wallet
 * boundary. Ready cannot currently assemble a bare external invoke, so a claim
 * pairs its seal with a one-fri STRK self-transfer. That anchor changes neither
 * owner nor wage value; remediation must privately transfer one proved amount
 * before its REMEDIATE invocation.
 */
export function buildPrivateExceptionActions(
  workflow: PrivateExceptionWorkflow,
  recipients: PrivatePayrollRecipient[],
  payoAction: STRK20_INVOKE_ACTION | readonly STRK20_INVOKE_ACTION[],
  configuredSeal: string,
  connectedAddress?: string,
  configuredBookSeal?: string,
): PrivatePayrollActionBundle {
  const payoActions = Array.isArray(payoAction) ? [...payoAction] : [payoAction];
  const sourceAction = payoActions[0];
  if (!sourceAction) throw new Error("The proof-bound exception action is missing.");
  const expectedMode = workflow === "wage_claim" ? 2 : 3;
  assertProofBoundAction(sourceAction, configuredSeal, expectedMode);
  if (workflow === "wage_claim" && payoActions.length !== 1) {
    throw new Error("A wage claim cannot attach a private payroll-book callback.");
  }
  if (workflow === "wage_remediation") {
    if (payoActions.length !== 2 || !configuredBookSeal) {
      throw new Error("A wage remediation requires its universal payroll-book callback.");
    }
    const bookAction = payoActions[1];
    let bookSeal: string;
    try {
      bookSeal = validateAndParseAddress(configuredBookSeal);
    } catch {
      throw new Error("The configured PAYO payroll-book seal address is invalid.");
    }
    if (bookAction.type !== "invoke"
      || num.toBigInt(validateAndParseAddress(bookAction.contract)) !== num.toBigInt(bookSeal)
      || bookAction.calldata.length !== 6
      || BigInt(String(bookAction.calldata[0])) !== BigInt(String(sourceAction.calldata[1]))
      || BigInt(String(bookAction.calldata[1])) !== BigInt(String(sourceAction.calldata[2]))) {
      throw new Error("The remediation payroll-book callback is not bound to the exact source subject.");
    }
    for (const field of bookAction.calldata) {
      if (BigInt(String(field)) < 0n) throw new Error("Payroll-book callback calldata is not canonical.");
    }
  }
  if (workflow === "wage_claim") {
    if (recipients.length !== 0) throw new Error("A wage claim cannot transfer private funds.");
    let selfRecipient: string;
    try {
      selfRecipient = validateAndParseAddress(connectedAddress?.trim() ?? "");
    } catch {
      throw new Error("A wage claim requires the connected Starknet address for its private execution anchor.");
    }
    return {
      actions: [
        {
          type: "transfer",
          token: PAYROLL_TOKENS.STRK.address,
          amount: num.toHex(1n),
          recipient: selfRecipient,
        },
        sourceAction,
      ],
      totals: { STRK: 0n, USDC: 0n },
      operationalReserves: { STRK: 1n, USDC: 0n },
    };
  }
  if (recipients.length !== 1) {
    throw new Error("A wage remediation proof must settle exactly one private recipient.");
  }
  const { actions, totals } = buildPrivatePayrollActions(
    recipients,
    { ...sourceAction, calldata: ["0x0", ...sourceAction.calldata.slice(1)] },
    configuredSeal,
  );
  actions[actions.length - 1] = sourceAction;
  actions.push(payoActions[1]!);
  return { actions, totals, operationalReserves: { STRK: 0n, USDC: 0n } };
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
