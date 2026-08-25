import { hash, num } from "starknet";

export type Strk20WalletFeeQuote = {
  tokenAddress: string;
  amount: bigint;
  source: "wallet-simulation";
};

export const PAYMASTER_PRICE_SCALE = 10n ** 18n;
export const PAYMASTER_NON_STRK_QUOTE_BUFFER_BPS = 2_000n;

/**
 * Convert a STRK-denominated pool fee into token atomic units using AVNU's
 * public `price_in_strk` scale. Non-STRK quotes use a conservative buffer
 * because Ready's final private-paymaster fee can move between quote and
 * approval. This is a passive quote only; it never asks the wallet to prove or
 * approve anything.
 */
export function convertStrkPoolFeeToToken(input: {
  poolFeeStrkAtomic: bigint;
  tokenDecimals: number;
  tokenPriceInStrk: bigint;
  bufferBps?: bigint;
}): bigint {
  if (input.poolFeeStrkAtomic <= 0n) throw new Error("The STRK20 pool returned an invalid fee.");
  if (!Number.isSafeInteger(input.tokenDecimals) || input.tokenDecimals < 0 || input.tokenDecimals > 18) {
    throw new Error("The paymaster returned unsupported token decimals.");
  }
  if (input.tokenPriceInStrk <= 0n) throw new Error("The paymaster returned an invalid token price.");
  const bufferBps = input.bufferBps ?? 0n;
  if (bufferBps < 0n || bufferBps > 10_000n) throw new Error("The fee quote buffer is invalid.");

  const basisPoints = 10_000n;
  const bufferedFee = (
    input.poolFeeStrkAtomic * (basisPoints + bufferBps) + basisPoints - 1n
  ) / basisPoints;
  const numerator = bufferedFee * 10n ** BigInt(input.tokenDecimals);
  return (numerator + input.tokenPriceInStrk - 1n) / input.tokenPriceInStrk;
}

type Strk20PreparedCall = {
  entry_point: string;
  calldata?: readonly string[];
};

const PRIVATE_FORWARDER_ENTRYPOINTS = new Map<string, boolean>([
  [hash.getSelectorFromName("execute_private"), false],
  [hash.getSelectorFromName("execute_private_sponsored"), true],
]);

function normalizedEntrypoint(entrypoint: string): string {
  if (entrypoint === "execute_private" || entrypoint === "execute_private_sponsored") {
    return hash.getSelectorFromName(entrypoint);
  }
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(entrypoint)) {
    return hash.getSelectorFromName(entrypoint);
  }
  try {
    return num.toHex(num.toBigInt(entrypoint));
  } catch {
    throw new Error("Ready returned an invalid STRK20 simulation entrypoint.");
  }
}

function readFelt(calldata: readonly string[], index: number, label: string): bigint {
  if (index >= calldata.length) {
    throw new Error(`Ready's STRK20 simulation omitted ${label}.`);
  }
  try {
    const value = num.toBigInt(calldata[index]);
    if (value < 0n) throw new Error("negative felt");
    return value;
  } catch {
    throw new Error(`Ready's STRK20 simulation returned an invalid ${label}.`);
  }
}

function safeCount(value: bigint, label: string): number {
  if (value > 1_000n) {
    throw new Error(`Ready's STRK20 simulation returned an unreasonable ${label}.`);
  }
  return Number(value);
}

/**
 * Decode the token-denominated fee reserve from Ready's simulated AVNU private
 * forwarder call. This is deliberately strict: a changed or unknown call shape
 * fails closed instead of displaying a guessed STRK or USDC fee.
 */
export function decodeStrk20WalletFeeQuote(call: Strk20PreparedCall): Strk20WalletFeeQuote {
  const entrypoint = normalizedEntrypoint(call.entry_point);
  const sponsored = PRIVATE_FORWARDER_ENTRYPOINTS.get(entrypoint);
  if (sponsored === undefined) {
    throw new Error(
      "Ready did not return a recognized private-forwarder simulation; PAYO cannot quote this fee safely.",
    );
  }

  const calldata = (call.calldata ?? []).map(String);
  let cursor = 0;
  const callCount = safeCount(readFelt(calldata, cursor++, "private call count"), "private call count");
  for (let callIndex = 0; callIndex < callCount; callIndex += 1) {
    readFelt(calldata, cursor++, `private call ${callIndex + 1} target`);
    readFelt(calldata, cursor++, `private call ${callIndex + 1} selector`);
    const length = safeCount(
      readFelt(calldata, cursor++, `private call ${callIndex + 1} calldata length`),
      `private call ${callIndex + 1} calldata length`,
    );
    if (cursor + length > calldata.length) {
      throw new Error(`Ready's STRK20 simulation truncated private call ${callIndex + 1}.`);
    }
    cursor += length;
  }

  const tokenAddress = num.toHex(readFelt(calldata, cursor++, "fee token"));
  const low = readFelt(calldata, cursor++, "fee amount low limb");
  const high = readFelt(calldata, cursor++, "fee amount high limb");
  const amount = low + (high << 128n);
  if (amount <= 0n) {
    throw new Error("Ready's STRK20 simulation returned a zero fee reserve.");
  }

  if (sponsored) {
    const metadataLength = safeCount(
      readFelt(calldata, cursor++, "sponsor metadata length"),
      "sponsor metadata length",
    );
    if (cursor + metadataLength !== calldata.length) {
      throw new Error("Ready's sponsored STRK20 simulation has an invalid metadata boundary.");
    }
    cursor += metadataLength;
  }
  if (cursor !== calldata.length) {
    throw new Error("Ready's STRK20 simulation contains unrecognized trailing fee data.");
  }

  return { tokenAddress, amount, source: "wallet-simulation" };
}
