import "server-only";

import { shortString, type Call } from "starknet";
import {
  buildFxSnapshot,
  buildPragmaProtectedFxSnapshot,
  type FxSnapshot,
  type PragmaProtectedFxSnapshot,
} from "@/lib/domain/fx";
import type { PayrollTokenSymbol } from "@/lib/domain/payroll";

export const PRAGMA_MAINNET_ORACLE_ADDRESS =
  "0x2a85bd616f912537c50a49a4076db02c00b29b2cdc8a197ce92ed1837fa875b";
export const PRAGMA_MAINNET_SUMMARY_STATS_ADDRESS =
  "0x49eefafae944d07744d07cc72a5bf14728a6fb463c3eae5bca13552f5d455fd";
const QUOTE_DECIMALS = 6;
const MAXIMUM_AGE_SECONDS = 3_600;
const MINIMUM_SOURCE_COUNT = 3;
const PHASE3_MAXIMUM_AGE_SECONDS = 300;
// Pragma Mainnet checkpoints are intentionally sparse. A 12-hour window is
// the shortest interval currently evidenced for STRK/USD; shorter windows can
// contain only one checkpoint and the Summary Stats contract correctly reverts.
const PHASE3_TWAP_WINDOW_SECONDS = 43_200;

export type PragmaFxRpc = {
  getBlockNumber: () => Promise<number>;
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

export type PragmaProtectedFxRpc = PragmaFxRpc & {
  getBlockTimestamp: (blockNumber: number) => Promise<number>;
};

export class PragmaProtectedPairUnavailableError extends Error {
  constructor(
    readonly pair: string,
    readonly component: "median" | "twap",
    options?: ErrorOptions,
  ) {
    super(`Pragma ${component} is unavailable for ${pair} at the pinned block.`, options);
    this.name = "PragmaProtectedPairUnavailableError";
  }
}

function responseFelts(response: unknown): string[] {
  if (Array.isArray(response)) return response.map(String);
  if (response && typeof response === "object" && Array.isArray((response as { result?: unknown }).result)) {
    return (response as { result: unknown[] }).result.map(String);
  }
  throw new Error("Pragma returned no price data.");
}

function rescalePrice(price: bigint, fromDecimals: number): bigint {
  if (fromDecimals < 0 || fromDecimals > 18) throw new Error("Pragma returned unsupported decimals.");
  if (fromDecimals === QUOTE_DECIMALS) return price;
  if (fromDecimals < QUOTE_DECIMALS) return price * 10n ** BigInt(QUOTE_DECIMALS - fromDecimals);
  return price / 10n ** BigInt(fromDecimals - QUOTE_DECIMALS);
}

export async function readPragmaFxSnapshots(input: {
  rpc: PragmaFxRpc;
  tokens: readonly PayrollTokenSymbol[];
  now?: Date;
  oracleAddress?: string;
}): Promise<{ blockNumber: number; snapshots: FxSnapshot[] }> {
  const tokens = [...new Set(input.tokens)];
  if (tokens.length === 0 || tokens.some((token) => token !== "STRK" && token !== "USDC")) {
    throw new Error("Request at least one supported PAYO FX token.");
  }
  const now = input.now ?? new Date();
  const blockNumber = await input.rpc.getBlockNumber();
  const oracleAddress = input.oracleAddress ?? PRAGMA_MAINNET_ORACLE_ADDRESS;
  const snapshots = await Promise.all(tokens.map(async (token) => {
    const pair = `${token}/USD`;
    const response = responseFelts(await input.rpc.callContract({
      contractAddress: oracleAddress,
      entrypoint: "get_data_median",
      // DataType::SpotEntry is enum variant 0 followed by its pair felt.
      calldata: ["0x0", shortString.encodeShortString(pair)],
    }, blockNumber));
    if (response.length < 4) throw new Error(`Pragma returned an incomplete ${pair} observation.`);
    const price = BigInt(response[0]);
    const decimals = Number(BigInt(response[1]));
    const observedAt = Number(BigInt(response[2]));
    const sourceCount = Number(BigInt(response[3]));
    if (price <= 0n || !Number.isSafeInteger(observedAt) || !Number.isSafeInteger(sourceCount)) {
      throw new Error(`Pragma returned invalid ${pair} fields.`);
    }
    const ageSeconds = Math.floor(now.getTime() / 1_000) - observedAt;
    if (ageSeconds < 0 || ageSeconds > MAXIMUM_AGE_SECONDS) {
      throw new Error(`Pragma ${pair} observation is stale or future-dated.`);
    }
    if (sourceCount < MINIMUM_SOURCE_COUNT) {
      throw new Error(`Pragma ${pair} has only ${sourceCount} aggregated sources.`);
    }
    const priceAtomic = rescalePrice(price, decimals).toString();
    const observedAtIso = new Date(observedAt * 1_000).toISOString();
    return buildFxSnapshot({
      baseToken: token,
      referenceCurrency: "USD",
      quoteDecimals: QUOTE_DECIMALS,
      haircutBps: token === "STRK" ? 100 : 0,
      maximumAgeSeconds: MAXIMUM_AGE_SECONDS,
      minimumSources: MINIMUM_SOURCE_COUNT,
      aggregatedSourceCount: sourceCount,
      feedId: `pragma-mainnet:${oracleAddress}:${pair}:median`,
      quotes: [{
        source: `pragma-mainnet-${pair.toLowerCase()}`,
        priceAtomic,
        observedAt: observedAtIso,
      }],
      now,
    });
  }));
  return { blockNumber, snapshots };
}

/**
 * Reads both Pragma's source-aggregated spot median and its on-chain TWAP at
 * one pinned Starknet block. The lower value is committed before applying the
 * haircut, so neither a transient spike nor a lagging optimistic TWAP can raise
 * the worker's proved reference value.
 */
export async function readPragmaProtectedFxSnapshots(input: {
  rpc: PragmaProtectedFxRpc;
  tokens: readonly PayrollTokenSymbol[];
  oracleAddress?: string;
  summaryStatsAddress?: string;
  twapWindowSeconds?: number;
  maximumAgeSeconds?: number;
  minimumSourceCount?: number;
}): Promise<{ blockNumber: number; blockTimestamp: number; snapshots: PragmaProtectedFxSnapshot[] }> {
  const tokens = [...new Set(input.tokens)];
  if (tokens.length === 0 || tokens.some((token) => token !== "STRK" && token !== "USDC")) {
    throw new Error("Request at least one supported PAYO FX token.");
  }
  const twapWindowSeconds = input.twapWindowSeconds ?? PHASE3_TWAP_WINDOW_SECONDS;
  const maximumAgeSeconds = input.maximumAgeSeconds ?? PHASE3_MAXIMUM_AGE_SECONDS;
  const minimumSourceCount = input.minimumSourceCount ?? MINIMUM_SOURCE_COUNT;
  if (!Number.isInteger(twapWindowSeconds) || twapWindowSeconds < 300 || twapWindowSeconds > 86_400) {
    throw new Error("Pragma TWAP window must be between five minutes and one day.");
  }
  if (!Number.isInteger(maximumAgeSeconds) || maximumAgeSeconds <= 0 || maximumAgeSeconds > 3_600) {
    throw new Error("Pragma maximum age must be between one second and one hour.");
  }
  if (!Number.isInteger(minimumSourceCount) || minimumSourceCount < 1 || minimumSourceCount > 255) {
    throw new Error("Pragma minimum source count is invalid.");
  }
  const blockNumber = await input.rpc.getBlockNumber();
  const blockTimestamp = await input.rpc.getBlockTimestamp(blockNumber);
  if (!Number.isSafeInteger(blockTimestamp) || blockTimestamp <= twapWindowSeconds) {
    throw new Error("Starknet returned an invalid pinned block timestamp.");
  }
  const oracleAddress = input.oracleAddress ?? PRAGMA_MAINNET_ORACLE_ADDRESS;
  const summaryStatsAddress = input.summaryStatsAddress ?? PRAGMA_MAINNET_SUMMARY_STATS_ADDRESS;
  const snapshots = await Promise.all(tokens.map(async (token) => {
    const pair = `${token}/USD`;
    const dataType = ["0x0", shortString.encodeShortString(pair)];
    const [spotResult, twapResult] = await Promise.allSettled([
        input.rpc.callContract({
          contractAddress: oracleAddress,
          entrypoint: "get_data_median",
          calldata: dataType,
        }, blockNumber).then(responseFelts),
        input.rpc.callContract({
          contractAddress: summaryStatsAddress,
          entrypoint: "calculate_twap",
          // DataType::SpotEntry(pair), AggregationMode::Median, time, start_time.
          calldata: [
            ...dataType,
            "0x0",
            `0x${twapWindowSeconds.toString(16)}`,
            `0x${(blockTimestamp - twapWindowSeconds).toString(16)}`,
          ],
        }, blockNumber).then(responseFelts),
      ]);
    if (spotResult.status === "rejected") {
      throw new PragmaProtectedPairUnavailableError(pair, "median", { cause: spotResult.reason });
    }
    if (twapResult.status === "rejected") {
      throw new PragmaProtectedPairUnavailableError(pair, "twap", { cause: twapResult.reason });
    }
    const spotResponse = responseFelts(spotResult.value);
    const twapResponse = responseFelts(twapResult.value);
    if (spotResponse.length < 4 || twapResponse.length < 2) {
      throw new Error(`Pragma returned incomplete median/TWAP data for ${pair}.`);
    }
    const spot = BigInt(spotResponse[0]);
    const spotDecimals = Number(BigInt(spotResponse[1]));
    const observedAt = Number(BigInt(spotResponse[2]));
    const sourceCount = Number(BigInt(spotResponse[3]));
    const twap = BigInt(twapResponse[0]);
    const twapDecimals = Number(BigInt(twapResponse[1]));
    if (
      spot <= 0n
      || twap <= 0n
      || !Number.isSafeInteger(observedAt)
      || !Number.isSafeInteger(sourceCount)
    ) throw new Error(`Pragma returned invalid median/TWAP fields for ${pair}.`);
    const ageSeconds = blockTimestamp - observedAt;
    if (ageSeconds < 0 || ageSeconds > maximumAgeSeconds) {
      throw new Error(`Pragma ${pair} median is stale or future-dated at the pinned block.`);
    }
    if (sourceCount < minimumSourceCount) {
      throw new Error(`Pragma ${pair} has only ${sourceCount} aggregated sources.`);
    }
    return buildPragmaProtectedFxSnapshot({
      baseToken: token,
      referenceCurrency: "USD",
      pairId: pair as "STRK/USD" | "USDC/USD",
      oracleAddress,
      summaryStatsAddress,
      blockNumber: blockNumber.toString(),
      blockTimestamp: new Date(blockTimestamp * 1_000).toISOString(),
      quoteDecimals: QUOTE_DECIMALS,
      spotMedianPriceAtomic: rescalePrice(spot, spotDecimals).toString(),
      twapPriceAtomic: rescalePrice(twap, twapDecimals).toString(),
      twapWindowSeconds,
      haircutBps: token === "STRK" ? 100 : 0,
      observedAt: new Date(observedAt * 1_000).toISOString(),
      sourceCount,
      minimumSourceCount,
      maximumAgeSeconds,
    });
  }));
  return { blockNumber, blockTimestamp, snapshots };
}
