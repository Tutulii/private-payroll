import "server-only";

import { shortString, type Call } from "starknet";
import { buildFxSnapshot, type FxSnapshot } from "@/lib/domain/fx";
import type { PayrollTokenSymbol } from "@/lib/domain/payroll";

export const PRAGMA_MAINNET_ORACLE_ADDRESS =
  "0x2a85bd616f912537c50a49a4076db02c00b29b2cdc8a197ce92ed1837fa875b";
const QUOTE_DECIMALS = 6;
const MAXIMUM_AGE_SECONDS = 3_600;
const MINIMUM_SOURCE_COUNT = 3;

export type PragmaFxRpc = {
  getBlockNumber: () => Promise<number>;
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

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
