import { z } from "zod";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hashTextCommitment } from "@/lib/crypto/commitments";
import { concatBytes, encodeUint, normalizedHexBytes, stableJson, toHex, utf8 } from "@/lib/crypto/encoding";
import { atomicAmountSchema, payrollTokenSchema } from "./payroll";

const sourceQuoteSchema = z.object({
  source: z.string().min(1).max(80),
  priceAtomic: atomicAmountSchema,
  observedAt: z.string().datetime(),
}).strict();

export const fxSnapshotSchema = z.object({
  snapshotVersion: z.literal("payo-fx-snapshot-v1"),
  baseToken: payrollTokenSchema,
  referenceCurrency: z.string().regex(/^[A-Z]{3}$/),
  feedId: z.string().min(1).max(160),
  quoteDecimals: z.number().int().min(0).max(18),
  medianPriceAtomic: atomicAmountSchema,
  conservativePriceAtomic: atomicAmountSchema,
  haircutBps: z.number().int().min(0).max(5000),
  observedAt: z.string().datetime(),
  minimumSourceCount: z.number().int().min(1).max(9),
  maximumAgeSeconds: z.number().int().positive().max(86_400),
  sources: z.array(sourceQuoteSchema).min(2).max(9),
}).strict();
export type FxSnapshot = z.infer<typeof fxSnapshotSchema>;

export function buildFxSnapshot(input: {
  baseToken: "STRK" | "USDC";
  referenceCurrency: string;
  quoteDecimals: number;
  haircutBps: number;
  maximumAgeSeconds: number;
  minimumSources: number;
  feedId?: string;
  quotes: Array<z.infer<typeof sourceQuoteSchema>>;
  now?: Date;
}): FxSnapshot {
  const now = input.now ?? new Date();
  if (input.quotes.length < input.minimumSources) throw new Error("FX snapshot has too few independent sources.");
  const uniqueSources = new Set(input.quotes.map((quote) => quote.source.toLowerCase()));
  if (uniqueSources.size !== input.quotes.length) throw new Error("FX sources must be unique.");
  for (const quote of input.quotes) {
    sourceQuoteSchema.parse(quote);
    const age = (now.getTime() - new Date(quote.observedAt).getTime()) / 1000;
    if (age < 0 || age > input.maximumAgeSeconds) throw new Error(`FX quote is stale or future-dated: ${quote.source}.`);
  }
  const sorted = input.quotes.map((quote) => BigInt(quote.priceAtomic)).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  const middle = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2n;
  const conservative = median * BigInt(10_000 - input.haircutBps) / 10_000n;
  const latestCommonTime = input.quotes.reduce(
    (oldest, quote) => new Date(quote.observedAt) < oldest ? new Date(quote.observedAt) : oldest,
    now,
  );
  return fxSnapshotSchema.parse({
    snapshotVersion: "payo-fx-snapshot-v1",
    baseToken: input.baseToken,
    referenceCurrency: input.referenceCurrency,
    feedId: input.feedId ?? `${input.baseToken}/${input.referenceCurrency}`,
    quoteDecimals: input.quoteDecimals,
    medianPriceAtomic: median.toString(),
    conservativePriceAtomic: conservative.toString(),
    haircutBps: input.haircutBps,
    observedAt: latestCommonTime.toISOString(),
    minimumSourceCount: input.minimumSources,
    maximumAgeSeconds: input.maximumAgeSeconds,
    sources: input.quotes,
  });
}

export type CircuitFxSnapshot = {
  token: 0 | 1;
  tokenDecimals: 18 | 6;
  referenceCurrency: 0 | 1;
  feedCommitment: `0x${string}`;
  sourcesCommitment: `0x${string}`;
  priceNumerator: string;
  priceDenominator: string;
  observedAt: string;
  sourceCount: number;
  minimumSourceCount: number;
  maximumAgeSeconds: string;
  haircutBps: number;
};

export function toCircuitFxSnapshot(snapshotInput: FxSnapshot): CircuitFxSnapshot {
  const snapshot = fxSnapshotSchema.parse(snapshotInput);
  const referenceCurrency = snapshot.referenceCurrency === "USD"
    ? 0
    : snapshot.referenceCurrency === "GBP"
      ? 1
      : undefined;
  if (referenceCurrency === undefined) {
    throw new Error(`Unsupported circuit reference currency: ${snapshot.referenceCurrency}.`);
  }
  const sortedSources = [...snapshot.sources].sort((left, right) => left.source.localeCompare(right.source));
  return {
    token: snapshot.baseToken === "STRK" ? 0 : 1,
    tokenDecimals: snapshot.baseToken === "STRK" ? 18 : 6,
    referenceCurrency,
    feedCommitment: toHex(hashTextCommitment("PAYO_FX_FEED_V1", snapshot.feedId)),
    sourcesCommitment: toHex(hashTextCommitment("PAYO_FX_SOURCES_V1", stableJson(sortedSources))),
    priceNumerator: snapshot.medianPriceAtomic,
    priceDenominator: (10n ** BigInt(snapshot.baseToken === "STRK" ? 18 : 6)).toString(),
    observedAt: Math.floor(new Date(snapshot.observedAt).getTime() / 1000).toString(),
    sourceCount: snapshot.sources.length,
    minimumSourceCount: snapshot.minimumSourceCount,
    maximumAgeSeconds: snapshot.maximumAgeSeconds.toString(),
    haircutBps: snapshot.haircutBps,
  };
}

export function fxSnapshotCommitment(snapshot: FxSnapshot): `0x${string}` {
  const compiled = toCircuitFxSnapshot(snapshot);
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_FX_SNAPSHOT_V1"),
    Uint8Array.of(compiled.token, compiled.tokenDecimals, compiled.referenceCurrency),
    normalizedHexBytes(compiled.feedCommitment, 32),
    normalizedHexBytes(compiled.sourcesCommitment, 32),
    encodeUint(BigInt(compiled.priceNumerator), 16),
    encodeUint(BigInt(compiled.priceDenominator), 16),
    encodeUint(BigInt(compiled.observedAt), 8),
    Uint8Array.of(compiled.sourceCount, compiled.minimumSourceCount),
    encodeUint(BigInt(compiled.maximumAgeSeconds), 8),
    encodeUint(BigInt(compiled.haircutBps), 2),
  )));
}
