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
  sources: z.array(sourceQuoteSchema).min(1).max(9),
  aggregatedSourceCount: z.number().int().min(1).max(255).optional(),
}).strict();
export type FxSnapshot = z.infer<typeof fxSnapshotSchema>;

export const pragmaProtectedFxSnapshotSchema = z.object({
  snapshotVersion: z.literal("payo-pragma-fx-snapshot-v2"),
  baseToken: payrollTokenSchema,
  referenceCurrency: z.literal("USD"),
  pairId: z.string().regex(/^(STRK|USDC)\/USD$/),
  oracleAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
  summaryStatsAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
  blockNumber: atomicAmountSchema,
  blockTimestamp: z.string().datetime(),
  quoteDecimals: z.literal(6),
  spotMedianPriceAtomic: atomicAmountSchema,
  twapPriceAtomic: atomicAmountSchema,
  selectedPriceAtomic: atomicAmountSchema,
  conservativePriceAtomic: atomicAmountSchema,
  selectionRule: z.literal("min_spot_median_twap"),
  twapWindowSeconds: z.number().int().min(300).max(86_400),
  haircutBps: z.number().int().min(0).max(5_000),
  observedAt: z.string().datetime(),
  sourceCount: z.number().int().min(1).max(255),
  minimumSourceCount: z.number().int().min(1).max(255),
  maximumAgeSeconds: z.number().int().positive().max(3_600),
}).strict().superRefine((snapshot, context) => {
  const selected = BigInt(snapshot.selectedPriceAtomic);
  const expectedSelected = BigInt(snapshot.spotMedianPriceAtomic) < BigInt(snapshot.twapPriceAtomic)
    ? BigInt(snapshot.spotMedianPriceAtomic)
    : BigInt(snapshot.twapPriceAtomic);
  if (selected !== expectedSelected) {
    context.addIssue({ code: "custom", path: ["selectedPriceAtomic"], message: "Selected FX value must be the lower of spot median and TWAP." });
  }
  const expectedConservative = selected * BigInt(10_000 - snapshot.haircutBps) / 10_000n;
  if (BigInt(snapshot.conservativePriceAtomic) !== expectedConservative) {
    context.addIssue({ code: "custom", path: ["conservativePriceAtomic"], message: "Conservative FX value does not match the committed haircut." });
  }
  if (snapshot.sourceCount < snapshot.minimumSourceCount) {
    context.addIssue({ code: "custom", path: ["sourceCount"], message: "Pragma FX snapshot has too few aggregated sources." });
  }
  const blockTime = new Date(snapshot.blockTimestamp).getTime();
  const observationTime = new Date(snapshot.observedAt).getTime();
  const ageSeconds = (blockTime - observationTime) / 1_000;
  if (ageSeconds < 0 || ageSeconds > snapshot.maximumAgeSeconds) {
    context.addIssue({ code: "custom", path: ["observedAt"], message: "Pragma FX snapshot is stale or future-dated at its pinned block." });
  }
});
export type PragmaProtectedFxSnapshot = z.infer<typeof pragmaProtectedFxSnapshotSchema>;

export function buildPragmaProtectedFxSnapshot(input: Omit<
  PragmaProtectedFxSnapshot,
  "snapshotVersion" | "selectionRule" | "selectedPriceAtomic" | "conservativePriceAtomic"
>): PragmaProtectedFxSnapshot {
  const spot = BigInt(atomicAmountSchema.parse(input.spotMedianPriceAtomic));
  const twap = BigInt(atomicAmountSchema.parse(input.twapPriceAtomic));
  if (spot === 0n || twap === 0n) throw new Error("Pragma returned a zero FX value.");
  const selected = spot < twap ? spot : twap;
  return pragmaProtectedFxSnapshotSchema.parse({
    ...input,
    snapshotVersion: "payo-pragma-fx-snapshot-v2",
    selectionRule: "min_spot_median_twap",
    selectedPriceAtomic: selected.toString(),
    conservativePriceAtomic: (selected * BigInt(10_000 - input.haircutBps) / 10_000n).toString(),
  });
}

export function pragmaProtectedFxSnapshotCommitment(
  snapshotInput: PragmaProtectedFxSnapshot,
): `0x${string}` {
  const snapshot = pragmaProtectedFxSnapshotSchema.parse(snapshotInput);
  return toHex(keccak_256(utf8(stableJson(snapshot))));
}

/**
 * Adapts the fully validated Phase 3 observation into PayrollIntegrity's fixed
 * v1 witness without dropping its provenance. The feed identifier commits the
 * entire protected snapshot (oracle addresses, pinned block, median, TWAP,
 * selection rule, freshness, source count, and haircut).
 */
export function protectedFxSnapshotToPayrollSnapshot(
  snapshotInput: PragmaProtectedFxSnapshot,
): FxSnapshot {
  const snapshot = pragmaProtectedFxSnapshotSchema.parse(snapshotInput);
  const protectedCommitment = pragmaProtectedFxSnapshotCommitment(snapshot);
  return buildFxSnapshot({
    baseToken: snapshot.baseToken,
    referenceCurrency: snapshot.referenceCurrency,
    quoteDecimals: snapshot.quoteDecimals,
    haircutBps: snapshot.haircutBps,
    maximumAgeSeconds: snapshot.maximumAgeSeconds,
    minimumSources: snapshot.minimumSourceCount,
    aggregatedSourceCount: snapshot.sourceCount,
    feedId: `pragma-protected-v2:${snapshot.pairId}:${protectedCommitment}`,
    quotes: [{
      source: `pragma-protected-v2:${snapshot.pairId.toLowerCase()}`,
      priceAtomic: snapshot.selectedPriceAtomic,
      observedAt: snapshot.observedAt,
    }],
    now: new Date(snapshot.blockTimestamp),
  });
}

export function buildFxSnapshot(input: {
  baseToken: "STRK" | "USDC";
  referenceCurrency: string;
  quoteDecimals: number;
  haircutBps: number;
  maximumAgeSeconds: number;
  minimumSources: number;
  aggregatedSourceCount?: number;
  feedId?: string;
  quotes: Array<z.infer<typeof sourceQuoteSchema>>;
  now?: Date;
}): FxSnapshot {
  const now = input.now ?? new Date();
  const sourceCount = input.aggregatedSourceCount ?? input.quotes.length;
  if (sourceCount < input.minimumSources) throw new Error("FX snapshot has too few independent sources.");
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
    ...(input.aggregatedSourceCount === undefined
      ? {}
      : { aggregatedSourceCount: input.aggregatedSourceCount }),
  });
}

export type CircuitFxSnapshot = {
  token: 0 | 1;
  tokenDecimals: 18 | 6;
  referenceCurrency: 0 | 1;
  quoteDecimals: 6;
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
  if (snapshot.quoteDecimals !== 6) {
    throw new Error("PayrollIntegrity v1 requires 6-decimal USD/GBP reference values.");
  }
  const referenceCurrency = snapshot.referenceCurrency === "USD"
    ? 0
    : snapshot.referenceCurrency === "GBP"
      ? 1
      : undefined;
  if (referenceCurrency === undefined) {
    throw new Error(`Unsupported circuit reference currency: ${snapshot.referenceCurrency}.`);
  }
  const sortedSources = [...snapshot.sources].sort((left, right) => left.source.localeCompare(right.source));
  const sourceCount = snapshot.aggregatedSourceCount ?? snapshot.sources.length;
  return {
    token: snapshot.baseToken === "STRK" ? 0 : 1,
    tokenDecimals: snapshot.baseToken === "STRK" ? 18 : 6,
    referenceCurrency,
    quoteDecimals: 6,
    feedCommitment: toHex(hashTextCommitment("PAYO_FX_FEED_V1", snapshot.feedId)),
    sourcesCommitment: toHex(hashTextCommitment(
      "PAYO_FX_SOURCES_V1",
      stableJson(snapshot.aggregatedSourceCount === undefined
        ? sortedSources
        : { aggregatedSourceCount: sourceCount, observations: sortedSources }),
    )),
    priceNumerator: snapshot.medianPriceAtomic,
    priceDenominator: (10n ** BigInt(snapshot.baseToken === "STRK" ? 18 : 6)).toString(),
    observedAt: Math.floor(new Date(snapshot.observedAt).getTime() / 1000).toString(),
    sourceCount,
    minimumSourceCount: snapshot.minimumSourceCount,
    maximumAgeSeconds: snapshot.maximumAgeSeconds.toString(),
    haircutBps: snapshot.haircutBps,
  };
}

export function fxSnapshotCommitment(snapshot: FxSnapshot): `0x${string}` {
  const compiled = toCircuitFxSnapshot(snapshot);
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_FX_SNAPSHOT_V1"),
    Uint8Array.of(
      compiled.token,
      compiled.tokenDecimals,
      compiled.referenceCurrency,
      compiled.quoteDecimals,
    ),
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

export function fxCatalogPublicationWindow(snapshotsInput: readonly FxSnapshot[]): {
  observedAt: number;
  maximumAgeSeconds: number;
  expiresAt: number;
} {
  if (snapshotsInput.length < 1 || snapshotsInput.length > 2) {
    throw new Error("An FX catalog publication requires 1–2 snapshots.");
  }
  const snapshots = snapshotsInput.map((snapshot) => fxSnapshotSchema.parse(snapshot));
  const observedAt = Math.max(...snapshots.map((snapshot) =>
    Math.floor(new Date(snapshot.observedAt).getTime() / 1_000)));
  const expiresAt = Math.min(...snapshots.map((snapshot) =>
    Math.floor(new Date(snapshot.observedAt).getTime() / 1_000) + snapshot.maximumAgeSeconds));
  const maximumAgeSeconds = expiresAt - observedAt;
  if (maximumAgeSeconds <= 0 || maximumAgeSeconds > 3_600) {
    throw new Error("The FX catalog does not share a valid publication window of at most one hour.");
  }
  return { observedAt, maximumAgeSeconds, expiresAt };
}
