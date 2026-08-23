import { z } from "zod";
import { hashTextCommitment } from "@/lib/crypto/commitments";
import { stableJson, toHex } from "@/lib/crypto/encoding";
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
  quoteDecimals: z.number().int().min(0).max(18),
  medianPriceAtomic: atomicAmountSchema,
  conservativePriceAtomic: atomicAmountSchema,
  haircutBps: z.number().int().min(0).max(5000),
  observedAt: z.string().datetime(),
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
    quoteDecimals: input.quoteDecimals,
    medianPriceAtomic: median.toString(),
    conservativePriceAtomic: conservative.toString(),
    haircutBps: input.haircutBps,
    observedAt: latestCommonTime.toISOString(),
    sources: input.quotes,
  });
}

export function fxSnapshotCommitment(snapshot: FxSnapshot): `0x${string}` {
  return toHex(hashTextCommitment("PAYO_FX_SNAPSHOT_V1", stableJson(fxSnapshotSchema.parse(snapshot))));
}
