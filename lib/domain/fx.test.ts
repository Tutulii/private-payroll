import { describe, expect, it } from "vitest";
import { buildFxSnapshot, fxSnapshotCommitment, toCircuitFxSnapshot } from "./fx";

const now = new Date("2026-08-23T10:00:00.000Z");
const quotes = [
  { source: "oracle-a", priceAtomic: "1000000", observedAt: "2026-08-23T09:59:40.000Z" },
  { source: "oracle-b", priceAtomic: "1100000", observedAt: "2026-08-23T09:59:50.000Z" },
  { source: "oracle-c", priceAtomic: "900000", observedAt: "2026-08-23T09:59:45.000Z" },
];

describe("FX snapshots", () => {
  it("builds a conservative multi-source median", () => {
    const snapshot = buildFxSnapshot({
      baseToken: "STRK",
      referenceCurrency: "USD",
      feedId: "pragma:STRK/USD:median",
      quoteDecimals: 6,
      haircutBps: 500,
      maximumAgeSeconds: 60,
      minimumSources: 3,
      quotes,
      now,
    });
    expect(snapshot.medianPriceAtomic).toBe("1000000");
    expect(snapshot.conservativePriceAtomic).toBe("950000");
    expect(fxSnapshotCommitment(snapshot))
      .toBe("0xae0fd72180780f289bfc5198db38f5050eebc742ae961ed56037ef2e5840be18");
  });

  it("rejects stale, duplicate, and insufficient sources", () => {
    expect(() => buildFxSnapshot({
      baseToken: "STRK", referenceCurrency: "USD", quoteDecimals: 6, haircutBps: 0,
      maximumAgeSeconds: 5, minimumSources: 3, quotes, now,
    })).toThrow("stale");
    expect(() => buildFxSnapshot({
      baseToken: "STRK", referenceCurrency: "USD", quoteDecimals: 6, haircutBps: 0,
      maximumAgeSeconds: 60, minimumSources: 3, quotes: [quotes[0], { ...quotes[1], source: "oracle-a" }, quotes[2]], now,
    })).toThrow("unique");
    expect(() => buildFxSnapshot({
      baseToken: "STRK", referenceCurrency: "USD", quoteDecimals: 6, haircutBps: 0,
      maximumAgeSeconds: 60, minimumSources: 3, quotes: quotes.slice(0, 2), now,
    })).toThrow("too few");
  });

  it("rejects an ambiguous reference-currency scale", () => {
    const snapshot = buildFxSnapshot({
      baseToken: "USDC",
      referenceCurrency: "USD",
      quoteDecimals: 18,
      haircutBps: 0,
      maximumAgeSeconds: 60,
      minimumSources: 3,
      quotes,
      now,
    });
    expect(() => toCircuitFxSnapshot(snapshot)).toThrow("requires 6-decimal");
    expect(() => fxSnapshotCommitment(snapshot)).toThrow("requires 6-decimal");
  });
});
