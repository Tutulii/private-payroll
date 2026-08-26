import { describe, expect, it } from "vitest";
import {
  buildFxSnapshot,
  buildPragmaProtectedFxSnapshot,
  fxCatalogPublicationWindow,
  fxSnapshotCommitment,
  pragmaProtectedFxSnapshotCommitment,
  protectedFxSnapshotToPayrollSnapshot,
  toCircuitFxSnapshot,
} from "./fx";

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

  it("uses the shared freshness intersection for a mixed-token FX root", () => {
    const strk = buildFxSnapshot({
      baseToken: "STRK", referenceCurrency: "USD", quoteDecimals: 6, haircutBps: 0,
      maximumAgeSeconds: 60, minimumSources: 3, quotes, now,
    });
    const usdc = buildFxSnapshot({
      baseToken: "USDC", referenceCurrency: "USD", quoteDecimals: 6, haircutBps: 0,
      maximumAgeSeconds: 30, minimumSources: 3,
      quotes: quotes.map((quote) => ({ ...quote, observedAt: "2026-08-23T09:59:50.000Z" })),
      now,
    });
    expect(fxCatalogPublicationWindow([strk, usdc])).toEqual({
      observedAt: 1_787_479_190,
      maximumAgeSeconds: 30,
      expiresAt: 1_787_479_220,
    });
  });

  it("commits a block-pinned lower-of-median-and-TWAP value", () => {
    const snapshot = buildPragmaProtectedFxSnapshot({
      baseToken: "STRK",
      referenceCurrency: "USD",
      pairId: "STRK/USD",
      oracleAddress: "0x123",
      summaryStatsAddress: "0x456",
      blockNumber: "13800000",
      blockTimestamp: "2026-08-26T00:00:00.000Z",
      quoteDecimals: 6,
      spotMedianPriceAtomic: "125000",
      twapPriceAtomic: "120000",
      twapWindowSeconds: 1800,
      haircutBps: 100,
      observedAt: "2026-08-25T23:59:30.000Z",
      sourceCount: 5,
      minimumSourceCount: 3,
      maximumAgeSeconds: 300,
    });
    expect(snapshot.selectedPriceAtomic).toBe("120000");
    expect(snapshot.conservativePriceAtomic).toBe("118800");
    expect(pragmaProtectedFxSnapshotCommitment(snapshot)).toMatch(/^0x[0-9a-f]{64}$/);
    const payrollSnapshot = protectedFxSnapshotToPayrollSnapshot(snapshot);
    expect(payrollSnapshot.medianPriceAtomic).toBe("120000");
    expect(payrollSnapshot.conservativePriceAtomic).toBe("118800");
    expect(payrollSnapshot.feedId).toContain(pragmaProtectedFxSnapshotCommitment(snapshot));
    expect(() => protectedFxSnapshotToPayrollSnapshot({
      ...snapshot,
      twapPriceAtomic: "130000",
    })).toThrow(/lower of spot median and TWAP/);
  });

  it("rejects an optimistic selection, stale pinned observation, or weak source set", () => {
    const valid = buildPragmaProtectedFxSnapshot({
      baseToken: "USDC",
      referenceCurrency: "USD",
      pairId: "USDC/USD",
      oracleAddress: "0x123",
      summaryStatsAddress: "0x456",
      blockNumber: "13800000",
      blockTimestamp: "2026-08-26T00:00:00.000Z",
      quoteDecimals: 6,
      spotMedianPriceAtomic: "1001000",
      twapPriceAtomic: "999000",
      twapWindowSeconds: 1800,
      haircutBps: 0,
      observedAt: "2026-08-25T23:59:30.000Z",
      sourceCount: 5,
      minimumSourceCount: 3,
      maximumAgeSeconds: 300,
    });
    expect(() => pragmaProtectedFxSnapshotCommitment({
      ...valid,
      selectedPriceAtomic: "1001000",
    })).toThrow("lower of spot median and TWAP");
    expect(() => pragmaProtectedFxSnapshotCommitment({
      ...valid,
      observedAt: "2026-08-25T23:00:00.000Z",
    })).toThrow("stale");
    expect(() => pragmaProtectedFxSnapshotCommitment({
      ...valid,
      sourceCount: 2,
    })).toThrow("too few");
  });
});
