import { describe, expect, it } from "vitest";
import { validateAndParseAddress } from "starknet";
import {
  PAYO_OBLIGATION_ROOT_LIFETIME_SECONDS,
  PAYO_BASELINE_LIFETIME_SECONDS,
  PAYO_REGISTRY_ACTIVATION_BUFFER_SECONDS,
  PAYO_REGISTRY_MIN_DELAY_SECONDS,
  prepareFxRootPublication,
  preparePayoBaselineSchedule,
  prepareObligationRootSchedule,
} from "./payo-registry";

describe("PAYO obligation-root registry calls", () => {
  it("uses the canonical root limbs and activates at the current block timestamp", () => {
    const root = `0x${"11".repeat(16)}${"22".repeat(16)}`;
    const result = prepareObligationRootSchedule({
      registryAddress: "0x789",
      agreementRoot: root,
      blockTimestamp: 1_000,
    });
    expect(result.validAfter).toBe(
      1_000 + PAYO_REGISTRY_MIN_DELAY_SECONDS + PAYO_REGISTRY_ACTIVATION_BUFFER_SECONDS,
    );
    expect(result.expiresAt).toBe(result.validAfter + PAYO_OBLIGATION_ROOT_LIFETIME_SECONDS);
    expect(result.call).toEqual({
      contractAddress: validateAndParseAddress("0x789"),
      entrypoint: "schedule_obligation_root",
      calldata: [
        BigInt(`0x${"11".repeat(16)}`).toString(),
        BigInt(`0x${"22".repeat(16)}`).toString(),
        result.validAfter.toString(),
        result.expiresAt.toString(),
      ],
    });
  });

  it("rejects malformed roots and unsafe timestamps before a wallet request", () => {
    expect(() => prepareObligationRootSchedule({
      registryAddress: "0x789",
      agreementRoot: "0x123",
      blockTimestamp: 1_000,
    })).toThrow(/canonical 32-byte/);
    expect(() => prepareObligationRootSchedule({
      registryAddress: "0x789",
      agreementRoot: `0x${"11".repeat(32)}`,
      blockTimestamp: Number.MAX_SAFE_INTEGER + 1,
    })).toThrow(/timestamp/);
  });

  it("permits only a fresh, one-hour-or-shorter FX publication", () => {
    const root = `0x${"33".repeat(32)}`;
    expect(prepareFxRootPublication({
      registryAddress: "0x456",
      fxRoot: root,
      observedAt: 990,
      maximumAgeSeconds: 30,
      blockTimestamp: 1_000,
    })).toMatchObject({
      entrypoint: "publish_fx_root",
      calldata: [expect.any(String), expect.any(String), "990", "30"],
    });
    expect(() => prepareFxRootPublication({
      registryAddress: "0x456",
      fxRoot: root,
      observedAt: 900,
      maximumAgeSeconds: 30,
      blockTimestamp: 1_000,
    })).toThrow(/stale/);
    expect(() => prepareFxRootPublication({
      registryAddress: "0x456",
      fxRoot: root,
      observedAt: 990,
      maximumAgeSeconds: 3_601,
      blockTimestamp: 1_000,
    })).toThrow(/3,600/);
  });

  it("activates the canonical policy root and PRECOMMIT verifier in one baseline transaction", () => {
    const root = `0x${"44".repeat(32)}`;
    const result = preparePayoBaselineSchedule({
      registryAddress: "0x456",
      bundleVerifierAddress: "0x789",
      policyRoot: root,
      blockTimestamp: 2_000,
    });
    expect(result.validAfter).toBe(
      2_000 + PAYO_REGISTRY_MIN_DELAY_SECONDS + PAYO_REGISTRY_ACTIVATION_BUFFER_SECONDS,
    );
    expect(result.expiresAt).toBe(result.validAfter + PAYO_BASELINE_LIFETIME_SECONDS);
    expect(result.calls.map(({ entrypoint }) => entrypoint)).toEqual([
      "schedule_policy_root",
      "schedule_verifier",
    ]);
    expect(result.calls[1].calldata).toEqual([
      "0",
      "1",
      validateAndParseAddress("0x789"),
      result.validAfter.toString(),
      result.expiresAt.toString(),
    ]);
  });
});
