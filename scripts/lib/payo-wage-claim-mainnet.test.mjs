import { describe, expect, it } from "vitest";
import {
  assertPayoWageClaimMainnetPlan,
  buildPayoWageClaimMainnetPlan,
  wageClaimDeploymentPayloads,
} from "./payo-wage-claim-mainnet.mjs";

const artifact = (seed) => ({
  classHash: `0x${seed}`,
  compiledClassHash: `0x${seed}1`,
  sierraSha256: seed.padEnd(64, "a"),
  casmSha256: seed.padEnd(64, "b"),
});
const livePlan = {
  network: "starknet-mainnet",
  chainId: "0x534e5f4d41494e",
  poolAddress: "0x40337",
  deployerAddress: "0x126a7",
  contracts: {
    policyRegistry: { address: "0x34701", classHash: "0x101" },
    obligationRegistry: { address: "0x44b22", classHash: "0x102" },
    payrollSeal: { address: "0x603c6", classHash: "0x103" },
  },
};
const context = {
  livePlan,
  liveVerification: { passed: true },
  artifacts: {
    snapshotVerifier: artifact("201"),
    claimVerifier: artifact("202"),
    remediationVerifier: artifact("203"),
    exceptionSeal: artifact("204"),
  },
};

describe("wage-claim Mainnet deployment plan", () => {
  it("binds deterministic contracts to the verified live dependencies", () => {
    const plan = buildPayoWageClaimMainnetPlan({
      ...context,
      generatedAt: "2026-08-29T00:00:00.000Z",
    });
    expect(plan.contracts.exceptionSeal.constructorCalldata).toEqual([
      "0x40337", "0x34701", "0x44b22", "0x534e5f4d41494e",
    ]);
    expect(plan.verifierProfiles.map(({ mode, proofVersion }) => [mode, proofVersion]))
      .toEqual([[0, 5], [2, 6], [3, 7]]);
    expect(wageClaimDeploymentPayloads(plan)).toHaveLength(4);
    expect(() => assertPayoWageClaimMainnetPlan(plan, context)).not.toThrow();
  });

  it("rejects a plan after an artifact changes", () => {
    const plan = buildPayoWageClaimMainnetPlan(context);
    const changed = structuredClone(context);
    changed.artifacts.claimVerifier = artifact("999");
    expect(() => assertPayoWageClaimMainnetPlan(plan, changed)).toThrow(/stale or was modified/);
  });
});
