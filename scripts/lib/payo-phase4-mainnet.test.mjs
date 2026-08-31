import { describe, expect, it } from "vitest";
import {
  assertPayoPhase4MainnetPlan,
  buildPayoPhase4MainnetPlan,
  phase4DeploymentPayloads,
} from "./payo-phase4-mainnet.mjs";

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
  liveVerification: {
    passed: true,
    checks: [{ code: "pool.deployed", passed: true, classHash: "0x100" }],
  },
  policyOwnerPublicKey: "0x456",
  artifacts: {
    settlementVerifier: artifact("201"),
    payrollSeal: artifact("202"),
    policyAccount: artifact("203"),
  },
};

describe("Phase 4 Mainnet deployment plan", () => {
  it("binds three deterministic deployments to verified Phase 3 dependencies", () => {
    const plan = buildPayoPhase4MainnetPlan({
      ...context,
      generatedAt: "2026-08-31T00:00:00.000Z",
    });

    expect(plan.contracts.payrollSeal.constructorCalldata).toEqual([
      "0x40337", "0x34701", "0x44b22", "0x534e5f4d41494e",
    ]);
    expect(plan.contracts.policyAccount.constructorCalldata).toEqual(["0x456"]);
    expect(plan.verifierProfile).toMatchObject({ mode: 1, proofVersion: 8 });
    expect(phase4DeploymentPayloads(plan).map(({ name }) => name)).toEqual([
      "settlementVerifier",
      "payrollSeal",
      "policyAccount",
    ]);
    expect(() => assertPayoPhase4MainnetPlan(plan, context)).not.toThrow();
  });

  it("fails closed after an artifact or reviewed owner changes", () => {
    const plan = buildPayoPhase4MainnetPlan(context);
    const changedArtifact = structuredClone(context);
    changedArtifact.artifacts.payrollSeal = artifact("999");
    expect(() => assertPayoPhase4MainnetPlan(plan, changedArtifact)).toThrow(/stale or modified/);
    expect(() => assertPayoPhase4MainnetPlan(plan, {
      ...context,
      policyOwnerPublicKey: "0x457",
    })).toThrow(/stale or modified/);
  });

  it("rejects an unverified Phase 3 topology and a zero account owner", () => {
    expect(() => buildPayoPhase4MainnetPlan({
      ...context,
      liveVerification: {
        passed: false,
        checks: [{ code: "pool.deployed", passed: true, classHash: "0x100" }],
      },
    })).toThrow(/verified tenant-aware Phase 3 Mainnet topology/);
    expect(() => buildPayoPhase4MainnetPlan({
      ...context,
      policyOwnerPublicKey: "0x0",
    })).toThrow(/must be non-zero/);
  });
});
