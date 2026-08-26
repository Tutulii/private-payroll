import { describe, expect, it } from "vitest";
import {
  PAYO_PHASE3_MAINNET_CHAIN_ID,
  PAYO_PHASE3_MAINNET_POOL,
  assertPayoPhase3PlanMatchesArtifacts,
  buildPayoPhase3MainnetPlan,
  deploymentPayloads,
  phase3DeclarationOrder,
  phase3VerifierDeploymentOrder,
} from "./payo-phase3-mainnet.mjs";

const hashes = {
  baseVerifier: "0x101",
  advancedVerifier: "0x102",
  claimVerifier: "0x103",
  remediationVerifier: "0x104",
  advancedBundle: "0x105",
  integrityBundle: "0x106",
  policyRegistry: "0x107",
  obligationRegistry: "0x108",
  payrollSeal: "0x109",
};

function artifact(name) {
  return {
    classHash: hashes[name],
    compiledClassHash: `0x2${hashes[name].slice(3)}`,
    sierraSha256: `${name}-sierra`,
    casmSha256: `${name}-casm`,
  };
}

function fixtures() {
  const artifacts = Object.fromEntries(Object.keys(hashes).map((name) => [name, artifact(name)]));
  const phase2Plan = {
    generatedAt: "2026-08-24T00:00:00.000Z",
    chainId: PAYO_PHASE3_MAINNET_CHAIN_ID,
    poolAddress: PAYO_PHASE3_MAINNET_POOL,
    adminAddress: "0x301",
    contracts: {
      generatedVerifier: { address: "0x401", classHash: hashes.baseVerifier },
      bundleVerifier: { address: "0x402", classHash: hashes.integrityBundle },
      policyRegistry: { address: "0x403", classHash: hashes.policyRegistry },
      obligationRegistry: { address: "0x404", classHash: hashes.obligationRegistry },
    },
  };
  return { artifacts, phase2Plan };
}

describe("PAYO Phase 3 Mainnet topology", () => {
  it("builds a deterministic staged topology that reuses the proven Phase 2 boundary", () => {
    const { artifacts, phase2Plan } = fixtures();
    const input = {
      artifacts,
      phase2Plan,
      deployerAddress: "0x501",
      generatedAt: "2026-08-26T00:00:00.000Z",
    };
    const first = buildPayoPhase3MainnetPlan(input);
    const second = buildPayoPhase3MainnetPlan(input);

    expect(first).toEqual(second);
    expect(first.contracts.baseVerifier).toMatchObject({ reuse: true, address: "0x401" });
    expect(first.contracts.policyRegistry).toMatchObject({ reuse: true, address: "0x403" });
    expect(first.contracts.obligationRegistry).toMatchObject({ reuse: true, address: "0x404" });
    expect(Object.keys(first.declarations)).toEqual(phase3DeclarationOrder);
    expect(deploymentPayloads(first, "verifiers").map((item) => item.name)).toEqual(
      phase3VerifierDeploymentOrder,
    );
    expect(deploymentPayloads(first, "seal").map((item) => item.name)).toEqual(["payrollSeal"]);
    expect(first.contracts.payrollSeal.constructorCalldata).toEqual([
      PAYO_PHASE3_MAINNET_POOL,
      "0x403",
      "0x404",
      PAYO_PHASE3_MAINNET_CHAIN_ID,
    ]);
    assertPayoPhase3PlanMatchesArtifacts(first, artifacts);
  });

  it("refuses a Phase 2 class mismatch instead of silently redeploying trusted components", () => {
    const { artifacts, phase2Plan } = fixtures();
    phase2Plan.contracts.policyRegistry.classHash = "0x999";
    expect(() => buildPayoPhase3MainnetPlan({
      artifacts,
      phase2Plan,
      deployerAddress: "0x501",
    })).toThrow(/policy registry artifact does not match/i);
  });

  it("refuses an artifact or constructor change after plan review", () => {
    const { artifacts, phase2Plan } = fixtures();
    const plan = buildPayoPhase3MainnetPlan({
      artifacts,
      phase2Plan,
      deployerAddress: "0x501",
    });
    const changedArtifact = structuredClone(artifacts);
    changedArtifact.claimVerifier.sierraSha256 = "changed";
    expect(() => assertPayoPhase3PlanMatchesArtifacts(plan, changedArtifact)).toThrow(
      /claimVerifier sierraSha256 changed/i,
    );

    const changedConstructor = structuredClone(plan);
    changedConstructor.contracts.payrollSeal.constructorCalldata[0] = "0x777";
    expect(() => assertPayoPhase3PlanMatchesArtifacts(changedConstructor, artifacts)).toThrow(
      /payrollSeal predicted address or constructor changed/i,
    );
  });

  it("rejects unsupported deployment stages", () => {
    const { artifacts, phase2Plan } = fixtures();
    const plan = buildPayoPhase3MainnetPlan({
      artifacts,
      phase2Plan,
      deployerAddress: "0x501",
    });
    expect(() => deploymentPayloads(plan, "all-at-once")).toThrow(/unknown phase 3 deployment stage/i);
  });
});
