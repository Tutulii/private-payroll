import { describe, expect, it } from "vitest";
import {
  assertPayoPhase3V2UpgradePlan,
  assertV2UpgradeProofSummary,
  buildPayoPhase3V2UpgradePlan,
  v2UpgradeDeploymentPayloads,
} from "./payo-phase3-v2-upgrade.mjs";

const numHex = (value) => `0x${value.toString(16)}`;

const artifact = (classHash) => ({
  classHash,
  compiledClassHash: `${classHash}1`,
  sierraSha256: "a".repeat(64),
  casmSha256: "b".repeat(64),
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
  verifierProfiles: [
    { mode: 0, proofVersion: 2, address: "0x26002" },
    { mode: 2, proofVersion: 3, address: "0x26003" },
    { mode: 3, proofVersion: 4, address: "0x26004" },
  ],
};
const liveVerification = { passed: true };
const advancedVerifierArtifact = artifact("0x201");
const integrityBundleArtifact = artifact("0x202");

describe("Phase 3 merged-v2 Mainnet upgrade plan", () => {
  it("binds a new single-verifier bundle to the verified tenant-aware topology", () => {
    const plan = buildPayoPhase3V2UpgradePlan({
      livePlan,
      liveVerification,
      advancedVerifierArtifact,
      integrityBundleArtifact,
      generatedAt: "2026-08-28T00:00:00.000Z",
    });
    expect(plan.liveTopology.payrollSeal.address).toBe("0x603c6");
    expect(plan.liveTopology.previousAdvancedBundle).toBe("0x26002");
    expect(plan.contracts.advancedBundle.constructorCalldata).toEqual([
      plan.contracts.advancedVerifier.address,
    ]);
    expect(plan.contracts.advancedBundle.classHash).toBe("0x202");
    expect(plan.circuit.measuredProofCalldataFelts).toBeLessThanOrEqual(
      plan.circuit.maximumProofCalldataFelts,
    );
    expect(() => assertPayoPhase3V2UpgradePlan(plan, {
      livePlan,
      liveVerification,
      advancedVerifierArtifact,
      integrityBundleArtifact,
    })).not.toThrow();
  });

  it("fails closed when reviewed artifact identity changes", () => {
    const plan = buildPayoPhase3V2UpgradePlan({
      livePlan,
      liveVerification,
      advancedVerifierArtifact,
      integrityBundleArtifact,
    });
    expect(() => assertPayoPhase3V2UpgradePlan(plan, {
      livePlan,
      liveVerification,
      advancedVerifierArtifact: artifact("0x999"),
      integrityBundleArtifact,
    })).toThrow(/stale or was modified/);
  });

  it("creates only the verifier and one-verifier bundle deployments", () => {
    const plan = buildPayoPhase3V2UpgradePlan({
      livePlan,
      liveVerification,
      advancedVerifierArtifact,
      integrityBundleArtifact,
    });
    expect(v2UpgradeDeploymentPayloads(plan).map(({ name }) => name)).toEqual([
      "advancedVerifier",
      "advancedBundle",
    ]);
  });

  it("accepts only proof summaries bound to the live seal, chain and calldata budget", () => {
    const plan = buildPayoPhase3V2UpgradePlan({
      livePlan,
      liveVerification,
      advancedVerifierArtifact,
      integrityBundleArtifact,
    });
    const common = {
      chainId: plan.chainId,
      sealAddress: plan.liveTopology.payrollSeal.address,
      proofVersion: "0x2",
      schemaVersion: "0x1",
      agreementRootHigh: "0x1",
      agreementRootLow: "0x2",
    };
    const summary = {
      circuitSha256: plan.circuit.circuitSha256,
      shards: [0, 1].map((shardIndex) => ({
        shardIndex,
        proofCalldataFelts: 3_223,
        resultingInvokeCalldataFelts: 3_231,
        publicInputs: { ...common, shardIndex: numHex(shardIndex) },
      })),
    };
    expect(() => assertV2UpgradeProofSummary(plan, summary)).not.toThrow();
    const wrongSeal = structuredClone(summary);
    wrongSeal.shards[1].publicInputs.sealAddress = "0x999";
    expect(() => assertV2UpgradeProofSummary(plan, wrongSeal)).toThrow(/deployment binding/);

    const missingInvokeSize = structuredClone(summary);
    delete missingInvokeSize.shards[0].resultingInvokeCalldataFelts;
    expect(() => assertV2UpgradeProofSummary(plan, missingInvokeSize)).toThrow(/calldata budget/);

    const inconsistentInvokeSize = structuredClone(summary);
    inconsistentInvokeSize.shards[1].resultingInvokeCalldataFelts = 3_232;
    expect(() => assertV2UpgradeProofSummary(plan, inconsistentInvokeSize)).toThrow(/calldata budget/);
  });

});
