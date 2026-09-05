import { describe, expect, it } from "vitest";
import {
  assertPayoVestingBookMainnetPlan,
  buildPayoVestingBookMainnetPlan,
  vestingBookDeploymentPayloads,
} from "./payo-vesting-book-mainnet.mjs";

function artifact(classHash) {
  return {
    classHash,
    compiledClassHash: `0x${(BigInt(classHash) + 1n).toString(16)}`,
    sierraSha256: "11".repeat(32),
    casmSha256: "22".repeat(32),
  };
}

function context() {
  const livePlan = {
    network: "starknet-mainnet",
    chainId: "0x534e5f4d41494e",
    poolAddress: "0x100",
    deployerAddress: "0x200",
    contracts: {
      policyRegistry: { address: "0x300", classHash: "0x301" },
      obligationRegistry: { address: "0x400", classHash: "0x401" },
    },
  };
  return {
    livePlan,
    liveVerification: { passed: true },
    v2UpgradeEvidence: {
      network: "starknet-mainnet",
      plan: {
        chainId: livePlan.chainId,
        liveTopology: { policyRegistry: { address: "0x300" } },
      },
      activation: { activeBundle: "0x500" },
      verification: { passed: true },
    },
    exceptionEvidence: {
      network: "starknet-mainnet",
      plan: {
        chainId: livePlan.chainId,
        liveTopology: { policyRegistry: { address: "0x300" } },
        contracts: {
          exceptionSeal: { address: "0x550", classHash: "0x551" },
        },
      },
      verification: { passed: true },
    },
    vestingVerifierArtifact: artifact("0x600"),
    vestingBundleArtifact: artifact("0x700"),
    vestingBookSealArtifact: artifact("0x800"),
  };
}

describe("VestingBook Mainnet plan", () => {
  it("builds three deterministic, non-colliding production deployments", () => {
    const input = context();
    const plan = buildPayoVestingBookMainnetPlan({
      ...input,
      generatedAt: "2026-09-04T00:00:00.000Z",
    });
    expect(() => assertPayoVestingBookMainnetPlan(plan, input)).not.toThrow();
    expect(vestingBookDeploymentPayloads(plan).map(({ name }) => name)).toEqual([
      "vestingVerifier",
      "vestingBundle",
      "vestingBookSeal",
    ]);
    expect(plan.contracts.vestingBundle.constructorCalldata).toEqual([
      plan.contracts.vestingVerifier.address,
    ]);
    expect(plan.contracts.vestingBookSeal.constructorCalldata).toEqual([
      plan.poolAddress,
      plan.reusedTopology.policyRegistry.address,
      plan.reusedTopology.obligationRegistry.address,
      plan.reusedTopology.exceptionSeal.address,
      plan.chainId,
    ]);
    expect(plan.circuit).toMatchObject({
      publicInputCount: 58,
      circuitSha256: "0xbb1a8029e604de7b47a28f2ab7dc49f7a3859bc0c3c66b4bf502bdb1b943aec6",
      verificationKeySha256: "0xafad41c9d11ec920fe9cb091b04dc4ed092d2dfee561444a95b2af855ae80a20",
      measuredProofCalldataFelts: 3269,
    });
    expect(plan.circuit.measuredProofCalldataFelts).toBeLessThanOrEqual(4992);
  });

  it("rejects plan mutation and unverified v2 or exception dependencies", () => {
    const input = context();
    const plan = buildPayoVestingBookMainnetPlan(input);
    const changed = structuredClone(plan);
    changed.contracts.vestingBookSeal.address = "0x999";
    expect(() => assertPayoVestingBookMainnetPlan(changed, input)).toThrow(/stale or modified/);
    expect(() => buildPayoVestingBookMainnetPlan({
      ...input,
      v2UpgradeEvidence: { ...input.v2UpgradeEvidence, verification: { passed: false } },
    })).toThrow(/active PayrollIntegrity v2/);
    expect(() => buildPayoVestingBookMainnetPlan({
      ...input,
      exceptionEvidence: { ...input.exceptionEvidence, verification: { passed: false } },
    })).toThrow(/wage-exception seal/);
  });
});
