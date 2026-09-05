import { describe, expect, it } from "vitest";
import {
  PAYO_PRIVATE_EXIT_ANONYMIZER_ADDRESS,
  PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH,
  assertPayoAnonymizerAbi,
  assertPayoPrivateExitMainnetPlan,
  buildPayoPrivateExitMainnetPlan,
  calculatePayoPrivateExitAddress,
  privateExitDeploymentPayload,
} from "./payo-private-exit-mainnet.mjs";

const upstreamEvidence = {
  schemaVersion: "payo.block5.private-exit.upstream.v1",
  upstream: {
    commit: "bc75e4bac71ad0ce10c6e63effc33b5b25131a4f",
    lockfileSha256: "a",
    anonymizerSourceSha256: "b",
    privacyIntegrationSourceSha256: "c",
  },
  reviewedContract: {
    classHash: PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH,
    releaseArtifactSha256: "d",
  },
  checks: {
    pinnedUpstreamRevision: true,
    releaseClassHashReproduced: true,
    anonymizerAssertions: { passed: 3, failed: 0 },
    strk20OpenNoteSwapComposition: { passed: 1, failed: 0 },
  },
};

const abi = [
  { type: "constructor", name: "constructor", inputs: [] },
  {
    type: "interface",
    name: "ekubo_swap_anonymizer::ekubo_swap_anonymizer::IEkuboSwapAnonymizer",
    items: [{
      type: "function",
      name: "privacy_invoke",
      state_mutability: "external",
      inputs: [
        { type: "core::starknet::contract_address::ContractAddress" },
        { type: "ekubo::interfaces::router::TokenAmount" },
        { type: "ekubo::types::keys::PoolKey" },
        { type: "core::integer::u256" },
        { type: "core::integer::u128" },
        { type: "core::felt252" },
      ],
      outputs: [{ type: "core::array::Span::<privacy::objects::OpenNoteDeposit>" }],
    }],
  },
];

describe("private-exit Mainnet release plan", () => {
  it("locks the exact deterministic empty-constructor address", () => {
    expect(calculatePayoPrivateExitAddress()).toBe(PAYO_PRIVATE_EXIT_ANONYMIZER_ADDRESS);
    const plan = buildPayoPrivateExitMainnetPlan({
      deployerAddress: "0x126a7a572cf8935d069af937e9f7b27a24949e271e1fbccfe4de0c0d8dc8ea9",
      upstreamEvidence,
      generatedAt: "2026-09-05T00:00:00.000Z",
    });
    expect(privateExitDeploymentPayload(plan)).toEqual({
      classHash: PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH,
      constructorCalldata: [],
      salt: plan.deployment.salt,
      unique: false,
    });
    expect(() => assertPayoPrivateExitMainnetPlan(plan, {
      deployerAddress: plan.deployerAddress,
      upstreamEvidence,
    })).not.toThrow();
  });

  it("rejects missing upstream proof and any plan mutation", () => {
    expect(() => buildPayoPrivateExitMainnetPlan({
      deployerAddress: "0x1",
      upstreamEvidence: {
        ...upstreamEvidence,
        checks: { ...upstreamEvidence.checks, releaseClassHashReproduced: false },
      },
    })).toThrow(/upstream/i);
    const plan = buildPayoPrivateExitMainnetPlan({
      deployerAddress: "0x1",
      upstreamEvidence,
      generatedAt: "2026-09-05T00:00:00.000Z",
    });
    plan.deployment.unique = true;
    expect(() => assertPayoPrivateExitMainnetPlan(plan, {
      deployerAddress: "0x1",
      upstreamEvidence,
    })).toThrow(/stale or modified/i);
  });

  it("accepts only the exact empty-constructor privacy_invoke ABI", () => {
    expect(assertPayoAnonymizerAbi(abi)).toBe(true);
    const wrongConstructor = structuredClone(abi);
    wrongConstructor[0].inputs.push({ type: "core::felt252" });
    expect(() => assertPayoAnonymizerAbi(wrongConstructor)).toThrow(/empty constructor/i);
    const wrongInvoke = structuredClone(abi);
    wrongInvoke[1].items[0].inputs[5].type = "core::integer::u256";
    expect(() => assertPayoAnonymizerAbi(wrongInvoke)).toThrow(/privacy_invoke ABI/i);
  });
});
