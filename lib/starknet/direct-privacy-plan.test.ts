import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type {
  DirectPrivacyAccountConfig,
  DirectPrivacyRunMaterial,
} from "@/lib/domain/direct-privacy";
import {
  mapPayrollPublicInputs,
  type PayrollIntegrityShardProof,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import {
  assertDirectPrivacySdkResult,
  assertDirectPrivacySdkResultBindings,
  buildDirectPrivacyPlan,
  buildDirectPrivacyPolicyCall,
} from "./direct-privacy-plan";

const PUBLIC_INPUTS = [
  "0x1", "0x12345", "0x1", "0x1",
  "0x21ccf78b37818195a99011a0becd63c0", "0x2cd00396a065125a9fdbfa4fe694267f",
  "0x14bc023ba6616464d80762f3a3cd18cb", "0x402c1a1f63dcce95568decb9f442e19",
  "0x2268a0aded87d370810a4fa92f02dd24", "0xadf09af7b56c56d740df4ea601696b33",
  "0x1ed06ee71227267e051c4da3b3da51ea", "0xe7c38e7b0170fb183bbb36aa361d1049",
  "0x64142157a0d39df1051bf01190a707ef", "0x56c538e09b32afbef3ba098c37e630ba",
  "0x3f2", "0x7d0",
] as const;

const joinRoot = (high: string, low: string) =>
  `0x${((BigInt(high) << 128n) | BigInt(low)).toString(16).padStart(64, "0")}` as `0x${string}`;

function shard(shardIndex: 0 | 1): PayrollIntegrityShardProof {
  const proofCalldata = readFileSync(
    new URL(`../../contracts/integrity_verifier/tests/proof_calldata-shard-${shardIndex}.txt`, import.meta.url),
    "utf8",
  ).trim().split(/\s+/);
  return {
    shardIndex,
    proof: new Uint8Array(),
    proofCalldata,
    calldataHash: hashProofCalldata(proofCalldata),
    publicInputs: mapPayrollPublicInputs([...PUBLIC_INPUTS, `0x${shardIndex}`]),
  };
}

const config: DirectPrivacyAccountConfig = {
  version: "payo-direct-privacy-account-v1",
  chainId: "0x1",
  policyAccountAddress: "0x777",
  policyId: "0x888",
  sessionPublicKey: "0x999",
  sealMode: 0,
  proofVersion: 1,
  schemaVersion: 1,
  payrollPolicyRoot: joinRoot(PUBLIC_INPUTS[8], PUBLIC_INPUTS[9]),
  tokenSetCommitment: "0x10",
  recipientSetCommitment: "0x11",
  purposeCommitment: "0x12",
  amountLimitCommitment: "0x13",
  authorizedRunsRoot: "0x14",
  validAfterUnix: "1",
  validBeforeUnix: "9999999999",
  periodSeconds: "86400",
  maxCallsPerPeriod: 5,
  maxCallCount: 5,
  poolAddress: "0xabc",
  sealAddress: "0x12345",
  tokenAddresses: { STRK: "0x111", USDC: "0x222" },
  sdkVersion: "0.14.3-rc.5",
  sdkRevision: "66e3caae8c0201227a6719696d004e30d90aea65",
};

const material = {
  version: "payo-direct-privacy-run-v1",
  organizationId: "organization-0001",
  capabilityId: "capability-0001",
  runId: "payroll-run-0001",
  runVersion: 1,
  requestCommitment: `0x${"11".repeat(32)}`,
  authoritativeRequest: {
    requestVersion: "payo-agent-execution-v1",
    runId: "payroll-run-0001",
    intents: [
      {
        intentVersion: "payo-payment-intent-v1",
        intentId: "intent-strk-0001",
        organizationId: "organization-0001",
        runId: "payroll-run-0001",
        action: "request_execution",
        token: "STRK",
        recipientAddress: "0x456",
        amountAtomic: "100",
        purposeCode: "private_payroll",
        capabilityNonce: "capability-nonce-0001",
        createdAt: "2026-08-30T00:00:00.000Z",
        validUntil: "2026-08-30T00:05:00.000Z",
      },
      {
        intentVersion: "payo-payment-intent-v1",
        intentId: "intent-usdc-0002",
        organizationId: "organization-0001",
        runId: "payroll-run-0001",
        action: "request_execution",
        token: "USDC",
        recipientAddress: "0x654",
        amountAtomic: "200",
        purposeCode: "private_payroll",
        capabilityNonce: "capability-nonce-0001",
        createdAt: "2026-08-30T00:00:00.000Z",
        validUntil: "2026-08-30T00:05:00.000Z",
      },
    ],
  },
  encryptedWitness: {},
  policyRun: {
    agreementRoot: joinRoot(PUBLIC_INPUTS[4], PUBLIC_INPUTS[5]),
    manifestRoot: joinRoot(PUBLIC_INPUTS[6], PUBLIC_INPUTS[7]),
    runNullifier: joinRoot(PUBLIC_INPUTS[12], PUBLIC_INPUTS[13]),
    pathBits: 3,
    siblings: Array.from({ length: 8 }, (_, index) => `0x${index + 1}`),
  },
} as unknown as DirectPrivacyRunMaterial;

const payrollProof: ProofWorkerSuccess = {
  version: 1,
  type: "proof-complete",
  requestId: "request-0001",
  scheme: "ultra_keccak_zk_honk",
  shards: [shard(0), shard(1)],
  circuitSha256: "test-circuit",
  provingTimeMs: 1,
};

describe("direct private SDK execution plan", () => {
  it("builds only authoritative private notes and change after proof-first sealing", () => {
    const plan = buildDirectPrivacyPlan({ config, material, payrollProof, nowUnixSeconds: 1_500n });
    expect(plan.actions.createNotes).toEqual([
      { recipient: 0x456n, token: 0x111n, amount: 100n },
      { recipient: 0x654n, token: 0x222n, amount: 200n },
    ]);
    expect(plan.actions.surpluses).toEqual([
      { recipient: 0x777n, token: 0x111n, withdraw: false },
      { recipient: 0x777n, token: 0x222n, withdraw: false },
    ]);
    expect(plan.actions).not.toHaveProperty("invoke");
    expect(plan.sealedPayroll.invokeAction.calldata).toEqual(
      expect.arrayContaining(["0x0", "0x1"]),
    );
  });

  it("rejects a proof whose owner-authorized roots were substituted", () => {
    expect(() => buildDirectPrivacyPlan({
      config,
      material: {
        ...material,
        policyRun: { ...material.policyRun, manifestRoot: `0x${"99".repeat(32)}` },
      },
      payrollProof,
      nowUnixSeconds: 1_500n,
    })).toThrow("proved manifest root");
  });

  it("accepts only proof-bound apply_actions calldata without screening or warnings", () => {
    const result = {
      callAndProof: {
        call: { contractAddress: "0xabc", entrypoint: "apply_actions", calldata: ["0x2", "0x3", "0x1"] },
        proof: { data: "base64-proof-data-long", output: ["0xfeed", "0x2", "0x3"], proofFacts: ["0x4"] },
      },
      warnings: [],
    };
    expect(() => assertDirectPrivacySdkResult({ result, poolAddress: "0xabc" })).not.toThrow();
    expect(() => assertDirectPrivacySdkResult({
      result: {
        ...result,
        callAndProof: { ...result.callAndProof, call: { ...result.callAndProof.call, contractAddress: "0xdef" } },
      },
      poolAddress: "0xabc",
    })).toThrow("substituted pool target");
    expect(() => assertDirectPrivacySdkResult({
      result: {
        ...result,
        callAndProof: { ...result.callAndProof, call: { ...result.callAndProof.call, calldata: ["0x2", "0x9", "0x1"] } },
      },
      poolAddress: "0xabc",
    })).toThrow("not bound to the prover output");
    const noTransactionProof = {
      ...result,
      callAndProof: {
        ...result.callAndProof,
        proof: { ...result.callAndProof.proof, data: undefined as unknown as string },
      },
    };
    expect(() => assertDirectPrivacySdkResultBindings({
      result: noTransactionProof,
      poolAddress: "0xabc",
    })).not.toThrow();
    expect(() => assertDirectPrivacySdkResult({
      result: noTransactionProof,
      poolAddress: "0xabc",
    })).toThrow("did not return a transaction proof");
  });

  it("encodes the sole policy gateway with exact roots, Merkle path and pool span", () => {
    const settlementProofChunks = [{
      chunkIndex: 0,
      chunkCount: 1,
      proofCalldata: ["0xa", "0xb"],
    }];
    const call = buildDirectPrivacyPolicyCall({
      config,
      material,
      poolCalldata: ["0x2", "0x3", "0x1"],
      settlementProofChunks,
    });
    expect(call).toMatchObject({ contractAddress: expect.stringMatching(/777$/), entrypoint: "execute_policy_intent" });
    expect(call.calldata).toEqual([
      "0x888",
      PUBLIC_INPUTS[4], PUBLIC_INPUTS[5],
      PUBLIC_INPUTS[6], PUBLIC_INPUTS[7],
      PUBLIC_INPUTS[12], PUBLIC_INPUTS[13],
      "0x3", "0x8",
      "0x1", "0x2", "0x3", "0x4", "0x5", "0x6", "0x7", "0x8",
      "0x3", "0x2", "0x3", "0x1",
      "0x2", "0xa", "0xb",
    ]);

    expect(() => buildDirectPrivacyPolicyCall({
      config,
      material,
      poolCalldata: ["0x2", "0x3", "0x1"],
      settlementProofChunks: [],
    })).toThrow("exactly one atomic SettlementMatch chunk");
    expect(() => buildDirectPrivacyPolicyCall({
      config,
      material,
      poolCalldata: ["0x2", "0x3", "0x1"],
      settlementProofChunks: [
        ...settlementProofChunks,
        { chunkIndex: 1, chunkCount: 2, proofCalldata: ["0xc"] },
      ],
    })).toThrow("exactly one atomic SettlementMatch chunk");
    expect(() => buildDirectPrivacyPolicyCall({
      config,
      material,
      poolCalldata: Array.from({ length: 1_800 }, () => "0x1"),
      settlementProofChunks: [{
        chunkIndex: 0,
        chunkCount: 1,
        proofCalldata: Array.from({ length: 3_200 }, () => "0x2"),
      }],
    })).toThrow("invoke calldata limit");
  });
});
