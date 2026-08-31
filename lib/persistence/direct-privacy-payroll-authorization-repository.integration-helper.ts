import { expect, it } from "vitest";
import type { DirectPrivacyPayrollAuthorization } from "@/lib/domain/direct-privacy";
import { PAYROLL_INTEGRITY_CIRCUIT_SHA256 } from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { requestAgentExecution } from "./agent-execution-repository";
import { leaseAgentExecutions } from "./agent-execution-worker-repository";
import {
  loadDirectPrivacyPayrollAuthorization,
  recordDirectPrivacyPayrollAuthorizationProgress,
  storeDirectPrivacyPayrollAuthorization,
} from "./direct-privacy-payroll-authorization-repository";
import {
  leaseDirectPrivacyExecutionContext,
  stageDirectPrivacyRunWitness,
} from "./direct-privacy-repository";
import { fixture, now, principal } from "./direct-privacy-repository.integration-helper";
import { getDatabase } from "./db";
import { directPrivacyPayrollAuthorizations } from "./schema";

const mask128 = (1n << 128n) - 1n;

function split(value: string): [string, string] {
  const parsed = BigInt(value);
  return [(parsed >> 128n).toString(), (parsed & mask128).toString()];
}

async function authorizationFixture() {
  const input = await fixture();
  await stageDirectPrivacyRunWitness({
    accountId: input.account.id,
    encryptedWitness: input.material.encryptedWitness,
    principal,
    now,
  });
  await requestAgentExecution({
    capabilityId: input.capability.id,
    idempotencyKey: "direct-payroll-auth:" + input.runId,
    request: input.request,
    principal,
    now,
  });
  const [job] = await leaseAgentExecutions("direct-payroll-auth-worker", 1, now);
  const context = await leaseDirectPrivacyExecutionContext(job, now);
  const [agreementRootHigh, agreementRootLow] = split(input.material.policyRun.agreementRoot);
  const [manifestRootHigh, manifestRootLow] = split(input.material.policyRun.manifestRoot);
  const [policyRootHigh, policyRootLow] = split(context.config.payrollPolicyRoot);
  const [runNullifierHigh, runNullifierLow] = split(input.material.policyRun.runNullifier);
  const [fxRootHigh, fxRootLow] = split("0x" + "33".repeat(32));
  const proofCalldata = [["0xabc123", "0x1"], ["0xdef456", "0x2"]] as const;
  const hashes = proofCalldata.map(hashProofCalldata) as [string, string];
  const common = {
    chainId: context.config.chainId,
    sealAddress: context.config.sealAddress,
    proofVersion: String(context.config.proofVersion),
    schemaVersion: String(context.config.schemaVersion),
    agreementRootHigh,
    agreementRootLow,
    manifestRootHigh,
    manifestRootLow,
    policyRootHigh,
    policyRootLow,
    fxRootHigh,
    fxRootLow,
    runNullifierHigh,
    runNullifierLow,
    validityStart: "1000",
    validityExpiry: "2000",
  };
  const precommitCalldata = [
    common.proofVersion,
    common.schemaVersion,
    common.agreementRootHigh,
    common.agreementRootLow,
    common.manifestRootHigh,
    common.manifestRootLow,
    common.policyRootHigh,
    common.policyRootLow,
    common.fxRootHigh,
    common.fxRootLow,
    common.runNullifierHigh,
    common.runNullifierLow,
    common.validityStart,
    common.validityExpiry,
    hashes[0],
    hashes[1],
  ].map((value) => `0x${BigInt(value).toString(16)}` as `0x${string}`);
  const authorization: DirectPrivacyPayrollAuthorization = {
    version: "payo-direct-payroll-authorization-v1",
    executionId: job.id,
    requestCommitment: job.requestCommitment as `0x${string}`,
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    precommitCall: {
      contractAddress: context.config.sealAddress,
      entrypoint: "precommit_direct",
      calldata: precommitCalldata,
    },
    shards: [{
      shardIndex: 0,
      proofCalldata: [...proofCalldata[0]],
      calldataHash: hashes[0] as `0x${string}`,
      publicInputs: { ...common, shardIndex: "0" },
    }, {
      shardIndex: 1,
      proofCalldata: [...proofCalldata[1]],
      calldataHash: hashes[1] as `0x${string}`,
      publicInputs: { ...common, shardIndex: "1" },
    }],
  };
  return { input, job, context, authorization };
}

export function registerDirectPrivacyPayrollAuthorizationRepositoryIntegrationTests(): void {
  it("encrypts one exact payroll proof before precommit and recovers progress", async () => {
    const value = await authorizationFixture();
    const stored = await storeDirectPrivacyPayrollAuthorization({
      accountId: value.context.accountId,
      organizationId: value.input.organizationId,
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      authorization: value.authorization,
      now,
    });
    await expect(storeDirectPrivacyPayrollAuthorization({
      accountId: value.context.accountId,
      organizationId: value.input.organizationId,
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      authorization: value.authorization,
      now,
    })).resolves.toEqual({ ...stored, replayed: true });
    const [row] = await getDatabase().select().from(directPrivacyPayrollAuthorizations);
    expect(JSON.stringify(row)).not.toContain("abc123");
    await expect(loadDirectPrivacyPayrollAuthorization(value.job.id)).resolves.toMatchObject({
      authorization: {
        shards: value.authorization.shards.map(({ calldataHash }) => ({ calldataHash })),
      },
    });

    await recordDirectPrivacyPayrollAuthorizationProgress({
      executionId: value.job.id,
      state: "sealed",
      transactionHash: "0x101",
      now,
    });
    await recordDirectPrivacyPayrollAuthorizationProgress({
      executionId: value.job.id,
      state: "shard0_verified",
      transactionHash: "0x102",
      now,
    });
    await recordDirectPrivacyPayrollAuthorizationProgress({
      executionId: value.job.id,
      state: "proven",
      transactionHash: "0x103",
      now,
    });
    expect((await getDatabase().select().from(directPrivacyPayrollAuthorizations))[0])
      .toMatchObject({
        state: "proven",
        precommitTransactionHash: "0x101",
        shard0TransactionHash: "0x102",
        shard1TransactionHash: "0x103",
      });
    await expect(recordDirectPrivacyPayrollAuthorizationProgress({
      executionId: value.job.id,
      state: "proven",
      transactionHash: "0x104",
      now,
    })).rejects.toThrow("DIRECT_PAYROLL_AUTHORIZATION_HASH_CONFLICT");
  });

  it("rejects a regenerated payroll proof after the first durable commitment", async () => {
    const value = await authorizationFixture();
    await storeDirectPrivacyPayrollAuthorization({
      accountId: value.context.accountId,
      organizationId: value.input.organizationId,
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      authorization: value.authorization,
      now,
    });
    const proofCalldata = ["0x999", "0x1"] as `0x${string}`[];
    const calldataHash = hashProofCalldata(proofCalldata) as `0x${string}`;
    const changed: DirectPrivacyPayrollAuthorization = {
      ...value.authorization,
      precommitCall: {
        ...value.authorization.precommitCall,
        calldata: value.authorization.precommitCall.calldata.map((felt, index) =>
          index === 14 ? calldataHash : felt),
      },
      shards: [{
        ...value.authorization.shards[0],
        proofCalldata,
        calldataHash,
      }, value.authorization.shards[1]],
    };
    await expect(storeDirectPrivacyPayrollAuthorization({
      accountId: value.context.accountId,
      organizationId: value.input.organizationId,
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      authorization: changed,
      now,
    })).rejects.toThrow("DIRECT_PAYROLL_AUTHORIZATION_REPLAY_CONFLICT");
  });
}
