import { expect, it } from "vitest";
import type { DirectPrivacyPreparedSubmission } from "@/lib/domain/direct-privacy";
import { requestAgentExecution } from "./agent-execution-repository";
import { leaseAgentExecutions } from "./agent-execution-worker-repository";
import {
  leaseDirectPrivacyExecutionContext,
  stageDirectPrivacyRunWitness,
} from "./direct-privacy-repository";
import { fixture, now, principal } from "./direct-privacy-repository.integration-helper";
import {
  failDirectPrivacySubmission,
  finalizeDirectPrivacySubmission,
  loadPreparedDirectPrivacySubmission,
  markDirectPrivacySubmissionBroadcasting,
  recordDirectPrivacyBroadcast,
  storePreparedDirectPrivacySubmission,
} from "./direct-privacy-submission-repository";
import { getDatabase } from "./db";
import {
  directPrivacySubmissions,
  directPrivacyTreasuries,
} from "./schema";

function preparedSubmission(input: {
  executionId: string;
  requestCommitment: string;
  expectedTransactionHash: `0x${string}`;
  expectedStateVersion: number;
  nextState: DirectPrivacyPreparedSubmission["nextState"];
  settlement: DirectPrivacyPreparedSubmission["settlement"];
}): DirectPrivacyPreparedSubmission {
  return {
    version: "payo-direct-privacy-submission-v1",
    executionId: input.executionId,
    requestCommitment: input.requestCommitment as `0x${string}`,
    expectedTransactionHash: input.expectedTransactionHash,
    signedTransaction: {
      type: "INVOKE",
      sender_address: "0x777",
      calldata: ["0x1"],
      signature: ["0x2", "0x3"],
      nonce: "0x0",
      resource_bounds: {
        l1_gas: { max_amount: "0x1", max_price_per_unit: "0x1" },
        l1_data_gas: { max_amount: "0x1", max_price_per_unit: "0x1" },
        l2_gas: { max_amount: "0x1", max_price_per_unit: "0x1" },
      },
      tip: "0x0",
      paymaster_data: [],
      nonce_data_availability_mode: "L1",
      fee_data_availability_mode: "L1",
      account_deployment_data: [],
      version: "0x3",
      proof_facts: ["0x4"],
      proof: "private-proof-bytes",
    },
    settlement: input.settlement,
    proofValidAfterUnix: "1000",
    proofValidBeforeUnix: "2000",
    nextState: input.nextState,
    expectedStateVersion: input.expectedStateVersion,
    pinnedBlock: { number: 80, hash: "0xdef" },
    feeEstimateAtomic: "321",
  };
}

async function leasedFixture(workerId: string) {
  const input = await fixture();
  await stageDirectPrivacyRunWitness({
    accountId: input.account.id,
    encryptedWitness: input.material.encryptedWitness,
    principal,
    now,
  });
  const receipt = await requestAgentExecution({
    capabilityId: input.capability.id,
    idempotencyKey: `${workerId}:${input.runId}`,
    request: input.request,
    principal,
    now,
  });
  const [job] = await leaseAgentExecutions(workerId, 1, now);
  expect(job.id).toBe(receipt.executionId);
  const context = await leaseDirectPrivacyExecutionContext(job, now);
  return { input, job, context };
}

export function registerDirectPrivacySubmissionRepositoryIntegrationTests(): void {
  it("stores one encrypted pre-signed transaction and commits SDK state only after confirmation", async () => {
    const { job, context } = await leasedFixture("direct-submission-worker");
    const expectedTransactionHash = "0xabc123";
    const prepared = preparedSubmission({
      executionId: job.id,
      requestCommitment: job.requestCommitment,
      expectedTransactionHash,
      expectedStateVersion: context.stateVersion,
      nextState: {
        ...context.state,
        pinnedBlock: { number: 81, hash: "0xabc" },
      },
      settlement: {
        transactionReference: ("0x" + "11".repeat(32)) as `0x${string}`,
        settlementRoot: ("0x" + "22".repeat(32)) as `0x${string}`,
        encryptedPayrollWitness: context.material.encryptedWitness,
        encryptedSettlementWitness: context.material.encryptedWitness,
      },
    });
    const stored = await storePreparedDirectPrivacySubmission({
      job,
      accountId: context.accountId,
      prepared,
      now,
    });
    const databaseRow = (await getDatabase().select().from(directPrivacySubmissions))[0];
    expect(JSON.stringify(databaseRow)).not.toContain("private-proof-bytes");
    await expect(loadPreparedDirectPrivacySubmission({
      executionId: job.id,
      requestCommitment: job.requestCommitment,
      submissionCommitment: stored.submissionCommitment,
    })).resolves.toEqual(prepared);

    await markDirectPrivacySubmissionBroadcasting(job.id, stored.submissionCommitment, now);
    await expect(recordDirectPrivacyBroadcast({
      executionId: job.id,
      submissionCommitment: stored.submissionCommitment,
      transactionHash: "0x999",
      now,
    })).rejects.toThrow("DIRECT_TRANSACTION_HASH_MISMATCH");
    await recordDirectPrivacyBroadcast({
      executionId: job.id,
      submissionCommitment: stored.submissionCommitment,
      transactionHash: expectedTransactionHash,
      now,
    });
    await finalizeDirectPrivacySubmission(expectedTransactionHash, now);
    await finalizeDirectPrivacySubmission(expectedTransactionHash, now);
    expect((await getDatabase().select().from(directPrivacyTreasuries))[0]).toMatchObject({
      stateVersion: context.stateVersion + 1,
      activeAccountId: null,
      activeExecutionId: null,
    });
    expect((await getDatabase().select().from(directPrivacySubmissions))[0].state).toBe("confirmed");
  });

  it("releases the direct account after a proved transaction reverts", async () => {
    const { job, context } = await leasedFixture("direct-revert-worker");
    const prepared = preparedSubmission({
      executionId: job.id,
      requestCommitment: job.requestCommitment,
      expectedTransactionHash: "0xabc124",
      expectedStateVersion: context.stateVersion,
      nextState: context.state,
      settlement: {
        transactionReference: ("0x" + "33".repeat(32)) as `0x${string}`,
        settlementRoot: ("0x" + "44".repeat(32)) as `0x${string}`,
        encryptedPayrollWitness: context.material.encryptedWitness,
        encryptedSettlementWitness: context.material.encryptedWitness,
      },
    });
    const stored = await storePreparedDirectPrivacySubmission({
      job,
      accountId: context.accountId,
      prepared,
      now,
    });
    await markDirectPrivacySubmissionBroadcasting(job.id, stored.submissionCommitment, now);
    await recordDirectPrivacyBroadcast({
      executionId: job.id,
      submissionCommitment: stored.submissionCommitment,
      transactionHash: prepared.expectedTransactionHash,
      now,
    });
    await failDirectPrivacySubmission(prepared.expectedTransactionHash, "reverted", now);
    expect((await getDatabase().select().from(directPrivacyTreasuries))[0]).toMatchObject({
      activeAccountId: null,
      activeExecutionId: null,
    });
    expect((await getDatabase().select().from(directPrivacySubmissions))[0].state).toBe("reverted");
  });
}
