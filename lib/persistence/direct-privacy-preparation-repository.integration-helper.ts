import { expect, it } from "vitest";
import { OutsideExecutionVersion, hash, outsideExecution } from "starknet";
import {
  directPrivacyPreparationSchema,
  type DirectPrivacyPreparation,
} from "@/lib/domain/direct-privacy";
import { requestAgentExecution } from "./agent-execution-repository";
import { leaseAgentExecutions } from "./agent-execution-worker-repository";
import {
  abandonDirectPrivacyPreparation,
  findDirectPrivacyPreparation,
  loadDirectPrivacyPreparation,
  storeDirectPrivacyPreparation,
} from "./direct-privacy-preparation-repository";
import {
  leaseDirectPrivacyExecutionContext,
  stageDirectPrivacyRunWitness,
} from "./direct-privacy-repository";
import { fixture, now, principal } from "./direct-privacy-repository.integration-helper";
import { getDatabase } from "./db";
import { directPrivacyPreparations, directPrivacyTreasuries } from "./schema";

async function leasedFixture() {
  const input = await fixture();
  await stageDirectPrivacyRunWitness({
    accountId: input.account.id,
    encryptedWitness: input.material.encryptedWitness,
    principal,
    now,
  });
  await requestAgentExecution({
    capabilityId: input.capability.id,
    idempotencyKey: `direct-preparation:${input.runId}`,
    request: input.request,
    principal,
    now,
  });
  const [job] = await leaseAgentExecutions("direct-preparation-worker", 1, now);
  const context = await leaseDirectPrivacyExecutionContext(job, now);
  const policyCall: DirectPrivacyPreparation["policyCall"] = {
    contractAddress: context.config.policyAccountAddress,
    entrypoint: "execute_policy_intent",
    calldata: Array.from({ length: 20 }, (_, index) => `0x${index}` as `0x${string}`),
  };
  const outsideCall = outsideExecution.buildExecuteFromOutsideCall({
    outsideExecution: {
      caller: "0x321",
      nonce: "0x456",
      execute_after: 1001,
      execute_before: 1100,
      calls: [{
        to: policyCall.contractAddress,
        selector: hash.getSelectorFromName(policyCall.entrypoint),
        calldata: policyCall.calldata,
      }],
    },
    signature: ["0xabc", "0xdef"],
    signerAddress: policyCall.contractAddress,
    version: OutsideExecutionVersion.V2,
  })[0];
  const preparation = directPrivacyPreparationSchema.parse({
    version: "payo-direct-privacy-preparation-v1",
    executionId: job.id,
    requestCommitment: job.requestCommitment as `0x${string}`,
    policyCall,
    outsideCall,
    sdkProof: { data: "private-sdk-proof-data", proofFacts: ["0x1"] },
    settlement: {
      transactionReference: ("0x" + "11".repeat(32)) as `0x${string}`,
      settlementRoot: ("0x" + "22".repeat(32)) as `0x${string}`,
      encryptedPayrollWitness: context.material.encryptedWitness,
      encryptedSettlementWitness: context.material.encryptedWitness,
    },
    proofValidAfterUnix: "1000",
    proofValidBeforeUnix: "2000",
    nextState: { ...context.state, pinnedBlock: { number: 90, hash: "0xabc" } },
    expectedStateVersion: context.stateVersion,
    pinnedBlock: { number: 90, hash: "0xabc" },
    feeEstimateAtomic: "321",
  });
  return { job, context, preparation };
}

export function registerDirectPrivacyPreparationRepositoryIntegrationTests(): void {
  it("encrypts an idempotent proof plan before signing and binds every lookup", async () => {
    const { job, context, preparation } = await leasedFixture();
    const stored = await storeDirectPrivacyPreparation({
      job,
      accountId: context.accountId,
      preparation,
      now,
    });
    await expect(storeDirectPrivacyPreparation({
      job,
      accountId: context.accountId,
      preparation,
      now,
    })).resolves.toEqual(stored);
    const row = (await getDatabase().select().from(directPrivacyPreparations))[0];
    expect(JSON.stringify(row)).not.toContain("private-sdk-proof-data");
    await expect(loadDirectPrivacyPreparation({
      executionId: job.id,
      requestCommitment: job.requestCommitment,
      preparationCommitment: stored.preparationCommitment,
    })).resolves.toMatchObject({ preparation });
    await expect(findDirectPrivacyPreparation(job)).resolves.toMatchObject({
      accountId: context.accountId,
      preparation,
      preparationCommitment: stored.preparationCommitment,
    });
    const substituted = directPrivacyPreparationSchema.parse({
      ...preparation,
      outsideCall: {
        ...preparation.outsideCall,
        calldata: preparation.outsideCall.calldata.map((value, index) =>
          index === 8 ? "0x999" : value),
      },
    });
    await expect(storeDirectPrivacyPreparation({
      job,
      accountId: context.accountId,
      preparation: substituted,
      now,
    })).rejects.toThrow("DIRECT_PREPARATION_REPLAY_CONFLICT");
    await expect(loadDirectPrivacyPreparation({
      executionId: job.id,
      requestCommitment: `0x${"99".repeat(32)}`,
      preparationCommitment: stored.preparationCommitment,
    })).rejects.toThrow("DIRECT_PREPARATION_TAMPERED");
  });

  it("abandons only an unsigned plan and releases its direct account", async () => {
    const { job, context, preparation } = await leasedFixture();
    const stored = await storeDirectPrivacyPreparation({
      job,
      accountId: context.accountId,
      preparation,
      now,
    });
    await abandonDirectPrivacyPreparation({
      executionId: job.id,
      preparationCommitment: stored.preparationCommitment,
      now,
    });
    expect((await getDatabase().select().from(directPrivacyPreparations))[0].state).toBe("abandoned");
    expect((await getDatabase().select().from(directPrivacyTreasuries))[0]).toMatchObject({
      activeAccountId: null,
      activeExecutionId: null,
    });
    await expect(loadDirectPrivacyPreparation({
      executionId: job.id,
      requestCommitment: job.requestCommitment,
      preparationCommitment: stored.preparationCommitment,
    })).rejects.toThrow("DIRECT_PREPARATION_NOT_FOUND");
  });
}
