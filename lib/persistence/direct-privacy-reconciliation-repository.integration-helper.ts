import { expect, it } from "vitest";
import type { DirectPrivacyProofDraft } from "@/lib/domain/direct-privacy";
import {
  SETTLEMENT_MATCH_CIRCUIT_SHA256,
  SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
  type SettlementMatchProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { requestAgentExecution } from "./agent-execution-repository";
import { leaseAgentExecutions } from "./agent-execution-worker-repository";
import {
  completeDirectPrivacyFinalizationChunk,
  ensureDirectPrivacyReconciliation,
  loadDirectPrivacyReconciliation,
  markDirectPrivacyReconciled,
  recordDirectPrivacyFinalizationBroadcast,
  storeDirectPrivacyFinalization,
  storeDirectPrivacyProofDraft,
  storeDirectPrivacyReconciliationProof,
} from "./direct-privacy-reconciliation-repository";
import {
  leaseDirectPrivacyExecutionContext,
  stageDirectPrivacyRunWitness,
} from "./direct-privacy-repository";
import {
  fixture,
  now,
  principal,
} from "./direct-privacy-repository.integration-helper";
import { getDatabase } from "./db";
import {
  directPrivacyReconciliations,
  directPrivacySubmissions,
} from "./schema";

const mask128 = (1n << 128n) - 1n;

function limbs(value: string) {
  const parsed = BigInt(value);
  return {
    high: (parsed >> 128n).toString(),
    low: (parsed & mask128).toString(),
  };
}

function settlementProof(input: {
  executionId: string;
  manifestRoot: string;
  runNullifier: string;
  settlementRoot: string;
  transactionReference: string;
}): SettlementMatchProofWorkerSuccess {
  const manifest = limbs(input.manifestRoot);
  const nullifier = limbs(input.runNullifier);
  const settlement = limbs(input.settlementRoot);
  const reference = limbs(input.transactionReference);
  const proofCalldata = ["0x123456789abc", "0x2"];
  return {
    version: 8,
    type: "settlement-proof-complete",
    requestId: input.executionId,
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: SETTLEMENT_MATCH_CIRCUIT_SHA256,
    verificationKeySha256: SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
    settlementRoot: input.settlementRoot,
    transactionReference: input.transactionReference,
    provingTimeMs: 1,
    chunks: [{
      chunkIndex: 0,
      chunkCount: 1,
      proofCalldata,
      calldataHash: hashProofCalldata(proofCalldata),
      publicInputs: {
        proofVersion: "8",
        manifestRootHigh: manifest.high,
        manifestRootLow: manifest.low,
        runNullifierHigh: nullifier.high,
        runNullifierLow: nullifier.low,
        transactionReferenceHigh: reference.high,
        transactionReferenceLow: reference.low,
        settlementRootHigh: settlement.high,
        settlementRootLow: settlement.low,
        chunkIndex: "0",
        chunkCount: "1",
      },
    }],
  };
}

async function reconciliationFixture() {
  const input = await fixture();
  await stageDirectPrivacyRunWitness({
    accountId: input.account.id,
    encryptedWitness: input.material.encryptedWitness,
    principal,
    now,
  });
  await requestAgentExecution({
    capabilityId: input.capability.id,
    idempotencyKey: "direct-reconciliation:" + input.runId,
    request: input.request,
    principal,
    now,
  });
  const [job] = await leaseAgentExecutions("direct-reconciliation-worker", 1, now);
  const context = await leaseDirectPrivacyExecutionContext(job, now);
  const settlementRoot = "0x" + "aa".repeat(32);
  const transactionReference = "0x" + "bb".repeat(32);
  await ensureDirectPrivacyReconciliation({
    executionId: job.id,
    accountId: input.account.id,
    organizationId: input.organizationId,
    settlementRoot,
    transactionReference,
    now,
  });
  return {
    input,
    job,
    settlementRoot,
    transactionReference,
    proof: settlementProof({
      executionId: job.id,
      manifestRoot: input.material.policyRun.manifestRoot,
      runNullifier: input.material.policyRun.runNullifier,
      settlementRoot,
      transactionReference,
    }),
    context,
  };
}

export function registerDirectPrivacyReconciliationRepositoryIntegrationTests(): void {
  it("encrypts one idempotent SDK proof draft and rejects regeneration", async () => {
    const value = await reconciliationFixture();
    const draft: DirectPrivacyProofDraft = {
      version: "payo-direct-privacy-proof-draft-v1",
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment as `0x${string}`,
      poolCalldata: ["0x1", "0x2"],
      sdkProof: { data: "durable-private-sdk-proof", proofFacts: ["0x3"] },
      settlement: {
        transactionReference: value.transactionReference as `0x${string}`,
        settlementRoot: value.settlementRoot as `0x${string}`,
        encryptedPayrollWitness: value.context.material.encryptedWitness,
        encryptedSettlementWitness: value.context.material.encryptedWitness,
      },
      proofValidAfterUnix: "1000",
      proofValidBeforeUnix: "2000",
      nextState: {
        ...value.context.state,
        pinnedBlock: { number: 90, hash: "0xabc" },
      },
      expectedStateVersion: value.context.stateVersion,
      pinnedBlock: { number: 90, hash: "0xabc" },
    };
    const stored = await storeDirectPrivacyProofDraft({
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      draft,
      now,
    });
    await expect(storeDirectPrivacyProofDraft({
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      draft,
      now,
    })).resolves.toEqual(stored);
    const [row] = await getDatabase().select().from(directPrivacyReconciliations);
    expect(JSON.stringify(row)).not.toContain("durable-private-sdk-proof");
    await expect(loadDirectPrivacyReconciliation(value.job.id)).resolves.toMatchObject({
      draft: { poolCalldata: ["0x1", "0x2"] },
    });
    await expect(storeDirectPrivacyProofDraft({
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      draft: { ...draft, poolCalldata: ["0x1", "0x4"] },
      now,
    })).rejects.toThrow("DIRECT_PROOF_DRAFT_REPLAY_CONFLICT");
  });

  it("encrypts one bound SettlementMatch result and rejects settlement substitution", async () => {
    const value = await reconciliationFixture();
    await ensureDirectPrivacyReconciliation({
      executionId: value.job.id,
      accountId: value.input.account.id,
      organizationId: value.input.organizationId,
      settlementRoot: value.settlementRoot,
      transactionReference: value.transactionReference,
      now,
    });
    await expect(ensureDirectPrivacyReconciliation({
      executionId: value.job.id,
      accountId: value.input.account.id,
      organizationId: value.input.organizationId,
      settlementRoot: "0x" + "cc".repeat(32),
      transactionReference: value.transactionReference,
      now,
    })).rejects.toThrow("DIRECT_RECONCILIATION_REPLAY_CONFLICT");

    await storeDirectPrivacyReconciliationProof({
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      proof: value.proof,
      now,
    });
    const [row] = await getDatabase().select().from(directPrivacyReconciliations);
    expect(row).toMatchObject({ state: "ready", chunkCount: 1, verifiedCount: 0 });
    expect(JSON.stringify(row)).not.toContain("123456789abc");
    await expect(loadDirectPrivacyReconciliation(value.job.id)).resolves.toMatchObject({
      proof: { proof: { settlementRoot: value.settlementRoot } },
    });

    await expect(storeDirectPrivacyReconciliationProof({
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      proof: {
        ...value.proof,
        settlementRoot: "0x" + "dd".repeat(32),
      },
      now,
    })).rejects.toThrow();
  });

  it("persists one signed FINALIZE transaction and reconciles only after its confirmed chunk", async () => {
    const value = await reconciliationFixture();
    await storeDirectPrivacyReconciliationProof({
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      proof: value.proof,
      now,
    });
    const chunk = value.proof.chunks[0];
    const expectedTransactionHash = "0x777";
    const submission = {
      version: "payo-direct-privacy-finalization-v1" as const,
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment as `0x${string}`,
      chunkIndex: 0,
      chunkCount: 1,
      calldataHash: chunk.calldataHash as `0x${string}`,
      expectedTransactionHash: expectedTransactionHash as `0x${string}`,
      signedTransaction: {
        type: "INVOKE" as const,
        sender_address: "0x777" as const,
        calldata: ["0x1" as const],
        signature: ["0x2" as const, "0x3" as const],
        nonce: "0x0" as const,
        resource_bounds: {
          l1_gas: { max_amount: "0x1" as const, max_price_per_unit: "0x1" as const },
          l1_data_gas: { max_amount: "0x1" as const, max_price_per_unit: "0x1" as const },
          l2_gas: { max_amount: "0x1" as const, max_price_per_unit: "0x1" as const },
        },
        tip: "0x0" as const,
        paymaster_data: [],
        nonce_data_availability_mode: "L1" as const,
        fee_data_availability_mode: "L1" as const,
        account_deployment_data: [],
        version: "0x3" as const,
      },
    };
    const stored = await storeDirectPrivacyFinalization({ submission, now });
    await expect(storeDirectPrivacyFinalization({ submission, now })).resolves.toEqual(stored);
    await expect(markDirectPrivacyReconciled({
      executionId: value.job.id,
      verifiedCount: 1,
      now,
    })).rejects.toThrow("DIRECT_RECONCILIATION_INCOMPLETE");
    await expect(recordDirectPrivacyFinalizationBroadcast({
      executionId: value.job.id,
      expectedTransactionHash,
      transactionHash: "0x778",
      now,
    })).rejects.toThrow("DIRECT_FINALIZATION_HASH_MISMATCH");
    await recordDirectPrivacyFinalizationBroadcast({
      executionId: value.job.id,
      expectedTransactionHash,
      transactionHash: expectedTransactionHash,
      now,
    });
    await completeDirectPrivacyFinalizationChunk(expectedTransactionHash, now);
    await markDirectPrivacyReconciled({
      executionId: value.job.id,
      verifiedCount: 1,
      now,
    });
    await expect(loadDirectPrivacyReconciliation(value.job.id)).resolves.toMatchObject({
      row: {
        state: "reconciled",
        verifiedCount: 1,
        activeChunkIndex: null,
        activeTransactionHash: null,
      },
    });
  });

  it("accepts atomic FINALIZE only from the exact confirmed payment transaction", async () => {
    const value = await reconciliationFixture();
    await storeDirectPrivacyReconciliationProof({
      executionId: value.job.id,
      requestCommitment: value.job.requestCommitment,
      proof: value.proof,
      now,
    });
    await getDatabase().insert(directPrivacySubmissions).values({
      executionId: value.job.id,
      accountId: value.input.account.id,
      organizationId: value.input.organizationId,
      submissionCommitment: "0x" + "77".repeat(32),
      expectedTransactionHash: "0x888",
      transactionHash: "0x888",
      encryptedPrepared: {},
      state: "confirmed",
      createdAt: now,
      updatedAt: now,
    });
    await expect(markDirectPrivacyReconciled({
      executionId: value.job.id,
      verifiedCount: 1,
      atomicTransactionHash: "0x889",
      now,
    })).rejects.toThrow("DIRECT_ATOMIC_FINALIZATION_UNCONFIRMED");
    await markDirectPrivacyReconciled({
      executionId: value.job.id,
      verifiedCount: 1,
      atomicTransactionHash: "0x888",
      now,
    });
    await expect(loadDirectPrivacyReconciliation(value.job.id)).resolves.toMatchObject({
      row: { state: "reconciled", verifiedCount: 1 },
    });
  });
}
