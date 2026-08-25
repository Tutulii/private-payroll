import "server-only";

import { num, type Call } from "starknet";
import {
  deferProofVerificationJob,
  leaseProofVerificationJobs,
  recordProofVerificationProgress,
  recordProofVerificationSubmission,
  type LeasedProofVerificationJob,
} from "@/lib/persistence/proof-verification-repository";
import { buildVerifySealedShardCalldataCall } from "@/lib/starknet/payo-seal";
import {
  observeStarknetTransaction,
  type ConfirmationRpc,
} from "./confirmation-worker";
import type { PayoDeploymentConfig } from "./payo-deployment";

export const PAYO_RUN_STATUS_NONE = 0;
export const PAYO_RUN_STATUS_SEALED = 1;
export const PAYO_RUN_STATUS_PROVEN = 2;

export type ProofRelayerRpc = ConfirmationRpc & {
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

export type ProofRelayerSubmitter = {
  submit: (call: Call) => Promise<{ transactionHash: string }>;
};

export type ProofSealState = {
  status: number;
  shardsVerified: readonly [boolean, boolean];
};

function resultFelts(response: unknown): string[] {
  if (Array.isArray(response)) return response.map(String);
  if (response && typeof response === "object") {
    const result = (response as { result?: unknown }).result;
    if (Array.isArray(result)) return result.map(String);
  }
  throw new Error("Starknet call returned no felt result.");
}

function singleFelt(response: unknown, label: string): bigint {
  const values = resultFelts(response);
  if (values.length !== 1) throw new Error(`${label} returned ${values.length} values instead of one.`);
  try {
    return BigInt(values[0]);
  } catch {
    throw new Error(`${label} returned a non-integer felt.`);
  }
}

export async function readProofSealState(
  rpc: Pick<ProofRelayerRpc, "callContract" | "getBlockNumber">,
  input: {
    sealAddress: string;
    runNullifierHigh: string;
    runNullifierLow: string;
  },
): Promise<ProofSealState> {
  // Pin all three reads to one canonical block so a newly mined block cannot
  // produce a torn status/shard snapshot.
  const blockNumber = await rpc.getBlockNumber();
  const nullifier = [
    num.toHex(BigInt(input.runNullifierHigh)),
    num.toHex(BigInt(input.runNullifierLow)),
  ];
  const [statusResponse, shardZeroResponse, shardOneResponse] = await Promise.all([
    rpc.callContract({
      contractAddress: input.sealAddress,
      entrypoint: "get_run_status",
      calldata: nullifier,
    }, blockNumber),
    rpc.callContract({
      contractAddress: input.sealAddress,
      entrypoint: "is_sealed_shard_verified",
      calldata: [...nullifier, "0x0"],
    }, blockNumber),
    rpc.callContract({
      contractAddress: input.sealAddress,
      entrypoint: "is_sealed_shard_verified",
      calldata: [...nullifier, "0x1"],
    }, blockNumber),
  ]);
  const status = singleFelt(statusResponse, "PAYO run status");
  if (status < 0n || status > 255n) throw new Error("PAYO run status is outside its u8 range.");
  return {
    status: Number(status),
    shardsVerified: [
      singleFelt(shardZeroResponse, "PAYO shard 0 status") !== 0n,
      singleFelt(shardOneResponse, "PAYO shard 1 status") !== 0n,
    ],
  };
}

export type ProofRelayerDependencies = {
  lease: typeof leaseProofVerificationJobs;
  readState: typeof readProofSealState;
  observe: typeof observeStarknetTransaction;
  recordSubmission: typeof recordProofVerificationSubmission;
  defer: typeof deferProofVerificationJob;
  recordProgress: typeof recordProofVerificationProgress;
};

const defaultDependencies: ProofRelayerDependencies = {
  lease: leaseProofVerificationJobs,
  readState: readProofSealState,
  observe: observeStarknetTransaction,
  recordSubmission: recordProofVerificationSubmission,
  defer: deferProofVerificationJob,
  recordProgress: recordProofVerificationProgress,
};

function desiredShard(state: ProofSealState): 0 | 1 | null {
  if (!state.shardsVerified[0]) return 0;
  if (!state.shardsVerified[1]) return 1;
  return null;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "Proof relayer operation failed.";
}

async function processLeasedJob(input: {
  job: LeasedProofVerificationJob;
  rpc: ProofRelayerRpc;
  submitter: ProofRelayerSubmitter;
  deployment: PayoDeploymentConfig;
  now: Date;
  dependencies: ProofRelayerDependencies;
}): Promise<string> {
  const { job, dependencies, now } = input;
  if (
    BigInt(job.chainId) !== BigInt(input.deployment.chainId)
    ||
    BigInt(job.sealAddress) !== BigInt(input.deployment.sealAddress)
  ) {
    const result = await dependencies.defer(job, {
      errorCode: "PROOF_DEPLOYMENT_MISMATCH",
      errorMessage: "Proof bundle is bound to a different PAYO seal deployment.",
      permanent: true,
    }, now);
    return result.state;
  }

  let state: ProofSealState;
  try {
    state = await dependencies.readState(input.rpc, {
      sealAddress: input.deployment.sealAddress,
      runNullifierHigh: job.runNullifierHigh,
      runNullifierLow: job.runNullifierLow,
    });
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "PROOF_STATE_RPC_FAILURE",
      errorMessage: errorText(error),
    }, now);
    return result.state;
  }

  if (state.status === PAYO_RUN_STATUS_PROVEN) {
    const result = await dependencies.recordProgress(job, {
      complete: true,
      verificationTransactionHash: job.activeTransactionHash,
    }, now);
    return result.state;
  }

  const nowSeconds = BigInt(Math.floor(now.getTime() / 1_000));
  if (nowSeconds > BigInt(job.validityExpiry)) {
    const result = await dependencies.defer(job, {
      errorCode: "PROOF_VALIDITY_EXPIRED",
      errorMessage: "PayrollIntegrity expired before both proof shards reached the PAYO seal.",
      permanent: true,
    }, now);
    return result.state;
  }

  if (state.status === PAYO_RUN_STATUS_NONE) {
    const result = await dependencies.defer(job, {
      errorCode: "PAYO_SEAL_NOT_OBSERVED",
      errorMessage: "The finalized settlement has not created its PAYO sealed proof state yet.",
    }, now);
    return result.state;
  }
  if (state.status !== PAYO_RUN_STATUS_SEALED) {
    const result = await dependencies.defer(job, {
      errorCode: "PAYO_SEAL_STATUS_UNEXPECTED",
      errorMessage: `PAYO seal returned unsupported run status ${state.status}.`,
      permanent: true,
    }, now);
    return result.state;
  }

  const shardIndex = desiredShard(state);
  if (shardIndex === null) {
    const result = await dependencies.defer(job, {
      errorCode: "PAYO_PROVEN_STATE_PENDING",
      errorMessage: "Both shards are recorded but the atomic PAYO proven state is not yet observable.",
    }, now);
    return result.state;
  }
  if (shardIndex !== job.nextShard) {
    const result = await dependencies.recordProgress(job, { nextShard: shardIndex }, now);
    return result.state;
  }

  if (job.activeTransactionHash) {
    let observation;
    try {
      observation = await dependencies.observe(input.rpc, job.activeTransactionHash);
    } catch (error) {
      const result = await dependencies.defer(job, {
        errorCode: "PROOF_RECEIPT_RPC_FAILURE",
        errorMessage: errorText(error),
      }, now);
      return result.state;
    }
    if (observation.state === "pending") {
      const result = await dependencies.defer(job, {
        errorCode: observation.errorCode ?? "PROOF_TRANSACTION_PENDING",
        errorMessage: observation.errorMessage ?? "Proof verification transaction is pending.",
      }, now);
      return result.state;
    }

    let refreshed: ProofSealState;
    try {
      refreshed = await dependencies.readState(input.rpc, {
        sealAddress: input.deployment.sealAddress,
        runNullifierHigh: job.runNullifierHigh,
        runNullifierLow: job.runNullifierLow,
      });
    } catch (error) {
      const result = await dependencies.defer(job, {
        errorCode: "PROOF_STATE_RPC_FAILURE",
        errorMessage: errorText(error),
      }, now);
      return result.state;
    }
    if (refreshed.status === PAYO_RUN_STATUS_PROVEN) {
      const result = await dependencies.recordProgress(job, {
        complete: true,
        verificationTransactionHash: job.activeTransactionHash,
      }, now);
      return result.state;
    }
    const refreshedShard = refreshed.status === PAYO_RUN_STATUS_SEALED
      ? desiredShard(refreshed)
      : shardIndex;
    if (refreshedShard !== null && refreshedShard !== shardIndex) {
      const result = await dependencies.recordProgress(job, { nextShard: refreshedShard }, now);
      return result.state;
    }
    if (observation.state === "failed" || observation.state === "reorged") {
      const result = await dependencies.defer(job, {
        errorCode: observation.errorCode ?? (observation.state === "reorged" ? "PROOF_TRANSACTION_REORGED" : "PROOF_TRANSACTION_FAILED"),
        errorMessage: observation.errorMessage ?? `Proof shard ${shardIndex} transaction ${observation.state}.`,
        clearActiveTransaction: true,
      }, now);
      return result.state;
    }
    const result = await dependencies.defer(job, {
      errorCode: "PROOF_STATE_NOT_OBSERVED",
      errorMessage: `Proof shard ${shardIndex} receipt succeeded, but the PAYO seal has not recorded it.`,
    }, now);
    return result.state;
  }

  const call = buildVerifySealedShardCalldataCall({
    sealAddress: input.deployment.sealAddress,
    runNullifierHigh: job.runNullifierHigh,
    runNullifierLow: job.runNullifierLow,
    shardIndex,
    proofCalldata: job.shards[shardIndex],
    calldataHash: job.shardCalldataHashes[shardIndex],
  });
  try {
    const submitted = await input.submitter.submit(call);
    await dependencies.recordSubmission(job, shardIndex, submitted.transactionHash, now);
    return "submitted";
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "PROOF_SUBMISSION_FAILED",
      errorMessage: errorText(error),
      clearActiveTransaction: true,
    }, now);
    return result.state;
  }
}

export async function processProofVerificationBatch(input: {
  rpc: ProofRelayerRpc;
  submitter: ProofRelayerSubmitter;
  deployment: PayoDeploymentConfig;
  workerId: string;
  limit?: number;
  now?: Date;
  dependencies?: ProofRelayerDependencies;
}) {
  const dependencies = input.dependencies ?? defaultDependencies;
  const now = input.now ?? new Date();
  const jobs = await dependencies.lease(input.workerId, input.limit ?? 2, now);
  const results: Array<{ jobId: string; settlementId: string; state: string }> = [];
  for (const job of jobs) {
    const state = await processLeasedJob({
      job,
      rpc: input.rpc,
      submitter: input.submitter,
      deployment: input.deployment,
      now,
      dependencies,
    });
    results.push({ jobId: job.id, settlementId: job.settlementId, state });
  }
  return { leased: jobs.length, results };
}
