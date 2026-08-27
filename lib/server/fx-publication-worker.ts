import "server-only";

import type { Call } from "starknet";
import type { SettlementObservation } from "@/lib/domain/settlement";
import {
  deferFxPublicationJob,
  leaseFxPublicationJobs,
  recordFxPublicationComplete,
  recordFxPublicationSubmission,
  type LeasedFxPublicationJob,
} from "@/lib/persistence/fx-publication-repository";
import { observeStarknetTransaction, type ConfirmationRpc } from "./confirmation-worker";
import type { PayoDeploymentConfig } from "./payo-deployment";
import {
  assertFxRootNotRevoked,
  isFxRootActive,
  verifyFxPublicationProof,
  type FxPublicationRpc,
} from "./fx-root-publisher";
import { prepareFxRootPublication } from "@/lib/starknet/payo-registry";

export type FxPublicationWorkerRpc = FxPublicationRpc & ConfirmationRpc;

export type FxPublicationSubmitter = {
  submit: (input: {
    job: LeasedFxPublicationJob;
    call: Call;
  }) => Promise<{ transactionHash: string } | null>;
};

export type FxPublicationWorkerDependencies = {
  lease: typeof leaseFxPublicationJobs;
  isActive: typeof isFxRootActive;
  assertNotRevoked: typeof assertFxRootNotRevoked;
  verify: typeof verifyFxPublicationProof;
  observe: (rpc: ConfirmationRpc, transactionHash: string) => Promise<SettlementObservation>;
  recordSubmission: typeof recordFxPublicationSubmission;
  recordComplete: typeof recordFxPublicationComplete;
  defer: typeof deferFxPublicationJob;
};

const defaultDependencies: FxPublicationWorkerDependencies = {
  lease: leaseFxPublicationJobs,
  isActive: isFxRootActive,
  assertNotRevoked: assertFxRootNotRevoked,
  verify: verifyFxPublicationProof,
  observe: observeStarknetTransaction,
  recordSubmission: recordFxPublicationSubmission,
  recordComplete: recordFxPublicationComplete,
  defer: deferFxPublicationJob,
};

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "FX publication failed.";
}

function deterministicProofFailure(error: unknown): boolean {
  const message = errorText(error).toLowerCase();
  return [
    "malformed",
    "inactive",
    "unexpected response",
    "exactly 17 public inputs",
    "different deployment or root bindings",
    "missing or reordered",
    "not bound to this payo fx catalog",
    "validity window is not active",
    "non-canonical fx root",
    "was revoked",
    "pagination exceeded",
  ].some((fragment) => message.includes(fragment));
}

async function processLeasedJob(input: {
  job: LeasedFxPublicationJob;
  rpc: FxPublicationWorkerRpc;
  submitter: FxPublicationSubmitter;
  deployment: PayoDeploymentConfig;
  policyRegistryAddress: string;
  now: Date;
  dependencies: FxPublicationWorkerDependencies;
}): Promise<string> {
  const { job, dependencies, now } = input;
  try {
    if (await dependencies.isActive({
      rpc: input.rpc,
      policyRegistryAddress: input.policyRegistryAddress,
      catalogRoot: job.catalogRoot,
    })) {
      const result = await dependencies.recordComplete(job, job.transactionHash, now);
      return result.state;
    }
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "FX_ROOT_READ_FAILED",
      errorMessage: errorText(error),
    }, now);
    return result.state;
  }

  const nowSeconds = Math.floor(now.getTime() / 1_000);
  if (nowSeconds > job.observedAt + job.maximumAgeSeconds) {
    const result = await dependencies.defer(job, {
      errorCode: "FX_PUBLICATION_WINDOW_EXPIRED",
      errorMessage: "The proved FX catalog expired before its root became active.",
      permanent: true,
    }, now);
    return result.state;
  }

  if (job.transactionHash) {
    let observation: SettlementObservation;
    try {
      observation = await dependencies.observe(input.rpc, job.transactionHash);
    } catch (error) {
      const result = await dependencies.defer(job, {
        errorCode: "FX_RECEIPT_READ_FAILED",
        errorMessage: errorText(error),
      }, now);
      return result.state;
    }
    if (observation.state === "failed") {
      const result = await dependencies.defer(job, {
        errorCode: observation.errorCode ?? "FX_PUBLICATION_REVERTED",
        errorMessage: observation.errorMessage ?? "The FX publication transaction failed.",
        permanent: true,
      }, now);
      return result.state;
    }
    if (observation.state === "reorged") {
      const result = await dependencies.defer(job, {
        errorCode: "FX_PUBLICATION_REORGED",
        errorMessage: observation.errorMessage ?? "The FX publication transaction was reorged.",
        clearTransactionHash: true,
      }, now);
      return result.state;
    }
    const result = await dependencies.defer(job, {
      errorCode: observation.state === "pending"
        ? "FX_PUBLICATION_PENDING"
        : "FX_ROOT_ACTIVATION_PENDING",
      errorMessage: observation.state === "pending"
        ? "The FX publication transaction is pending."
        : "The FX publication transaction is confirmed but the root is not observable yet.",
    }, now);
    return result.state;
  }

  if (job.historicalRenewal) {
    try {
      await dependencies.assertNotRevoked({
        rpc: input.rpc,
        policyRegistryAddress: input.policyRegistryAddress,
        catalogRoot: job.catalogRoot,
        fromBlock: Number(process.env.PAYO_POLICY_REGISTRY_FROM_BLOCK ?? process.env.PAYO_INDEX_FROM_BLOCK ?? "0"),
        toBlock: await input.rpc.getBlockNumber(),
      });
    } catch (error) {
      const result = await dependencies.defer(job, {
        errorCode: deterministicProofFailure(error)
          ? "FX_RENEWAL_REVOKED"
          : "FX_REVOCATION_READ_FAILED",
        errorMessage: errorText(error),
        permanent: deterministicProofFailure(error),
      }, now);
      return result.state;
    }
  }

  let verified;
  try {
    verified = await dependencies.verify({
      rpc: input.rpc,
      deployment: input.deployment,
      policyRegistryAddress: input.policyRegistryAddress,
      catalogRoot: job.catalogRoot,
      proofVersion: job.proofVersion,
      shards: job.shards,
      requireActiveWindow: !job.historicalRenewal,
    });
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: deterministicProofFailure(error)
        ? "FX_PUBLICATION_PROOF_INVALID"
        : "FX_PROOF_RPC_FAILED",
      errorMessage: errorText(error),
      permanent: deterministicProofFailure(error),
    }, now);
    return result.state;
  }

  try {
    const submitted = await input.submitter.submit({
      job,
      call: prepareFxRootPublication({
        registryAddress: input.policyRegistryAddress,
        fxRoot: job.catalogRoot,
        observedAt: job.observedAt,
        maximumAgeSeconds: job.maximumAgeSeconds,
        blockTimestamp: verified.blockTimestamp,
      }),
    });
    if (!submitted) {
      const result = await dependencies.recordComplete(job, null, now);
      return result.state;
    }
    const result = await dependencies.recordSubmission(job, submitted.transactionHash, now);
    return result.state;
  } catch (error) {
    const latestBlockExpired = verified.blockTimestamp > job.observedAt + job.maximumAgeSeconds;
    const result = await dependencies.defer(job, {
      errorCode: latestBlockExpired ? "FX_PUBLICATION_WINDOW_EXPIRED" : "FX_SUBMISSION_FAILED",
      errorMessage: errorText(error),
      permanent: latestBlockExpired,
    }, now);
    return result.state;
  }
}

export async function processFxPublicationBatch(input: {
  rpc: FxPublicationWorkerRpc;
  submitter: FxPublicationSubmitter;
  deployment: PayoDeploymentConfig;
  policyRegistryAddress: string;
  workerId: string;
  limit?: number;
  now?: Date;
  dependencies?: FxPublicationWorkerDependencies;
}) {
  const dependencies = input.dependencies ?? defaultDependencies;
  const now = input.now ?? new Date();
  const jobs = await dependencies.lease(input.workerId, input.limit ?? 1, now);
  const results: Array<{ jobId: string; catalogRoot: string; state: string }> = [];
  for (const job of jobs) {
    const state = await processLeasedJob({
      job,
      rpc: input.rpc,
      submitter: input.submitter,
      deployment: input.deployment,
      policyRegistryAddress: input.policyRegistryAddress,
      now,
      dependencies,
    });
    results.push({ jobId: job.id, catalogRoot: job.catalogRoot, state });
  }
  return { leased: jobs.length, results };
}
