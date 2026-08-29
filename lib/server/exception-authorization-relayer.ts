import "server-only";

import { num, type Call } from "starknet";
import type { ExceptionPublicInputsV2 } from "@/lib/domain/exception-protocol";
import type { SettlementObservation } from "@/lib/domain/settlement";
import {
  completeExceptionAuthorizationJob,
  deferExceptionAuthorizationJob,
  leaseExceptionAuthorizationJobs,
  recordExceptionAuthorizationSubmission,
  type LeasedExceptionAuthorizationJob,
} from "@/lib/persistence/exception-authorization-repository";
import type { ExceptionCircuitProof } from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import {
  buildAuthorizeClaimCall,
  buildAuthorizeRemediationCall,
} from "@/lib/starknet/payo-exception-seal";
import {
  observeStarknetTransaction,
  type ConfirmationRpc,
} from "./confirmation-worker";
import type { PayoDeploymentConfig } from "./payo-deployment";

export type ExceptionAuthorizationRpc = ConfirmationRpc & {
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

export type ExceptionAuthorizationSubmitter = {
  submit: (call: Call) => Promise<{ transactionHash: string }>;
};

export type ExceptionAuthorizationState = {
  exists: boolean;
  status: number;
  parentNullifierHigh: string;
  parentNullifierLow: string;
  factCommitmentHigh: string;
  factCommitmentLow: string;
  actionCommitmentHigh: string | null;
  actionCommitmentLow: string | null;
};

function resultFelts(response: unknown): string[] {
  if (Array.isArray(response)) return response.map(String);
  if (response && typeof response === "object") {
    const result = (response as { result?: unknown }).result;
    if (Array.isArray(result)) return result.map(String);
  }
  throw new Error("Starknet exception-state call returned no felt result.");
}

function canonicalFelt(value: string, label: string): string {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label} is not an integer felt.`);
  }
  if (parsed < 0n) throw new Error(`${label} is negative.`);
  return parsed.toString();
}

function booleanFelt(value: string, label: string): boolean {
  const parsed = BigInt(canonicalFelt(value, label));
  if (parsed !== 0n && parsed !== 1n) throw new Error(`${label} is not a Cairo boolean.`);
  return parsed === 1n;
}

function statusFelt(value: string, label: string): number {
  const parsed = BigInt(canonicalFelt(value, label));
  if (parsed < 0n || parsed > 255n) throw new Error(`${label} is outside its u8 range.`);
  return Number(parsed);
}

export async function readExceptionAuthorizationState(
  rpc: Pick<ExceptionAuthorizationRpc, "callContract" | "getBlockNumber">,
  input: {
    sealAddress: string;
    workflowType: "wage_claim" | "wage_remediation";
    subjectNullifierHigh: string;
    subjectNullifierLow: string;
  },
): Promise<ExceptionAuthorizationState> {
  const blockNumber = await rpc.getBlockNumber();
  const response = await rpc.callContract({
    contractAddress: input.sealAddress,
    entrypoint: input.workflowType === "wage_claim" ? "get_claim" : "get_remediation_attempt",
    calldata: [
      num.toHex(BigInt(input.subjectNullifierHigh)),
      num.toHex(BigInt(input.subjectNullifierLow)),
    ],
  }, blockNumber);
  const values = resultFelts(response);
  const minimumLength = input.workflowType === "wage_claim" ? 14 : 11;
  if (values.length !== minimumLength) {
    throw new Error(
      `PAYO ${input.workflowType} state returned ${values.length} felts; expected ${minimumLength}.`,
    );
  }
  if (input.workflowType === "wage_claim") {
    return {
      exists: booleanFelt(values[0], "Claim existence"),
      status: statusFelt(values[1], "Claim status"),
      parentNullifierHigh: canonicalFelt(values[2], "Claim run nullifier high"),
      parentNullifierLow: canonicalFelt(values[3], "Claim run nullifier low"),
      factCommitmentHigh: canonicalFelt(values[8], "Claim fact high"),
      factCommitmentLow: canonicalFelt(values[9], "Claim fact low"),
      actionCommitmentHigh: null,
      actionCommitmentLow: null,
    };
  }
  return {
    exists: booleanFelt(values[0], "Remediation existence"),
    status: statusFelt(values[1], "Remediation status"),
    parentNullifierHigh: canonicalFelt(values[2], "Remediation claim subject high"),
    parentNullifierLow: canonicalFelt(values[3], "Remediation claim subject low"),
    factCommitmentHigh: canonicalFelt(values[4], "Remediation fact high"),
    factCommitmentLow: canonicalFelt(values[5], "Remediation fact low"),
    actionCommitmentHigh: canonicalFelt(values[6], "Remediation action high"),
    actionCommitmentLow: canonicalFelt(values[7], "Remediation action low"),
  };
}

export type ExceptionAuthorizationRelayerDependencies = {
  lease: typeof leaseExceptionAuthorizationJobs;
  readState: typeof readExceptionAuthorizationState;
  observe: (
    rpc: ConfirmationRpc,
    transactionHash: string,
  ) => Promise<SettlementObservation>;
  recordSubmission: typeof recordExceptionAuthorizationSubmission;
  defer: typeof deferExceptionAuthorizationJob;
  complete: typeof completeExceptionAuthorizationJob;
};

const defaultDependencies: ExceptionAuthorizationRelayerDependencies = {
  lease: leaseExceptionAuthorizationJobs,
  readState: readExceptionAuthorizationState,
  observe: observeStarknetTransaction,
  recordSubmission: recordExceptionAuthorizationSubmission,
  defer: deferExceptionAuthorizationJob,
  complete: completeExceptionAuthorizationJob,
};

function sameFelt(left: string, right: string): boolean {
  return BigInt(left) === BigInt(right);
}

function stateBindingError(
  state: ExceptionAuthorizationState,
  inputs: ExceptionPublicInputsV2,
  workflowType: "wage_claim" | "wage_remediation",
): string | null {
  if (!sameFelt(state.parentNullifierHigh, inputs.parentNullifierHigh)
    || !sameFelt(state.parentNullifierLow, inputs.parentNullifierLow)) {
    return "The stored exception parent nullifier differs from the proof.";
  }
  if (!sameFelt(state.factCommitmentHigh, inputs.factCommitmentHigh)
    || !sameFelt(state.factCommitmentLow, inputs.factCommitmentLow)) {
    return "The stored exception fact commitment differs from the proof.";
  }
  if (workflowType === "wage_remediation" && (
    state.actionCommitmentHigh === null
    || state.actionCommitmentLow === null
    || !sameFelt(state.actionCommitmentHigh, inputs.manifestRootHigh)
    || !sameFelt(state.actionCommitmentLow, inputs.manifestRootLow)
  )) return "The stored remediation action commitment differs from the proof.";
  return null;
}

function errorText(error: unknown): string {
  const message = error instanceof Error ? error.message : "Exception authorization failed.";
  return message.length <= 500 ? message : `${message.slice(0, 100)} … ${message.slice(-380)}`;
}

async function processLeasedExceptionAuthorization(input: {
  job: LeasedExceptionAuthorizationJob;
  rpc: ExceptionAuthorizationRpc;
  submitter: ExceptionAuthorizationSubmitter;
  deployment: PayoDeploymentConfig;
  now: Date;
  dependencies: ExceptionAuthorizationRelayerDependencies;
}): Promise<string> {
  const { job, dependencies, now } = input;
  if (
    BigInt(job.publicInputs.chainId) !== BigInt(input.deployment.chainId)
    || BigInt(job.publicInputs.sealAddress) !== BigInt(input.deployment.sealAddress)
  ) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_DEPLOYMENT_MISMATCH",
      errorMessage: "The exception proof is bound to another PAYO deployment.",
      permanent: true,
    }, now);
    return result.state;
  }
  const requiredVersion = job.workflowType === "wage_claim" ? 6n : 7n;
  if (BigInt(job.publicInputs.proofVersion) !== requiredVersion) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_PROOF_VERSION_INVALID",
      errorMessage: `The ${job.workflowType} job has the wrong proof version.`,
      permanent: true,
    }, now);
    return result.state;
  }

  let chainState: ExceptionAuthorizationState;
  try {
    chainState = await dependencies.readState(input.rpc, {
      sealAddress: input.deployment.sealAddress,
      workflowType: job.workflowType,
      subjectNullifierHigh: job.publicInputs.subjectNullifierHigh,
      subjectNullifierLow: job.publicInputs.subjectNullifierLow,
    });
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_STATE_RPC_FAILURE",
      errorMessage: errorText(error),
    }, now);
    return result.state;
  }

  const nowSeconds = BigInt(Math.floor(now.getTime() / 1_000));
  if (chainState.exists) {
    const bindingError = stateBindingError(chainState, job.publicInputs, job.workflowType);
    if (bindingError) {
      const result = await dependencies.defer(job, {
        errorCode: "EXCEPTION_ONCHAIN_BINDING_MISMATCH",
        errorMessage: bindingError,
        permanent: true,
      }, now);
      return result.state;
    }
    const accepted = job.workflowType === "wage_claim"
      ? chainState.status === 1 || chainState.status === 2
      : chainState.status === 1 || chainState.status === 2;
    if (accepted) {
      if (
        job.workflowType === "wage_remediation"
        && chainState.status === 1
        && nowSeconds > BigInt(job.publicInputs.validityExpiry)
      ) {
        const result = await dependencies.defer(job, {
          errorCode: "REMEDIATION_AUTHORIZATION_EXPIRED",
          errorMessage: "The remediation authorization expired before its private payment was invoked.",
          permanent: true,
        }, now);
        return result.state;
      }
      await dependencies.complete(job, now);
      return "complete";
    }
    const result = await dependencies.defer(job, {
      errorCode: chainState.status === 3
        ? "REMEDIATION_AUTHORIZATION_EXPIRED"
        : "EXCEPTION_ONCHAIN_STATUS_INVALID",
      errorMessage: `PAYO returned unsupported ${job.workflowType} status ${chainState.status}.`,
      permanent: true,
    }, now);
    return result.state;
  }

  if (nowSeconds > BigInt(job.publicInputs.validityExpiry)) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_PROOF_EXPIRED",
      errorMessage: "The exception proof expired before its authorization reached PAYO.",
      permanent: true,
    }, now);
    return result.state;
  }
  if (nowSeconds < BigInt(job.publicInputs.validityStart)) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_PROOF_NOT_YET_VALID",
      errorMessage: "The exception proof validity window has not started.",
    }, now);
    return result.state;
  }

  if (job.transactionHash) {
    let observation: SettlementObservation;
    try {
      observation = await dependencies.observe(input.rpc, job.transactionHash);
    } catch (error) {
      const result = await dependencies.defer(job, {
        errorCode: "EXCEPTION_RECEIPT_RPC_FAILURE",
        errorMessage: errorText(error),
      }, now);
      return result.state;
    }
    if (observation.state === "failed" || observation.state === "reorged") {
      const result = await dependencies.defer(job, {
        errorCode: observation.errorCode ?? "EXCEPTION_TRANSACTION_FAILED",
        errorMessage: observation.errorMessage ?? `Exception authorization transaction ${observation.state}.`,
        clearTransaction: true,
      }, now);
      return result.state;
    }
    const result = await dependencies.defer(job, {
      errorCode: observation.state === "pending"
        ? "EXCEPTION_TRANSACTION_PENDING"
        : "EXCEPTION_STATE_NOT_OBSERVED",
      errorMessage: observation.state === "pending"
        ? "The exception authorization transaction is pending."
        : "The authorization receipt succeeded, but its canonical PAYO state is not observable yet.",
    }, now);
    return result.state;
  }

  const proof: ExceptionCircuitProof = {
    proof: new Uint8Array(),
    proofCalldata: job.proofCalldata,
    calldataHash: hashProofCalldata(job.proofCalldata),
    publicInputs: job.publicInputs,
  };
  const call = job.workflowType === "wage_claim"
    ? buildAuthorizeClaimCall({
      sealAddress: input.deployment.sealAddress,
      chainId: input.deployment.chainId,
      proof,
    })
    : buildAuthorizeRemediationCall({
      sealAddress: input.deployment.sealAddress,
      chainId: input.deployment.chainId,
      proof,
    });
  try {
    const submitted = await input.submitter.submit(call);
    await dependencies.recordSubmission(job, submitted.transactionHash, now);
    return "submitted";
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_SUBMISSION_FAILED",
      errorMessage: errorText(error),
      clearTransaction: true,
    }, now);
    return result.state;
  }
}

export async function processExceptionAuthorizationBatch(input: {
  rpc: ExceptionAuthorizationRpc;
  submitter: ExceptionAuthorizationSubmitter;
  deployment: PayoDeploymentConfig;
  workerId: string;
  limit?: number;
  now?: Date;
  dependencies?: ExceptionAuthorizationRelayerDependencies;
}) {
  const dependencies = input.dependencies ?? defaultDependencies;
  const now = input.now ?? new Date();
  const jobs = await dependencies.lease(input.workerId, input.limit ?? 2, now);
  const results: Array<{ jobId: string; proofBundleId: string; state: string }> = [];
  for (const job of jobs) {
    const state = await processLeasedExceptionAuthorization({
      job,
      rpc: input.rpc,
      submitter: input.submitter,
      deployment: input.deployment,
      now,
      dependencies,
    });
    results.push({ jobId: job.id, proofBundleId: job.proofBundleId, state });
  }
  return { leased: jobs.length, results };
}
