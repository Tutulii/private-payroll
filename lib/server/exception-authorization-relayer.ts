import "server-only";

import { num, type Call } from "starknet";
import type { ExceptionPublicInputsV2 } from "@/lib/domain/exception-protocol";
import type { SettlementObservation } from "@/lib/domain/settlement";
import {
  advanceExceptionAuthorizationJob,
  completeExceptionAuthorizationJob,
  deferExceptionAuthorizationJob,
  leaseExceptionAuthorizationJobs,
  recordExceptionAuthorizationSubmission,
  type ExceptionAuthorizationStep,
  type LeasedExceptionAuthorizationJob,
} from "@/lib/persistence/exception-authorization-repository";
import {
  buildAuthorizeClaimCall,
  buildAuthorizeRemediationCall,
} from "@/lib/starknet/payo-exception-seal";
import {
  buildBeginExceptionBookAuthorizationCall,
  buildFinalizeClaimBookEntryCall,
  buildVerifyVestingAuthorizationProofCall,
  serializeVestingTransitionProofState,
} from "@/lib/starknet/payo-vesting-book";
import {
  observeStarknetTransaction,
  type ConfirmationRpc,
} from "./confirmation-worker";
import type {
  PayoDeploymentConfig,
  PayoVestingBookConfig,
} from "./payo-deployment";

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

export type ExceptionBookAuthorizationState = {
  exists: boolean;
  status: number;
  transitionState: string[];
  proofHashes: [string, string, string, string];
  verifiedMask: number;
};

function resultFelts(response: unknown, label: string): string[] {
  const result = Array.isArray(response)
    ? response
    : response && typeof response === "object"
      ? (response as { result?: unknown }).result
      : undefined;
  if (!Array.isArray(result)) throw new Error(`${label} returned no felt result.`);
  return result.map((value, index) => {
    try {
      const parsed = BigInt(String(value));
      if (parsed < 0n) throw new Error();
      return parsed.toString();
    } catch {
      throw new Error(`${label} felt ${index} is invalid.`);
    }
  });
}

function booleanFelt(value: string, label: string): boolean {
  const parsed = BigInt(value);
  if (parsed !== 0n && parsed !== 1n) throw new Error(`${label} is not a Cairo boolean.`);
  return parsed === 1n;
}

function statusFelt(value: string, label: string): number {
  const parsed = BigInt(value);
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
  const values = resultFelts(response, `PAYO ${input.workflowType} state`);
  const expectedLength = input.workflowType === "wage_claim" ? 14 : 11;
  if (values.length !== expectedLength) {
    throw new Error(`PAYO ${input.workflowType} state returned ${values.length} felts; expected ${expectedLength}.`);
  }
  if (input.workflowType === "wage_claim") {
    return {
      exists: booleanFelt(values[0], "Claim existence"),
      status: statusFelt(values[1], "Claim status"),
      parentNullifierHigh: values[2],
      parentNullifierLow: values[3],
      factCommitmentHigh: values[8],
      factCommitmentLow: values[9],
      actionCommitmentHigh: null,
      actionCommitmentLow: null,
    };
  }
  return {
    exists: booleanFelt(values[0], "Remediation existence"),
    status: statusFelt(values[1], "Remediation status"),
    parentNullifierHigh: values[2],
    parentNullifierLow: values[3],
    factCommitmentHigh: values[4],
    factCommitmentLow: values[5],
    actionCommitmentHigh: values[6],
    actionCommitmentLow: values[7],
  };
}

export async function readExceptionBookAuthorizationState(
  rpc: Pick<ExceptionAuthorizationRpc, "callContract" | "getBlockNumber">,
  input: {
    sealAddress: string;
    subjectNullifierHigh: string;
    subjectNullifierLow: string;
  },
): Promise<ExceptionBookAuthorizationState> {
  const blockNumber = await rpc.getBlockNumber();
  const response = await rpc.callContract({
    contractAddress: input.sealAddress,
    entrypoint: "get_pending_authorization",
    calldata: [
      num.toHex(BigInt(input.subjectNullifierHigh)),
      num.toHex(BigInt(input.subjectNullifierLow)),
    ],
  }, blockNumber);
  const fields = resultFelts(response, "PAYO exception book authorization");
  if (fields.length !== 78) {
    throw new Error(`PAYO exception book authorization returned ${fields.length} felts; expected 78.`);
  }
  return {
    exists: booleanFelt(fields[0], "Exception book existence"),
    status: statusFelt(fields[1], "Exception book status"),
    transitionState: fields.slice(16, 71),
    proofHashes: fields.slice(71, 75) as [string, string, string, string],
    verifiedMask: statusFelt(fields[75], "Exception book proof mask"),
  };
}

export type ExceptionAuthorizationRelayerDependencies = {
  lease: typeof leaseExceptionAuthorizationJobs;
  readSourceState: typeof readExceptionAuthorizationState;
  readBookState: typeof readExceptionBookAuthorizationState;
  observe: (
    rpc: ConfirmationRpc,
    transactionHash: string,
  ) => Promise<SettlementObservation>;
  recordSubmission: typeof recordExceptionAuthorizationSubmission;
  advance: typeof advanceExceptionAuthorizationJob;
  defer: typeof deferExceptionAuthorizationJob;
  complete: typeof completeExceptionAuthorizationJob;
};

const defaultDependencies: ExceptionAuthorizationRelayerDependencies = {
  lease: leaseExceptionAuthorizationJobs,
  readSourceState: readExceptionAuthorizationState,
  readBookState: readExceptionBookAuthorizationState,
  observe: observeStarknetTransaction,
  recordSubmission: recordExceptionAuthorizationSubmission,
  advance: advanceExceptionAuthorizationJob,
  defer: deferExceptionAuthorizationJob,
  complete: completeExceptionAuthorizationJob,
};

function sameFelt(left: string, right: string): boolean {
  return BigInt(left) === BigInt(right);
}

function equalFelts(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length
    && left.every((value, index) => BigInt(value) === BigInt(right[index]));
}

function sourceBindingError(
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

function bookBindingError(
  job: LeasedExceptionAuthorizationJob,
  state: ExceptionBookAuthorizationState,
): string | null {
  const expectedTransition = serializeVestingTransitionProofState(job.vestingBook);
  if (!equalFelts(state.transitionState, expectedTransition)) {
    return "The pending payroll-book state differs from the durable v3 proof.";
  }
  const expectedHashes = [
    "0",
    "0",
    job.vestingBook.shards[0].calldataHash,
    job.vestingBook.shards[1].calldataHash,
  ];
  if (!equalFelts(state.proofHashes, expectedHashes)) {
    return "The pending payroll-book proof hashes differ from the durable v3 proof.";
  }
  return null;
}

function desiredBookStep(
  job: LeasedExceptionAuthorizationJob,
  state: ExceptionBookAuthorizationState,
): ExceptionAuthorizationStep | "complete" | "invalid" {
  if (!state.exists) return "book_begin";
  if (state.status === 3 && state.verifiedMask === 12) return "complete";
  if (state.status === 2 && state.verifiedMask === 12) {
    return job.workflowType === "wage_claim" ? "book_finalize" : "complete";
  }
  if (state.status !== 1) return "invalid";
  if (state.verifiedMask === 0) return "book_transition0";
  if (state.verifiedMask === 4) return "book_transition1";
  return "invalid";
}

function errorText(error: unknown): string {
  const message = error instanceof Error ? error.message : "Exception authorization failed.";
  return message.length <= 500 ? message : `${message.slice(0, 100)} … ${message.slice(-380)}`;
}

async function deferRpc(
  dependencies: ExceptionAuthorizationRelayerDependencies,
  job: LeasedExceptionAuthorizationJob,
  errorCode: string,
  error: unknown,
  now: Date,
) {
  return dependencies.defer(job, {
    errorCode,
    errorMessage: errorText(error),
  }, now);
}

async function processLeasedExceptionAuthorization(input: {
  job: LeasedExceptionAuthorizationJob;
  rpc: ExceptionAuthorizationRpc;
  submitter: ExceptionAuthorizationSubmitter;
  deployment: PayoDeploymentConfig;
  bookDeployment: PayoVestingBookConfig;
  now: Date;
  dependencies: ExceptionAuthorizationRelayerDependencies;
}): Promise<string> {
  const { job, dependencies, now } = input;
  const bookState = job.vestingBook.shards[0].publicInputs;
  if (BigInt(job.publicInputs.chainId) !== BigInt(input.deployment.chainId)
    || BigInt(job.publicInputs.sealAddress) !== BigInt(input.deployment.sealAddress)
    || BigInt(bookState.chainId) !== BigInt(input.bookDeployment.chainId)
    || BigInt(bookState.sealAddress) !== BigInt(input.bookDeployment.sealAddress)) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_DEPLOYMENT_MISMATCH",
      errorMessage: "The source or payroll-book proof is bound to another PAYO deployment.",
      permanent: true,
    }, now);
    return result.state;
  }
  const requiredVersion = job.workflowType === "wage_claim" ? 6n : 7n;
  if (BigInt(job.publicInputs.proofVersion) !== requiredVersion) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_PROOF_VERSION_INVALID",
      errorMessage: `The ${job.workflowType} job has the wrong source proof version.`,
      permanent: true,
    }, now);
    return result.state;
  }
  const nowSeconds = BigInt(Math.floor(now.getTime() / 1_000));
  if (nowSeconds > BigInt(job.publicInputs.validityExpiry)) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_PROOF_EXPIRED",
      errorMessage: "The linked source/book proof window expired before finalization.",
      permanent: true,
    }, now);
    return result.state;
  }
  if (nowSeconds < BigInt(job.publicInputs.validityStart)) {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_PROOF_NOT_YET_VALID",
      errorMessage: "The linked source/book proof window has not started.",
    }, now);
    return result.state;
  }

  let sourceState: ExceptionAuthorizationState;
  try {
    sourceState = await dependencies.readSourceState(input.rpc, {
      sealAddress: input.deployment.sealAddress,
      workflowType: job.workflowType,
      subjectNullifierHigh: job.publicInputs.subjectNullifierHigh,
      subjectNullifierLow: job.publicInputs.subjectNullifierLow,
    });
  } catch (error) {
    return (await deferRpc(dependencies, job, "EXCEPTION_STATE_RPC_FAILURE", error, now)).state;
  }

  let desired: ExceptionAuthorizationStep | "complete" | "invalid" = "source";
  if (sourceState.exists) {
    const bindingError = sourceBindingError(sourceState, job.publicInputs, job.workflowType);
    if (bindingError) {
      const result = await dependencies.defer(job, {
        errorCode: "EXCEPTION_ONCHAIN_BINDING_MISMATCH",
        errorMessage: bindingError,
        permanent: true,
      }, now);
      return result.state;
    }
    if (sourceState.status !== 1 && sourceState.status !== 2) {
      const result = await dependencies.defer(job, {
        errorCode: "EXCEPTION_ONCHAIN_STATUS_INVALID",
        errorMessage: `PAYO returned unsupported ${job.workflowType} status ${sourceState.status}.`,
        permanent: true,
      }, now);
      return result.state;
    }
    let persistedBook: ExceptionBookAuthorizationState;
    try {
      persistedBook = await dependencies.readBookState(input.rpc, {
        sealAddress: input.bookDeployment.sealAddress,
        subjectNullifierHigh: job.publicInputs.subjectNullifierHigh,
        subjectNullifierLow: job.publicInputs.subjectNullifierLow,
      });
    } catch (error) {
      return (await deferRpc(dependencies, job, "EXCEPTION_BOOK_STATE_RPC_FAILURE", error, now)).state;
    }
    if (persistedBook.exists) {
      const bindingError = bookBindingError(job, persistedBook);
      if (bindingError) {
        const result = await dependencies.defer(job, {
          errorCode: "EXCEPTION_BOOK_ONCHAIN_BINDING_MISMATCH",
          errorMessage: bindingError,
          permanent: true,
        }, now);
        return result.state;
      }
    }
    desired = desiredBookStep(job, persistedBook);
  }

  if (desired === "invalid") {
    const result = await dependencies.defer(job, {
      errorCode: "EXCEPTION_BOOK_ONCHAIN_STATUS_INVALID",
      errorMessage: "The payroll-book authorization has an unsupported state or proof mask.",
      permanent: true,
    }, now);
    return result.state;
  }
  if (desired === "complete") {
    await dependencies.complete(job, now);
    return "complete";
  }
  if (desired !== job.activeStep) {
    await dependencies.advance(job, desired, now);
    return "advanced";
  }

  if (job.transactionHash) {
    let observation: SettlementObservation;
    try {
      observation = await dependencies.observe(input.rpc, job.transactionHash);
    } catch (error) {
      return (await deferRpc(dependencies, job, "EXCEPTION_RECEIPT_RPC_FAILURE", error, now)).state;
    }
    if (observation.state === "failed" || observation.state === "reorged") {
      const result = await dependencies.defer(job, {
        errorCode: observation.errorCode ?? "EXCEPTION_TRANSACTION_FAILED",
        errorMessage: observation.errorMessage ?? `Exception ${desired} transaction ${observation.state}.`,
        clearTransaction: true,
      }, now);
      return result.state;
    }
    const result = await dependencies.defer(job, {
      errorCode: observation.state === "pending"
        ? "EXCEPTION_TRANSACTION_PENDING"
        : "EXCEPTION_STATE_NOT_OBSERVED",
      errorMessage: observation.state === "pending"
        ? `The exception ${desired} transaction is pending.`
        : `The exception ${desired} receipt succeeded, but canonical state is not observable yet.`,
    }, now);
    return result.state;
  }

  const call = desired === "source"
    ? job.workflowType === "wage_claim"
      ? buildAuthorizeClaimCall({
          sealAddress: input.deployment.sealAddress,
          chainId: input.deployment.chainId,
          proof: job.sourceProof,
        })
      : buildAuthorizeRemediationCall({
          sealAddress: input.deployment.sealAddress,
          chainId: input.deployment.chainId,
          proof: job.sourceProof,
        })
    : desired === "book_begin"
      ? buildBeginExceptionBookAuthorizationCall({
          sealAddress: input.bookDeployment.sealAddress,
          exceptionSealAddress: input.deployment.sealAddress,
          chainId: input.deployment.chainId,
          sourceProof: job.sourceProof,
          vestingBook: job.vestingBook,
        })
      : desired === "book_finalize"
        ? buildFinalizeClaimBookEntryCall({
            sealAddress: input.bookDeployment.sealAddress,
            exceptionSealAddress: input.deployment.sealAddress,
            chainId: input.deployment.chainId,
            sourceProof: job.sourceProof,
            vestingBook: job.vestingBook,
          })
        : buildVerifyVestingAuthorizationProofCall({
            sealAddress: input.bookDeployment.sealAddress,
            runNullifierHigh: job.publicInputs.subjectNullifierHigh,
            runNullifierLow: job.publicInputs.subjectNullifierLow,
            proofKind: desired === "book_transition0" ? 2 : 3,
            proofCalldata: desired === "book_transition0"
              ? job.vestingBook.shards[0].proofCalldata
              : job.vestingBook.shards[1].proofCalldata,
          });
  try {
    const submitted = await input.submitter.submit(call);
    await dependencies.recordSubmission(job, desired, submitted.transactionHash, now);
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
  bookDeployment: PayoVestingBookConfig;
  workerId: string;
  limit?: number;
  now?: Date;
  dependencies?: ExceptionAuthorizationRelayerDependencies;
}) {
  const dependencies = input.dependencies ?? defaultDependencies;
  const now = input.now ?? new Date();
  const jobs = await dependencies.lease(input.workerId, input.limit ?? 1, now);
  const results: Array<{ jobId: string; proofBundleId: string; state: string }> = [];
  for (const job of jobs) {
    const state = await processLeasedExceptionAuthorization({
      job,
      rpc: input.rpc,
      submitter: input.submitter,
      deployment: input.deployment,
      bookDeployment: input.bookDeployment,
      now,
      dependencies,
    });
    results.push({ jobId: job.id, proofBundleId: job.proofBundleId, state });
  }
  return { leased: jobs.length, results };
}
