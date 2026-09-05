import "server-only";

import { num, type Call } from "starknet";
import type { SettlementObservation } from "@/lib/domain/settlement";
import {
  advanceVestingAuthorizationJob,
  completeVestingAuthorizationJob,
  deferVestingAuthorizationJob,
  leaseVestingAuthorizationJobs,
  recordVestingAuthorizationSubmission,
  type LeasedVestingAuthorizationJob,
  type VestingAuthorizationStep,
} from "@/lib/persistence/vesting-authorization-repository";
import {
  buildBeginVestingAuthorizationCall,
  buildVerifyVestingAuthorizationProofCall,
  serializeVestingPayrollProofState,
  serializeVestingTransitionProofState,
} from "@/lib/starknet/payo-vesting-book";
import { observeStarknetTransaction, type ConfirmationRpc } from "./confirmation-worker";
import type { PayoVestingBookConfig } from "./payo-deployment";

export type VestingAuthorizationRpc = ConfirmationRpc & {
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

export type VestingAuthorizationSubmitter = {
  submit: (call: Call) => Promise<{ transactionHash: string }>;
};

type PendingVestingState = {
  exists: boolean;
  status: number;
  payrollState: string[];
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

function bool(value: string, label: string): boolean {
  const parsed = BigInt(value);
  if (parsed !== 0n && parsed !== 1n) throw new Error(`${label} is not a Cairo boolean.`);
  return parsed === 1n;
}

function small(value: string, label: string): number {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > 255n) throw new Error(`${label} is outside u8.`);
  return Number(parsed);
}

export async function readVestingAuthorizationChainState(
  rpc: Pick<VestingAuthorizationRpc, "callContract" | "getBlockNumber">,
  input: { sealAddress: string; runNullifierHigh: string; runNullifierLow: string },
): Promise<PendingVestingState> {
  const blockNumber = await rpc.getBlockNumber();
  const response = await rpc.callContract({
    contractAddress: input.sealAddress,
    entrypoint: "get_pending_authorization",
    calldata: [num.toHex(BigInt(input.runNullifierHigh)), num.toHex(BigInt(input.runNullifierLow))],
  }, blockNumber);
  const fields = resultFelts(response, "PAYO vesting authorization");
  if (fields.length !== 78) {
    throw new Error(`PAYO vesting authorization returned ${fields.length} felts; expected 78.`);
  }
  return {
    exists: bool(fields[0], "Vesting authorization existence"),
    status: small(fields[1], "Vesting authorization status"),
    payrollState: fields.slice(2, 16),
    transitionState: fields.slice(16, 71),
    proofHashes: fields.slice(71, 75) as [string, string, string, string],
    verifiedMask: small(fields[75], "Vesting authorization proof mask"),
  };
}

function expectedPayrollState(job: LeasedVestingAuthorizationJob): string[] {
  return serializeVestingPayrollProofState(job.payrollShards[0].publicInputs);
}

function expectedTransitionState(job: LeasedVestingAuthorizationJob): string[] {
  return serializeVestingTransitionProofState(job.vestingBook);
}

function equalFelts(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length
    && left.every((value, index) => BigInt(value) === BigInt(right[index]));
}

function bindingError(job: LeasedVestingAuthorizationJob, state: PendingVestingState): string | null {
  if (!equalFelts(state.payrollState, expectedPayrollState(job))) {
    return "Pending Advanced v2 state differs from its proof bundle.";
  }
  if (!equalFelts(state.transitionState, expectedTransitionState(job))) {
    return "Pending v3 state/book transition differs from its proof bundle.";
  }
  const expectedHashes = [
    job.payrollShards[0].calldataHash,
    job.payrollShards[1].calldataHash,
    job.vestingBook.shards[0].calldataHash,
    job.vestingBook.shards[1].calldataHash,
  ];
  if (!equalFelts(state.proofHashes, expectedHashes)) {
    return "Pending proof hashes differ from the durable authorization.";
  }
  return null;
}

function desiredStep(state: PendingVestingState): VestingAuthorizationStep | "complete" | "invalid" {
  if (!state.exists) return "begin";
  if ((state.status === 2 || state.status === 3) && state.verifiedMask === 15) return "complete";
  if (state.status !== 1) return "invalid";
  if (state.verifiedMask === 0) return "payroll0";
  if (state.verifiedMask === 1) return "payroll1";
  if (state.verifiedMask === 3) return "transition0";
  if (state.verifiedMask === 7) return "transition1";
  return state.verifiedMask === 15 ? "complete" : "invalid";
}

function errorText(error: unknown): string {
  const message = error instanceof Error ? error.message : "State/book authorization failed.";
  return message.length <= 500 ? message : `${message.slice(0, 100)} … ${message.slice(-380)}`;
}

export type VestingAuthorizationRelayerDependencies = {
  lease: typeof leaseVestingAuthorizationJobs;
  readState: typeof readVestingAuthorizationChainState;
  observe: (rpc: ConfirmationRpc, transactionHash: string) => Promise<SettlementObservation>;
  recordSubmission: typeof recordVestingAuthorizationSubmission;
  advance: typeof advanceVestingAuthorizationJob;
  defer: typeof deferVestingAuthorizationJob;
  complete: typeof completeVestingAuthorizationJob;
};

const defaultDependencies: VestingAuthorizationRelayerDependencies = {
  lease: leaseVestingAuthorizationJobs,
  readState: readVestingAuthorizationChainState,
  observe: observeStarknetTransaction,
  recordSubmission: recordVestingAuthorizationSubmission,
  advance: advanceVestingAuthorizationJob,
  defer: deferVestingAuthorizationJob,
  complete: completeVestingAuthorizationJob,
};

async function processLeasedJob(input: {
  job: LeasedVestingAuthorizationJob;
  rpc: VestingAuthorizationRpc;
  submitter: VestingAuthorizationSubmitter;
  deployment: PayoVestingBookConfig;
  now: Date;
  dependencies: VestingAuthorizationRelayerDependencies;
}): Promise<string> {
  const { job, dependencies, now } = input;
  const payroll = job.payrollShards[0].publicInputs;
  const transition = job.vestingBook.shards[0].publicInputs;
  if (BigInt(payroll.chainId) !== BigInt(input.deployment.chainId)
    || BigInt(transition.chainId) !== BigInt(input.deployment.chainId)
    || BigInt(transition.sealAddress) !== BigInt(input.deployment.sealAddress)
    || BigInt(payroll.sealAddress) !== BigInt(transition.sourceSealAddress)) {
    const result = await dependencies.defer(job, {
      errorCode: "VESTING_AUTHORIZATION_DEPLOYMENT_MISMATCH",
      errorMessage: "The staged state/book payroll is bound to another deployment.",
      permanent: true,
    }, now);
    return result.state;
  }
  let chainState: PendingVestingState;
  try {
    chainState = await dependencies.readState(input.rpc, {
      sealAddress: input.deployment.sealAddress,
      runNullifierHigh: payroll.runNullifierHigh,
      runNullifierLow: payroll.runNullifierLow,
    });
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "VESTING_AUTHORIZATION_STATE_RPC_FAILURE",
      errorMessage: errorText(error),
    }, now);
    return result.state;
  }
  if (chainState.exists) {
    const mismatch = bindingError(job, chainState);
    if (mismatch) {
      const result = await dependencies.defer(job, {
        errorCode: "VESTING_PENDING_BINDING_MISMATCH",
        errorMessage: mismatch,
        permanent: true,
      }, now);
      return result.state;
    }
  }
  const desired = desiredStep(chainState);
  if (desired === "complete") {
    await dependencies.complete(job, now);
    return "complete";
  }
  if (desired === "invalid") {
    const result = await dependencies.defer(job, {
      errorCode: "VESTING_AUTHORIZATION_STATE_INVALID",
      errorMessage: `PAYO returned invalid state ${chainState.status} and mask ${chainState.verifiedMask}.`,
      permanent: true,
    }, now);
    return result.state;
  }
  if (desired !== job.activeStep) {
    await dependencies.advance(job, desired, now);
    return "advanced";
  }
  const nowSeconds = BigInt(Math.floor(now.getTime() / 1_000));
  const validityStart = BigInt(payroll.validityStart);
  const validityExpiry = BigInt(payroll.validityExpiry);
  if (nowSeconds < validityStart) {
    const result = await dependencies.defer(job, {
      errorCode: "VESTING_AUTHORIZATION_NOT_YET_VALID",
      errorMessage: "The linked proof window has not started.",
    }, now);
    return result.state;
  }
  if (nowSeconds > validityExpiry) {
    const result = await dependencies.defer(job, {
      errorCode: "VESTING_AUTHORIZATION_PROOF_EXPIRED",
      errorMessage: "The linked proof window expired before authorization.",
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
        errorCode: "VESTING_AUTHORIZATION_RECEIPT_RPC_FAILURE",
        errorMessage: errorText(error),
      }, now);
      return result.state;
    }
    if (observation.state === "failed" || observation.state === "reorged") {
      const result = await dependencies.defer(job, {
        errorCode: observation.errorCode ?? "VESTING_AUTHORIZATION_TRANSACTION_FAILED",
        errorMessage: observation.errorMessage ?? `The ${desired} transaction ${observation.state}.`,
        clearTransaction: true,
      }, now);
      return result.state;
    }
    const result = await dependencies.defer(job, {
      errorCode: observation.state === "pending"
        ? "VESTING_AUTHORIZATION_TRANSACTION_PENDING"
        : "VESTING_AUTHORIZATION_STATE_NOT_OBSERVED",
      errorMessage: observation.state === "pending"
        ? `The ${desired} transaction is pending.`
        : `The ${desired} receipt succeeded, but canonical state is not observable yet.`,
    }, now);
    return result.state;
  }
  const call = desired === "begin"
    ? buildBeginVestingAuthorizationCall({
        sealAddress: input.deployment.sealAddress,
        chainId: input.deployment.chainId,
        payrollShards: job.payrollShards,
        vestingBook: job.vestingBook,
      })
    : buildVerifyVestingAuthorizationProofCall({
        sealAddress: input.deployment.sealAddress,
        runNullifierHigh: payroll.runNullifierHigh,
        runNullifierLow: payroll.runNullifierLow,
        proofKind: desired === "payroll0" ? 0
          : desired === "payroll1" ? 1
            : desired === "transition0" ? 2 : 3,
        proofCalldata: desired === "payroll0" ? job.payrollShards[0].proofCalldata
          : desired === "payroll1" ? job.payrollShards[1].proofCalldata
            : desired === "transition0" ? job.vestingBook.shards[0].proofCalldata
              : job.vestingBook.shards[1].proofCalldata,
      });
  try {
    const submitted = await input.submitter.submit(call);
    await dependencies.recordSubmission(job, desired, submitted.transactionHash, now);
    return "submitted";
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "VESTING_AUTHORIZATION_SUBMISSION_FAILED",
      errorMessage: errorText(error),
      clearTransaction: true,
    }, now);
    return result.state;
  }
}

export async function processVestingAuthorizationBatch(input: {
  rpc: VestingAuthorizationRpc;
  submitter: VestingAuthorizationSubmitter;
  deployment: PayoVestingBookConfig;
  workerId: string;
  limit?: number;
  now?: Date;
  dependencies?: VestingAuthorizationRelayerDependencies;
}) {
  const dependencies = input.dependencies ?? defaultDependencies;
  const now = input.now ?? new Date();
  const jobs = await dependencies.lease(input.workerId, input.limit ?? 1, now);
  const results: Array<{ jobId: string; runId: string; state: string }> = [];
  for (const job of jobs) {
    const state = await processLeasedJob({
      job,
      rpc: input.rpc,
      submitter: input.submitter,
      deployment: input.deployment,
      now,
      dependencies,
    });
    results.push({ jobId: job.id, runId: job.runId, state });
  }
  return { leased: jobs.length, results };
}
