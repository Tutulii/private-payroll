import "server-only";

import { num, type Call } from "starknet";
import type { SettlementObservation } from "@/lib/domain/settlement";
import {
  advancePayrollAuthorizationJob,
  completePayrollAuthorizationJob,
  deferPayrollAuthorizationJob,
  leasePayrollAuthorizationJobs,
  recordPayrollAuthorizationSubmission,
  type LeasedPayrollAuthorizationJob,
  type PayrollAuthorizationStep,
} from "@/lib/persistence/payroll-authorization-repository";
import type {
  ExceptionCircuitProof,
  PayrollIntegrityShardProof,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import {
  buildBeginPayrollAuthorizationCall,
  buildVerifyPayrollAuthorizationProofCall,
} from "@/lib/starknet/payo-exception-seal";
import {
  observeStarknetTransaction,
  type ConfirmationRpc,
} from "./confirmation-worker";
import type { PayoDeploymentConfig } from "./payo-deployment";

export type PayrollAuthorizationRpc = ConfirmationRpc & {
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

export type PayrollAuthorizationSubmitter = {
  submit: (call: Call) => Promise<{ transactionHash: string }>;
};

type SnapshotState = {
  exists: boolean;
  agreementRootHigh: string;
  agreementRootLow: string;
  claimRootHigh: string;
  claimRootLow: string;
  policyRootHigh: string;
  policyRootLow: string;
  factHigh: string;
  factLow: string;
};

type PendingState = {
  exists: boolean;
  status: number;
  payrollState: string[];
  snapshotState: string[];
  payrollShardHashes: readonly [string, string];
  snapshotProofHash: string;
  verifiedMask: number;
};

type RunAnchorState = {
  exists: boolean;
  invoked: boolean;
  agreementRootHigh: string;
  agreementRootLow: string;
  manifestRootHigh: string;
  manifestRootLow: string;
  policyRootHigh: string;
  policyRootLow: string;
  fxRootHigh: string;
  fxRootLow: string;
  snapshotFactHigh: string;
  snapshotFactLow: string;
};

export type PayrollAuthorizationChainState = {
  snapshot: SnapshotState;
  pending: PendingState;
  anchor: RunAnchorState;
};

function resultFelts(response: unknown, label: string): string[] {
  const values = Array.isArray(response)
    ? response
    : response && typeof response === "object"
      ? (response as { result?: unknown }).result
      : undefined;
  if (!Array.isArray(values)) throw new Error(`${label} returned no felt result.`);
  return values.map((value, index) => {
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

function u8(value: string, label: string): number {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > 255n) throw new Error(`${label} is outside u8.`);
  return Number(parsed);
}

export async function readPayrollAuthorizationChainState(
  rpc: Pick<PayrollAuthorizationRpc, "callContract" | "getBlockNumber">,
  input: { sealAddress: string; runNullifierHigh: string; runNullifierLow: string },
): Promise<PayrollAuthorizationChainState> {
  const blockNumber = await rpc.getBlockNumber();
  const calldata = [
    num.toHex(BigInt(input.runNullifierHigh)),
    num.toHex(BigInt(input.runNullifierLow)),
  ];
  const [snapshotResponse, pendingResponse, anchorResponse] = await Promise.all([
    rpc.callContract({ contractAddress: input.sealAddress, entrypoint: "get_snapshot", calldata }, blockNumber),
    rpc.callContract({ contractAddress: input.sealAddress, entrypoint: "get_pending_payroll_authorization", calldata }, blockNumber),
    rpc.callContract({ contractAddress: input.sealAddress, entrypoint: "get_run_anchor", calldata }, blockNumber),
  ]);
  const snapshot = resultFelts(snapshotResponse, "PAYO snapshot");
  const pending = resultFelts(pendingResponse, "PAYO pending payroll authorization");
  const anchor = resultFelts(anchorResponse, "PAYO run anchor");
  if (snapshot.length !== 15) throw new Error(`PAYO snapshot returned ${snapshot.length} felts; expected 15.`);
  if (pending.length !== 43) throw new Error(`PAYO pending authorization returned ${pending.length} felts; expected 43.`);
  if (anchor.length !== 14) throw new Error(`PAYO run anchor returned ${anchor.length} felts; expected 14.`);
  return {
    snapshot: {
      exists: booleanFelt(snapshot[0], "Snapshot existence"),
      agreementRootHigh: snapshot[2],
      agreementRootLow: snapshot[3],
      claimRootHigh: snapshot[4],
      claimRootLow: snapshot[5],
      policyRootHigh: snapshot[6],
      policyRootLow: snapshot[7],
      factHigh: snapshot[8],
      factLow: snapshot[9],
    },
    pending: {
      exists: booleanFelt(pending[0], "Pending authorization existence"),
      status: u8(pending[1], "Pending authorization status"),
      payrollState: pending.slice(2, 16),
      snapshotState: pending.slice(16, 37),
      payrollShardHashes: [pending[37], pending[38]],
      snapshotProofHash: pending[39],
      verifiedMask: u8(pending[40], "Pending authorization proof mask"),
    },
    anchor: {
      exists: booleanFelt(anchor[0], "Run anchor existence"),
      invoked: booleanFelt(anchor[1], "Run anchor invocation"),
      agreementRootHigh: anchor[2],
      agreementRootLow: anchor[3],
      manifestRootHigh: anchor[4],
      manifestRootLow: anchor[5],
      policyRootHigh: anchor[6],
      policyRootLow: anchor[7],
      fxRootHigh: anchor[8],
      fxRootLow: anchor[9],
      snapshotFactHigh: anchor[10],
      snapshotFactLow: anchor[11],
    },
  };
}

export type PayrollAuthorizationRelayerDependencies = {
  lease: typeof leasePayrollAuthorizationJobs;
  readState: typeof readPayrollAuthorizationChainState;
  observe: (rpc: ConfirmationRpc, transactionHash: string) => Promise<SettlementObservation>;
  recordSubmission: typeof recordPayrollAuthorizationSubmission;
  advance: typeof advancePayrollAuthorizationJob;
  defer: typeof deferPayrollAuthorizationJob;
  complete: typeof completePayrollAuthorizationJob;
};

const defaultDependencies: PayrollAuthorizationRelayerDependencies = {
  lease: leasePayrollAuthorizationJobs,
  readState: readPayrollAuthorizationChainState,
  observe: observeStarknetTransaction,
  recordSubmission: recordPayrollAuthorizationSubmission,
  advance: advancePayrollAuthorizationJob,
  defer: deferPayrollAuthorizationJob,
  complete: completePayrollAuthorizationJob,
};

function expectedPayrollState(job: LeasedPayrollAuthorizationJob): string[] {
  const value = job.payrollPublicInputs;
  return [
    value.proofVersion,
    value.schemaVersion,
    value.agreementRootHigh,
    value.agreementRootLow,
    value.manifestRootHigh,
    value.manifestRootLow,
    value.policyRootHigh,
    value.policyRootLow,
    value.fxRootHigh,
    value.fxRootLow,
    value.runNullifierHigh,
    value.runNullifierLow,
    value.validityStart,
    value.validityExpiry,
  ];
}

function expectedSnapshotState(job: LeasedPayrollAuthorizationJob): string[] {
  const value = job.snapshotPublicInputs;
  return [
    value.proofVersion,
    value.schemaVersion,
    value.agreementRootHigh,
    value.agreementRootLow,
    value.manifestRootHigh,
    value.manifestRootLow,
    value.policyRootHigh,
    value.policyRootLow,
    value.fxRootHigh,
    value.fxRootLow,
    value.subjectNullifierHigh,
    value.subjectNullifierLow,
    value.parentNullifierHigh,
    value.parentNullifierLow,
    value.factCommitmentHigh,
    value.factCommitmentLow,
    value.parentFactCommitmentHigh,
    value.parentFactCommitmentLow,
    value.validityStart,
    value.validityExpiry,
    value.shardIndex,
  ];
}

function equalFelts(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => BigInt(value) === BigInt(right[index]));
}

function snapshotBindingError(job: LeasedPayrollAuthorizationJob, state: SnapshotState): string | null {
  const expected = job.snapshotPublicInputs;
  const pairs: Array<[string, string, string]> = [
    [state.agreementRootHigh, expected.agreementRootHigh, "agreement root high"],
    [state.agreementRootLow, expected.agreementRootLow, "agreement root low"],
    [state.claimRootHigh, expected.manifestRootHigh, "claim root high"],
    [state.claimRootLow, expected.manifestRootLow, "claim root low"],
    [state.policyRootHigh, expected.policyRootHigh, "policy root high"],
    [state.policyRootLow, expected.policyRootLow, "policy root low"],
    [state.factHigh, expected.factCommitmentHigh, "snapshot fact high"],
    [state.factLow, expected.factCommitmentLow, "snapshot fact low"],
  ];
  const mismatch = pairs.find(([actual, wanted]) => BigInt(actual) !== BigInt(wanted));
  return mismatch ? `Registered snapshot differs at ${mismatch[2]}.` : null;
}

function anchorBindingError(job: LeasedPayrollAuthorizationJob, anchor: RunAnchorState): string | null {
  const payroll = job.payrollPublicInputs;
  const snapshot = job.snapshotPublicInputs;
  const pairs: Array<[string, string, string]> = [
    [anchor.agreementRootHigh, payroll.agreementRootHigh, "agreement root high"],
    [anchor.agreementRootLow, payroll.agreementRootLow, "agreement root low"],
    [anchor.manifestRootHigh, payroll.manifestRootHigh, "manifest root high"],
    [anchor.manifestRootLow, payroll.manifestRootLow, "manifest root low"],
    [anchor.policyRootHigh, payroll.policyRootHigh, "policy root high"],
    [anchor.policyRootLow, payroll.policyRootLow, "policy root low"],
    [anchor.fxRootHigh, payroll.fxRootHigh, "FX root high"],
    [anchor.fxRootLow, payroll.fxRootLow, "FX root low"],
    [anchor.snapshotFactHigh, snapshot.factCommitmentHigh, "snapshot fact high"],
    [anchor.snapshotFactLow, snapshot.factCommitmentLow, "snapshot fact low"],
  ];
  const mismatch = pairs.find(([actual, wanted]) => BigInt(actual) !== BigInt(wanted));
  return mismatch ? `Run anchor differs at ${mismatch[2]}.` : null;
}

function pendingBindingError(job: LeasedPayrollAuthorizationJob, state: PendingState): string | null {
  if (!equalFelts(state.payrollState, expectedPayrollState(job))) return "Pending payroll public state differs from its proof bundle.";
  if (!equalFelts(state.snapshotState, expectedSnapshotState(job))) return "Pending snapshot public state differs from its proof bundle.";
  if (
    BigInt(state.payrollShardHashes[0]) !== BigInt(job.payrollShardHashes[0])
    || BigInt(state.payrollShardHashes[1]) !== BigInt(job.payrollShardHashes[1])
    || BigInt(state.snapshotProofHash) !== BigInt(job.snapshotProofHash)
  ) return "Pending proof hashes differ from the durable staged authorization.";
  return null;
}

function desiredStep(state: PendingState): PayrollAuthorizationStep | "complete" | "invalid" {
  if (!state.exists) return "begin";
  if (state.status === 2 && state.verifiedMask === 7) return "complete";
  if (state.status !== 1) return "invalid";
  if (state.verifiedMask === 0) return "snapshot";
  if (state.verifiedMask === 4) return "shard0";
  if (state.verifiedMask === 5) return "shard1";
  return state.verifiedMask === 7 ? "complete" : "invalid";
}

function errorText(error: unknown): string {
  const message = error instanceof Error ? error.message : "Staged payroll authorization failed.";
  return message.length <= 500 ? message : `${message.slice(0, 100)} … ${message.slice(-380)}`;
}

function proofObjects(job: LeasedPayrollAuthorizationJob) {
  const payrollShards = job.payrollShards.map((proofCalldata, shardIndex) => ({
    shardIndex: shardIndex as 0 | 1,
    proof: new Uint8Array(),
    proofCalldata,
    calldataHash: hashProofCalldata(proofCalldata),
    publicInputs: { ...job.payrollPublicInputs, shardIndex: String(shardIndex) },
  })) as [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  const snapshotProof: ExceptionCircuitProof = {
    proof: new Uint8Array(),
    proofCalldata: job.snapshotProof,
    calldataHash: hashProofCalldata(job.snapshotProof),
    publicInputs: job.snapshotPublicInputs,
  };
  return { payrollShards, snapshotProof };
}

async function processLeasedJob(input: {
  job: LeasedPayrollAuthorizationJob;
  rpc: PayrollAuthorizationRpc;
  submitter: PayrollAuthorizationSubmitter;
  deployment: PayoDeploymentConfig;
  now: Date;
  dependencies: PayrollAuthorizationRelayerDependencies;
}): Promise<string> {
  const { job, dependencies, now } = input;
  if (
    BigInt(job.payrollPublicInputs.chainId) !== BigInt(input.deployment.chainId)
    || BigInt(job.payrollPublicInputs.sealAddress) !== BigInt(input.deployment.sealAddress)
    || BigInt(job.snapshotPublicInputs.chainId) !== BigInt(input.deployment.chainId)
    || BigInt(job.snapshotPublicInputs.sealAddress) !== BigInt(input.deployment.sealAddress)
  ) {
    const result = await dependencies.defer(job, {
      errorCode: "PAYROLL_AUTHORIZATION_DEPLOYMENT_MISMATCH",
      errorMessage: "The staged payroll is bound to another PAYO deployment.",
      permanent: true,
    }, now);
    return result.state;
  }
  let chainState: PayrollAuthorizationChainState;
  try {
    chainState = await dependencies.readState(input.rpc, {
      sealAddress: input.deployment.sealAddress,
      runNullifierHigh: job.payrollPublicInputs.runNullifierHigh,
      runNullifierLow: job.payrollPublicInputs.runNullifierLow,
    });
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "PAYROLL_AUTHORIZATION_STATE_RPC_FAILURE",
      errorMessage: errorText(error),
    }, now);
    return result.state;
  }
  if (chainState.anchor.exists) {
    const bindingError = anchorBindingError(job, chainState.anchor);
    if (bindingError) {
      const result = await dependencies.defer(job, {
        errorCode: "PAYROLL_ANCHOR_BINDING_MISMATCH",
        errorMessage: bindingError,
        permanent: true,
      }, now);
      return result.state;
    }
    await dependencies.complete(job, now);
    return "complete";
  }
  const nowSeconds = BigInt(Math.floor(now.getTime() / 1_000));
  const snapshotExpiry = BigInt(job.snapshotPublicInputs.validityExpiry);
  const payrollExpiry = BigInt(job.payrollPublicInputs.validityExpiry);
  if (!chainState.snapshot.exists) {
    const result = await dependencies.defer(job, {
      errorCode: snapshotExpiry <= nowSeconds ? "SNAPSHOT_REGISTRATION_EXPIRED" : "SNAPSHOT_NOT_REGISTERED",
      errorMessage: snapshotExpiry <= nowSeconds
        ? "The pre-payday snapshot was not registered before its proof expired."
        : "Waiting for the committed owner to register the pre-payday obligation snapshot.",
      permanent: snapshotExpiry <= nowSeconds,
    }, now);
    return result.state;
  }
  const snapshotError = snapshotBindingError(job, chainState.snapshot);
  if (snapshotError) {
    const result = await dependencies.defer(job, {
      errorCode: "SNAPSHOT_REGISTRATION_BINDING_MISMATCH",
      errorMessage: snapshotError,
      permanent: true,
    }, now);
    return result.state;
  }
  if (chainState.pending.exists) {
    const bindingError = pendingBindingError(job, chainState.pending);
    if (bindingError) {
      const result = await dependencies.defer(job, {
        errorCode: "PAYROLL_PENDING_BINDING_MISMATCH",
        errorMessage: bindingError,
        permanent: true,
      }, now);
      return result.state;
    }
  }
  const desired = desiredStep(chainState.pending);
  if (desired === "complete") {
    const result = await dependencies.defer(job, {
      errorCode: "PAYROLL_ANCHOR_NOT_OBSERVED",
      errorMessage: "All staged proofs are recorded, but the atomic run anchor is not observable yet.",
    }, now);
    return result.state;
  }
  if (desired === "invalid") {
    const result = await dependencies.defer(job, {
      errorCode: "PAYROLL_AUTHORIZATION_STATE_INVALID",
      errorMessage: `PAYO returned invalid staged status ${chainState.pending.status} and mask ${chainState.pending.verifiedMask}.`,
      permanent: true,
    }, now);
    return result.state;
  }
  if (desired !== job.activeStep) {
    await dependencies.advance(job, desired, now);
    return "advanced";
  }
  const validityStart = BigInt(desired === "begin" || desired === "snapshot"
    ? job.snapshotPublicInputs.validityStart
    : job.payrollPublicInputs.validityStart);
  const validityExpiry = desired === "begin" || desired === "snapshot" ? snapshotExpiry : payrollExpiry;
  if (nowSeconds < validityStart) {
    const result = await dependencies.defer(job, {
      errorCode: "PAYROLL_AUTHORIZATION_NOT_YET_VALID",
      errorMessage: `The ${desired} proof window has not started.`,
    }, now);
    return result.state;
  }
  if (nowSeconds > validityExpiry) {
    const result = await dependencies.defer(job, {
      errorCode: "PAYROLL_AUTHORIZATION_PROOF_EXPIRED",
      errorMessage: `The ${desired} proof window expired before authorization.`,
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
        errorCode: "PAYROLL_AUTHORIZATION_RECEIPT_RPC_FAILURE",
        errorMessage: errorText(error),
      }, now);
      return result.state;
    }
    if (observation.state === "failed" || observation.state === "reorged") {
      const result = await dependencies.defer(job, {
        errorCode: observation.errorCode ?? "PAYROLL_AUTHORIZATION_TRANSACTION_FAILED",
        errorMessage: observation.errorMessage ?? `The ${desired} transaction ${observation.state}.`,
        clearTransaction: true,
      }, now);
      return result.state;
    }
    const result = await dependencies.defer(job, {
      errorCode: observation.state === "pending"
        ? "PAYROLL_AUTHORIZATION_TRANSACTION_PENDING"
        : "PAYROLL_AUTHORIZATION_STATE_NOT_OBSERVED",
      errorMessage: observation.state === "pending"
        ? `The ${desired} transaction is pending.`
        : `The ${desired} receipt succeeded, but canonical PAYO state is not observable yet.`,
    }, now);
    return result.state;
  }
  const { payrollShards, snapshotProof } = proofObjects(job);
  const call = desired === "begin"
    ? buildBeginPayrollAuthorizationCall({
      sealAddress: input.deployment.sealAddress,
      chainId: input.deployment.chainId,
      payrollShards,
      snapshotProof,
    })
    : buildVerifyPayrollAuthorizationProofCall({
      sealAddress: input.deployment.sealAddress,
      runNullifierHigh: job.payrollPublicInputs.runNullifierHigh,
      runNullifierLow: job.payrollPublicInputs.runNullifierLow,
      proofKind: desired === "snapshot" ? 2 : desired === "shard0" ? 0 : 1,
      proofCalldata: desired === "snapshot"
        ? job.snapshotProof
        : desired === "shard0"
          ? job.payrollShards[0]
          : job.payrollShards[1],
    });
  try {
    const submitted = await input.submitter.submit(call);
    await dependencies.recordSubmission(job, desired, submitted.transactionHash, now);
    return "submitted";
  } catch (error) {
    const result = await dependencies.defer(job, {
      errorCode: "PAYROLL_AUTHORIZATION_SUBMISSION_FAILED",
      errorMessage: errorText(error),
      clearTransaction: true,
    }, now);
    return result.state;
  }
}

export async function processPayrollAuthorizationBatch(input: {
  rpc: PayrollAuthorizationRpc;
  submitter: PayrollAuthorizationSubmitter;
  deployment: PayoDeploymentConfig;
  workerId: string;
  limit?: number;
  now?: Date;
  dependencies?: PayrollAuthorizationRelayerDependencies;
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
