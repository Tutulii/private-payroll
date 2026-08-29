import { describe, expect, it, vi } from "vitest";
import type { LeasedPayrollAuthorizationJob } from "@/lib/persistence/payroll-authorization-repository";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import {
  processPayrollAuthorizationBatch,
  readPayrollAuthorizationChainState,
  type PayrollAuthorizationChainState,
  type PayrollAuthorizationRelayerDependencies,
  type PayrollAuthorizationRpc,
} from "./payroll-authorization-relayer";

const sealAddress = "0x12345";
const deployment = { chainId: "0x1", sealAddress };
const now = new Date("2026-08-28T00:00:00.000Z");
const proof = ["0x1"];

function leasedJob(overrides: Partial<LeasedPayrollAuthorizationJob> = {}): LeasedPayrollAuthorizationJob {
  const payrollPublicInputs = {
    chainId: "0x1",
    sealAddress,
    proofVersion: "2",
    schemaVersion: "1",
    agreementRootHigh: "3",
    agreementRootLow: "4",
    manifestRootHigh: "5",
    manifestRootLow: "6",
    policyRootHigh: "7",
    policyRootLow: "8",
    fxRootHigh: "9",
    fxRootLow: "10",
    runNullifierHigh: "11",
    runNullifierLow: "12",
    validityStart: "1",
    validityExpiry: "2000000000",
  };
  const snapshotPublicInputs = {
    chainId: "0x1",
    sealAddress,
    proofVersion: "5",
    schemaVersion: "2",
    agreementRootHigh: "3",
    agreementRootLow: "4",
    manifestRootHigh: "13",
    manifestRootLow: "14",
    policyRootHigh: "7",
    policyRootLow: "8",
    fxRootHigh: "0",
    fxRootLow: "0",
    subjectNullifierHigh: "11",
    subjectNullifierLow: "12",
    parentNullifierHigh: "0",
    parentNullifierLow: "0",
    factCommitmentHigh: "15",
    factCommitmentLow: "16",
    parentFactCommitmentHigh: "0",
    parentFactCommitmentLow: "0",
    validityStart: "1",
    validityExpiry: "2000000000",
    shardIndex: "0",
  };
  return {
    id: "job-1",
    organizationId: "organization-1",
    runId: "run-1",
    payrollProofBundleId: "payroll-bundle",
    snapshotProofBundleId: "snapshot-bundle",
    attempts: 0,
    activeStep: "begin",
    transactionHash: null,
    beginTransactionHash: null,
    snapshotTransactionHash: null,
    shard0TransactionHash: null,
    shard1TransactionHash: null,
    payrollShards: [proof, proof],
    snapshotProof: ["0x2"],
    payrollPublicInputs,
    snapshotPublicInputs,
    payrollShardHashes: [hashProofCalldata(proof), hashProofCalldata(proof)],
    snapshotProofHash: hashProofCalldata(["0x2"]),
    leaseOwner: "worker-1",
    ...overrides,
  };
}

function payrollState(job: LeasedPayrollAuthorizationJob): string[] {
  const value = job.payrollPublicInputs;
  return [
    value.proofVersion, value.schemaVersion,
    value.agreementRootHigh, value.agreementRootLow,
    value.manifestRootHigh, value.manifestRootLow,
    value.policyRootHigh, value.policyRootLow,
    value.fxRootHigh, value.fxRootLow,
    value.runNullifierHigh, value.runNullifierLow,
    value.validityStart, value.validityExpiry,
  ];
}

function snapshotProofState(job: LeasedPayrollAuthorizationJob): string[] {
  const value = job.snapshotPublicInputs;
  return [
    value.proofVersion, value.schemaVersion,
    value.agreementRootHigh, value.agreementRootLow,
    value.manifestRootHigh, value.manifestRootLow,
    value.policyRootHigh, value.policyRootLow,
    value.fxRootHigh, value.fxRootLow,
    value.subjectNullifierHigh, value.subjectNullifierLow,
    value.parentNullifierHigh, value.parentNullifierLow,
    value.factCommitmentHigh, value.factCommitmentLow,
    value.parentFactCommitmentHigh, value.parentFactCommitmentLow,
    value.validityStart, value.validityExpiry, value.shardIndex,
  ];
}

function chainState(job = leasedJob(), input: {
  snapshot?: boolean;
  pending?: boolean;
  status?: number;
  mask?: number;
  anchor?: boolean;
} = {}): PayrollAuthorizationChainState {
  return {
    snapshot: {
      exists: input.snapshot ?? true,
      agreementRootHigh: "3",
      agreementRootLow: "4",
      claimRootHigh: "13",
      claimRootLow: "14",
      policyRootHigh: "7",
      policyRootLow: "8",
      factHigh: "15",
      factLow: "16",
    },
    pending: {
      exists: input.pending ?? false,
      status: input.status ?? 0,
      payrollState: payrollState(job),
      snapshotState: snapshotProofState(job),
      payrollShardHashes: job.payrollShardHashes,
      snapshotProofHash: job.snapshotProofHash,
      verifiedMask: input.mask ?? 0,
    },
    anchor: {
      exists: input.anchor ?? false,
      invoked: false,
      agreementRootHigh: "3",
      agreementRootLow: "4",
      manifestRootHigh: "5",
      manifestRootLow: "6",
      policyRootHigh: "7",
      policyRootLow: "8",
      fxRootHigh: "9",
      fxRootLow: "10",
      snapshotFactHigh: "15",
      snapshotFactLow: "16",
    },
  };
}

function rpc(): PayrollAuthorizationRpc {
  return {
    callContract: vi.fn(),
    getTransactionReceipt: vi.fn(),
    getBlockNumber: vi.fn(),
    getBlockWithTxHashes: vi.fn(),
  };
}

function dependencies(job: LeasedPayrollAuthorizationJob, state: PayrollAuthorizationChainState) {
  const recordSubmission = vi.fn().mockResolvedValue({ state: "pending" });
  const advance = vi.fn().mockResolvedValue({ state: "pending" });
  const defer = vi.fn().mockImplementation((_job, options) => Promise.resolve({
    state: options.permanent ? "dead" : "pending",
  }));
  const complete = vi.fn().mockResolvedValue({ state: "complete" });
  const deps = {
    lease: vi.fn().mockResolvedValue([job]),
    readState: vi.fn().mockResolvedValue(state),
    observe: vi.fn().mockResolvedValue({ state: "pending", confirmationDepth: 0 }),
    recordSubmission,
    advance,
    defer,
    complete,
  } as unknown as PayrollAuthorizationRelayerDependencies;
  return { deps, recordSubmission, advance, defer, complete };
}

describe("PAYO staged payroll authorization relayer", () => {
  it("reads snapshot, pending proof state and run anchor at one block", async () => {
    const job = leasedJob();
    const snapshot = ["1", "99", "3", "4", "13", "14", "7", "8", "15", "16", "100", "110", "120", "90", "0"];
    const pending = [
      "1", "1", ...payrollState(job), ...snapshotProofState(job),
      job.payrollShardHashes[0], job.payrollShardHashes[1], job.snapshotProofHash,
      "4", "90", "91",
    ];
    const anchor = ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"];
    const callContract = vi.fn()
      .mockResolvedValueOnce(snapshot)
      .mockResolvedValueOnce({ result: pending })
      .mockResolvedValueOnce(anchor);
    await expect(readPayrollAuthorizationChainState({
      callContract,
      getBlockNumber: vi.fn().mockResolvedValue(321),
    }, {
      sealAddress,
      runNullifierHigh: "11",
      runNullifierLow: "12",
    })).resolves.toMatchObject({
      snapshot: { exists: true, factHigh: "15" },
      pending: { exists: true, status: 1, verifiedMask: 4 },
      anchor: { exists: false },
    });
    expect(callContract).toHaveBeenCalledTimes(3);
    expect(callContract.mock.calls.every((call) => call[1] === 321)).toBe(true);
  });

  it("waits without submitting until the committed owner registers the snapshot", async () => {
    const job = leasedJob();
    const { deps, defer, recordSubmission } = dependencies(job, chainState(job, { snapshot: false }));
    await processPayrollAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({ errorCode: "SNAPSHOT_NOT_REGISTERED" }), now);
    expect(recordSubmission).not.toHaveBeenCalled();
  });

  it("submits the compact begin call before any proof calldata", async () => {
    const job = leasedJob();
    const { deps, recordSubmission } = dependencies(job, chainState(job));
    const submit = vi.fn().mockResolvedValue({ transactionHash: "0xabc" });
    await processPayrollAuthorizationBatch({
      rpc: rpc(), submitter: { submit }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({ entrypoint: "begin_payroll_authorization" }));
    expect(recordSubmission).toHaveBeenCalledWith(job, "begin", "0xabc", now);
  });

  it("advances from a recorded begin to snapshot proof without resubmitting", async () => {
    const job = leasedJob({ activeStep: "begin", transactionHash: "0xabc" });
    const { deps, advance } = dependencies(job, chainState(job, { pending: true, status: 1, mask: 0 }));
    await processPayrollAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(advance).toHaveBeenCalledWith(job, "snapshot", now);
  });

  it("enforces snapshot-first ordering and then advances through both payroll shards", async () => {
    const snapshotJob = leasedJob({ activeStep: "snapshot" });
    const snapshotDeps = dependencies(snapshotJob, chainState(snapshotJob, { pending: true, status: 1, mask: 0 }));
    const submit = vi.fn().mockResolvedValue({ transactionHash: "0xdef" });
    await processPayrollAuthorizationBatch({
      rpc: rpc(), submitter: { submit }, deployment, workerId: "worker-1", now, dependencies: snapshotDeps.deps,
    });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({
      entrypoint: "verify_payroll_authorization_proof",
      calldata: ["0xb", "0xc", "0x2", "0x1", "0x2"],
    }));
    const shardJob = leasedJob({ activeStep: "snapshot", snapshotTransactionHash: "0xdef" });
    const shardDeps = dependencies(shardJob, chainState(shardJob, { pending: true, status: 1, mask: 4 }));
    await processPayrollAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: shardDeps.deps,
    });
    expect(shardDeps.advance).toHaveBeenCalledWith(shardJob, "shard0", now);
    const finalJob = leasedJob({ activeStep: "shard0" });
    const finalDeps = dependencies(finalJob, chainState(finalJob, { pending: true, status: 1, mask: 5 }));
    await processPayrollAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: finalDeps.deps,
    });
    expect(finalDeps.advance).toHaveBeenCalledWith(finalJob, "shard1", now);
  });

  it("completes only from an exactly matching immutable run anchor", async () => {
    const job = leasedJob({
      activeStep: "shard1",
      beginTransactionHash: "0x1",
      snapshotTransactionHash: "0x2",
      shard0TransactionHash: "0x3",
      shard1TransactionHash: "0x4",
    });
    const { deps, complete } = dependencies(job, chainState(job, { anchor: true, pending: true, status: 2, mask: 7 }));
    await processPayrollAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(complete).toHaveBeenCalledWith(job, now);
  });

  it("fails closed on a cross-proof or registered-snapshot binding mismatch", async () => {
    const job = leasedJob();
    const state = chainState(job);
    state.snapshot.factHigh = "999";
    const { deps, defer } = dependencies(job, state);
    await processPayrollAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "SNAPSHOT_REGISTRATION_BINDING_MISMATCH",
      permanent: true,
    }), now);
  });
});
