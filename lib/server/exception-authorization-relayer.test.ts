import { describe, expect, it, vi } from "vitest";
import type { LeasedExceptionAuthorizationJob } from "@/lib/persistence/exception-authorization-repository";
import {
  processExceptionAuthorizationBatch,
  readExceptionAuthorizationState,
  type ExceptionAuthorizationRelayerDependencies,
  type ExceptionAuthorizationRpc,
  type ExceptionAuthorizationState,
} from "./exception-authorization-relayer";

const sealAddress = "0x12345";
const deployment = { chainId: "0x1", sealAddress };
const now = new Date("2026-08-28T00:00:00.000Z");

function leasedJob(
  overrides: Partial<LeasedExceptionAuthorizationJob> = {},
): LeasedExceptionAuthorizationJob {
  return {
    id: "job-1",
    organizationId: "organization-1",
    runId: "run-1",
    proofBundleId: "bundle-1",
    workflowType: "wage_claim",
    subjectRecordId: "claim-1",
    attempts: 0,
    transactionHash: null,
    proofCalldata: ["0x1"],
    publicInputs: {
      chainId: "0x1",
      sealAddress,
      proofVersion: "6",
      schemaVersion: "2",
      agreementRootHigh: "1",
      agreementRootLow: "2",
      manifestRootHigh: "3",
      manifestRootLow: "4",
      policyRootHigh: "5",
      policyRootLow: "6",
      fxRootHigh: "7",
      fxRootLow: "8",
      subjectNullifierHigh: "9",
      subjectNullifierLow: "10",
      parentNullifierHigh: "11",
      parentNullifierLow: "12",
      factCommitmentHigh: "13",
      factCommitmentLow: "14",
      parentFactCommitmentHigh: "15",
      parentFactCommitmentLow: "16",
      validityStart: "1",
      validityExpiry: "2000000000",
      shardIndex: "0",
    },
    leaseOwner: "worker-1",
    ...overrides,
  };
}

function absentState(): ExceptionAuthorizationState {
  return {
    exists: false,
    status: 0,
    parentNullifierHigh: "0",
    parentNullifierLow: "0",
    factCommitmentHigh: "0",
    factCommitmentLow: "0",
    actionCommitmentHigh: null,
    actionCommitmentLow: null,
  };
}

function rpc(): ExceptionAuthorizationRpc {
  return {
    callContract: vi.fn(),
    getTransactionReceipt: vi.fn(),
    getBlockNumber: vi.fn(),
    getBlockWithTxHashes: vi.fn(),
  };
}

function dependencies(input: {
  job?: LeasedExceptionAuthorizationJob;
  state?: ExceptionAuthorizationState;
  observation?: Awaited<ReturnType<ExceptionAuthorizationRelayerDependencies["observe"]>>;
}) {
  const recordSubmission = vi.fn().mockResolvedValue({ state: "pending" });
  const defer = vi.fn().mockImplementation((_job, options) => Promise.resolve({
    state: options.permanent ? "dead" : "pending",
  }));
  const complete = vi.fn().mockResolvedValue({ state: "complete" });
  const deps = {
    lease: vi.fn().mockResolvedValue([input.job ?? leasedJob()]),
    readState: vi.fn().mockResolvedValue(input.state ?? absentState()),
    observe: vi.fn().mockResolvedValue(input.observation ?? {
      state: "pending",
      confirmationDepth: 0,
    }),
    recordSubmission,
    defer,
    complete,
  } as unknown as ExceptionAuthorizationRelayerDependencies;
  return { deps, recordSubmission, defer, complete };
}

describe("PAYO vNext exception authorization relayer", () => {
  it("reads claim and remediation records at one pinned block", async () => {
    const callContract = vi.fn()
      .mockResolvedValueOnce({
        result: ["0x1", "0x1", "0xb", "0xc", "0x1", "0x2", "0x5", "0x6", "0xd", "0xe", "0x10", "0x0", "0x0", "0x0"],
      })
      .mockResolvedValueOnce([
        "0x1", "0x1", "0x9", "0xa", "0xd", "0xe", "0x3", "0x4", "0x77359400", "0x10", "0x0",
      ]);
    const reader = { callContract, getBlockNumber: vi.fn().mockResolvedValue(123) };
    await expect(readExceptionAuthorizationState(reader, {
      sealAddress,
      workflowType: "wage_claim",
      subjectNullifierHigh: "9",
      subjectNullifierLow: "10",
    })).resolves.toMatchObject({
      exists: true,
      status: 1,
      parentNullifierHigh: "11",
      factCommitmentHigh: "13",
    });
    await expect(readExceptionAuthorizationState(reader, {
      sealAddress,
      workflowType: "wage_remediation",
      subjectNullifierHigh: "17",
      subjectNullifierLow: "18",
    })).resolves.toMatchObject({
      exists: true,
      status: 1,
      parentNullifierHigh: "9",
      actionCommitmentHigh: "3",
    });
    expect(callContract).toHaveBeenNthCalledWith(1, expect.objectContaining({ entrypoint: "get_claim" }), 123);
    expect(callContract).toHaveBeenNthCalledWith(2, expect.objectContaining({ entrypoint: "get_remediation_attempt" }), 123);
  });

  it("submits an exact v6 claim proof only after observing an empty subject", async () => {
    const { deps, recordSubmission } = dependencies({});
    const submit = vi.fn().mockResolvedValue({ transactionHash: "0xabc" });
    await expect(processExceptionAuthorizationBatch({
      rpc: rpc(),
      submitter: { submit },
      deployment,
      workerId: "worker-1",
      now,
      dependencies: deps,
    })).resolves.toMatchObject({ leased: 1, results: [{ state: "submitted" }] });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({
      entrypoint: "authorize_claim",
    }));
    expect(BigInt(submit.mock.calls[0][0].contractAddress)).toBe(BigInt(sealAddress));
    expect(recordSubmission).toHaveBeenCalledWith(expect.anything(), "0xabc", now);
  });

  it("completes from matching canonical contract state without resubmitting", async () => {
    const state = {
      ...absentState(),
      exists: true,
      status: 1,
      parentNullifierHigh: "11",
      parentNullifierLow: "12",
      factCommitmentHigh: "13",
      factCommitmentLow: "14",
    };
    const { deps, complete } = dependencies({ state });
    const submit = vi.fn();
    await processExceptionAuthorizationBatch({
      rpc: rpc(), submitter: { submit }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(complete).toHaveBeenCalledOnce();
    expect(submit).not.toHaveBeenCalled();
  });

  it("fails closed when an occupied subject has different proof bindings", async () => {
    const state = {
      ...absentState(),
      exists: true,
      status: 1,
      parentNullifierHigh: "999",
      parentNullifierLow: "12",
      factCommitmentHigh: "13",
      factCommitmentLow: "14",
    };
    const { deps, defer } = dependencies({ state });
    await processExceptionAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      errorCode: "EXCEPTION_ONCHAIN_BINDING_MISMATCH",
      permanent: true,
    }), now);
  });

  it("clears a failed invoke so the proof can be retried idempotently", async () => {
    const job = leasedJob({ transactionHash: "0xabc" });
    const { deps, defer } = dependencies({
      job,
      observation: {
        state: "failed",
        confirmationDepth: 1,
        errorCode: "TX_REVERTED",
        errorMessage: "Verifier rejected the invoke.",
      },
    });
    await processExceptionAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "TX_REVERTED",
      clearTransaction: true,
    }), now);
  });

  it("does not label an expired unconsumed remediation as complete", async () => {
    const job = leasedJob({
      workflowType: "wage_remediation",
      publicInputs: {
        ...leasedJob().publicInputs,
        proofVersion: "7",
        parentNullifierHigh: "9",
        parentNullifierLow: "10",
        subjectNullifierHigh: "17",
        subjectNullifierLow: "18",
        validityExpiry: "10",
      },
    });
    const state: ExceptionAuthorizationState = {
      exists: true,
      status: 1,
      parentNullifierHigh: "9",
      parentNullifierLow: "10",
      factCommitmentHigh: "13",
      factCommitmentLow: "14",
      actionCommitmentHigh: "3",
      actionCommitmentLow: "4",
    };
    const { deps, defer, complete } = dependencies({ job, state });
    await processExceptionAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "REMEDIATION_AUTHORIZATION_EXPIRED",
      permanent: true,
    }), now);
    expect(complete).not.toHaveBeenCalled();
  });
});
