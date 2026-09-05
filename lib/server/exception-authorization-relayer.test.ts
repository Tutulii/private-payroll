import { describe, expect, it, vi } from "vitest";
import { mockExceptionBookProof } from "@/lib/proof/vesting-transition-test-support";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { serializeVestingTransitionProofState } from "@/lib/starknet/payo-vesting-book";
import type { LeasedExceptionAuthorizationJob } from "@/lib/persistence/exception-authorization-repository";
import {
  processExceptionAuthorizationBatch,
  readExceptionAuthorizationState,
  readExceptionBookAuthorizationState,
  type ExceptionAuthorizationRelayerDependencies,
  type ExceptionAuthorizationRpc,
  type ExceptionAuthorizationState,
  type ExceptionBookAuthorizationState,
} from "./exception-authorization-relayer";

const sealAddress = "0x12345";
const bookSealAddress = "0x456";
const deployment = { chainId: "0x1", sealAddress };
const bookDeployment = { chainId: "0x1", sealAddress: bookSealAddress };
const now = new Date("2026-08-28T00:00:00.000Z");

function sourceInputs(workflowType: "wage_claim" | "wage_remediation") {
  return {
    chainId: "0x1",
    sealAddress,
    proofVersion: workflowType === "wage_claim" ? "6" as const : "7" as const,
    schemaVersion: "2",
    agreementRootHigh: "1",
    agreementRootLow: "2",
    manifestRootHigh: "3",
    manifestRootLow: "4",
    policyRootHigh: "5",
    policyRootLow: "6",
    fxRootHigh: "0",
    fxRootLow: "0",
    subjectNullifierHigh: workflowType === "wage_claim" ? "9" : "17",
    subjectNullifierLow: workflowType === "wage_claim" ? "10" : "18",
    parentNullifierHigh: workflowType === "wage_claim" ? "11" : "9",
    parentNullifierLow: workflowType === "wage_claim" ? "12" : "10",
    factCommitmentHigh: "13",
    factCommitmentLow: "14",
    parentFactCommitmentHigh: "15",
    parentFactCommitmentLow: "16",
    validityStart: "1",
    validityExpiry: "2000000000",
    shardIndex: "0",
  };
}

function leasedJob(input: {
  workflowType?: "wage_claim" | "wage_remediation";
  activeStep?: LeasedExceptionAuthorizationJob["activeStep"];
  transactionHash?: string | null;
  overrides?: Partial<LeasedExceptionAuthorizationJob>;
} = {}): LeasedExceptionAuthorizationJob {
  const workflowType = input.workflowType ?? "wage_claim";
  const publicInputs = sourceInputs(workflowType);
  const sourceProofCalldata = ["0x1"];
  const vestingBook = mockExceptionBookProof({
    source: publicInputs,
    entryKind: workflowType === "wage_claim" ? "claim" : "remediation",
    bookSealAddress,
    sourceSealAddress: sealAddress,
    ownerAddress: "0xabc",
    ...(workflowType === "wage_remediation"
      ? { runNullifier: `0x${"00".repeat(30)}0123`, payment: { token: "STRK" as const, amountAtomic: "1" } }
      : {}),
  });
  return {
    id: "job-1",
    organizationId: "organization-1",
    runId: "run-1",
    proofBundleId: "bundle-1",
    workflowType,
    subjectRecordId: workflowType === "wage_claim" ? "claim-1" : "remediation-1",
    attempts: 0,
    activeStep: input.activeStep ?? "source",
    transactionHash: input.transactionHash ?? null,
    sourceTransactionHash: null,
    bookBeginTransactionHash: null,
    bookTransitionShard0TransactionHash: null,
    bookTransitionShard1TransactionHash: null,
    bookFinalizeTransactionHash: null,
    proofCalldata: sourceProofCalldata,
    publicInputs,
    sourceProof: {
      proof: new Uint8Array(),
      proofCalldata: sourceProofCalldata,
      calldataHash: hashProofCalldata(sourceProofCalldata),
      publicInputs,
    },
    vestingBook,
    leaseOwner: "worker-1",
    ...input.overrides,
  };
}

function absentSourceState(): ExceptionAuthorizationState {
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

function matchingSourceState(job: LeasedExceptionAuthorizationJob): ExceptionAuthorizationState {
  return {
    exists: true,
    status: 1,
    parentNullifierHigh: job.publicInputs.parentNullifierHigh,
    parentNullifierLow: job.publicInputs.parentNullifierLow,
    factCommitmentHigh: job.publicInputs.factCommitmentHigh,
    factCommitmentLow: job.publicInputs.factCommitmentLow,
    actionCommitmentHigh: job.workflowType === "wage_remediation"
      ? job.publicInputs.manifestRootHigh : null,
    actionCommitmentLow: job.workflowType === "wage_remediation"
      ? job.publicInputs.manifestRootLow : null,
  };
}

function absentBookState(): ExceptionBookAuthorizationState {
  return {
    exists: false,
    status: 0,
    transitionState: [],
    proofHashes: ["0", "0", "0", "0"],
    verifiedMask: 0,
  };
}

function matchingBookState(
  job: LeasedExceptionAuthorizationJob,
  input: { status: number; verifiedMask: number },
): ExceptionBookAuthorizationState {
  return {
    exists: true,
    status: input.status,
    transitionState: serializeVestingTransitionProofState(job.vestingBook),
    proofHashes: [
      "0",
      "0",
      job.vestingBook.shards[0].calldataHash,
      job.vestingBook.shards[1].calldataHash,
    ],
    verifiedMask: input.verifiedMask,
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
  job: LeasedExceptionAuthorizationJob;
  sourceState?: ExceptionAuthorizationState;
  bookState?: ExceptionBookAuthorizationState;
  observation?: Awaited<ReturnType<ExceptionAuthorizationRelayerDependencies["observe"]>>;
}) {
  const recordSubmission = vi.fn().mockResolvedValue({ state: "pending" });
  const advance = vi.fn().mockResolvedValue({ state: "pending" });
  const defer = vi.fn().mockImplementation((_job, options) => Promise.resolve({
    state: options.permanent ? "dead" : "pending",
  }));
  const complete = vi.fn().mockResolvedValue({ state: "complete" });
  const deps = {
    lease: vi.fn().mockResolvedValue([input.job]),
    readSourceState: vi.fn().mockResolvedValue(input.sourceState ?? absentSourceState()),
    readBookState: vi.fn().mockResolvedValue(input.bookState ?? absentBookState()),
    observe: vi.fn().mockResolvedValue(input.observation ?? {
      state: "pending",
      confirmationDepth: 0,
    }),
    recordSubmission,
    advance,
    defer,
    complete,
  } as unknown as ExceptionAuthorizationRelayerDependencies;
  return { deps, recordSubmission, advance, defer, complete };
}

async function process(input: {
  job: LeasedExceptionAuthorizationJob;
  sourceState?: ExceptionAuthorizationState;
  bookState?: ExceptionBookAuthorizationState;
  observation?: Awaited<ReturnType<ExceptionAuthorizationRelayerDependencies["observe"]>>;
}) {
  const mocks = dependencies(input);
  const submit = vi.fn().mockResolvedValue({ transactionHash: "0xabc" });
  const result = await processExceptionAuthorizationBatch({
    rpc: rpc(),
    submitter: { submit },
    deployment,
    bookDeployment,
    workerId: "worker-1",
    now,
    dependencies: mocks.deps,
  });
  return { ...mocks, submit, result };
}

describe("PAYO linked exception authorization relayer", () => {
  it("reads source and payroll-book states at pinned blocks", async () => {
    const sourceCall = vi.fn().mockResolvedValue({
      result: ["0x1", "0x1", "0xb", "0xc", "0x1", "0x2", "0x5", "0x6", "0xd", "0xe", "0x10", "0x0", "0x0", "0x0"],
    });
    const reader = { callContract: sourceCall, getBlockNumber: vi.fn().mockResolvedValue(123) };
    await expect(readExceptionAuthorizationState(reader, {
      sealAddress,
      workflowType: "wage_claim",
      subjectNullifierHigh: "9",
      subjectNullifierLow: "10",
    })).resolves.toMatchObject({ exists: true, status: 1, parentNullifierHigh: "11" });
    expect(sourceCall).toHaveBeenCalledWith(expect.objectContaining({ entrypoint: "get_claim" }), 123);

    const bookFields = Array.from({ length: 78 }, () => "0x0");
    bookFields[0] = "0x1";
    bookFields[1] = "0x1";
    bookFields[75] = "0x4";
    const bookCall = vi.fn().mockResolvedValue({ result: bookFields });
    await expect(readExceptionBookAuthorizationState({
      callContract: bookCall,
      getBlockNumber: vi.fn().mockResolvedValue(124),
    }, {
      sealAddress: bookSealAddress,
      subjectNullifierHigh: "9",
      subjectNullifierLow: "10",
    })).resolves.toMatchObject({ exists: true, status: 1, verifiedMask: 4 });
    expect(bookCall).toHaveBeenCalledWith(expect.objectContaining({ entrypoint: "get_pending_authorization" }), 124);
  });

  it("submits the source proof only while the source subject is empty", async () => {
    const job = leasedJob();
    const { result, submit, recordSubmission } = await process({ job });
    expect(result).toMatchObject({ leased: 1, results: [{ state: "submitted" }] });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({ entrypoint: "authorize_claim" }));
    expect(BigInt(submit.mock.calls[0]![0].contractAddress)).toBe(BigInt(sealAddress));
    expect(recordSubmission).toHaveBeenCalledWith(job, "source", "0xabc", now);
  });

  it("advances durably from the accepted source to payroll-book begin", async () => {
    const job = leasedJob({ activeStep: "source", transactionHash: "0x111" });
    const { advance, submit } = await process({
      job,
      sourceState: matchingSourceState(job),
      bookState: absentBookState(),
    });
    expect(advance).toHaveBeenCalledWith(job, "book_begin", now);
    expect(submit).not.toHaveBeenCalled();
  });

  it.each([
    ["book_begin", 0, "begin_exception_book_authorization", null],
    ["book_transition0", 0, "verify_vesting_authorization_proof", "0x2"],
    ["book_transition1", 4, "verify_vesting_authorization_proof", "0x3"],
  ] as const)("submits exact %s call from canonical source/book state", async (
    activeStep, verifiedMask, entrypoint, proofKind,
  ) => {
    const job = leasedJob({ activeStep });
    const bookState = activeStep === "book_begin"
      ? absentBookState()
      : matchingBookState(job, { status: 1, verifiedMask });
    const { submit, recordSubmission } = await process({
      job,
      sourceState: matchingSourceState(job),
      bookState,
    });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({ entrypoint }));
    expect(BigInt(submit.mock.calls[0]![0].contractAddress)).toBe(BigInt(bookSealAddress));
    if (proofKind) expect(submit.mock.calls[0]![0].calldata[2]).toBe(proofKind);
    expect(recordSubmission).toHaveBeenCalledWith(job, activeStep, "0xabc", now);
  });

  it("finalizes a claim only after both v3 shards are canonical", async () => {
    const job = leasedJob({ activeStep: "book_finalize" });
    const { submit, recordSubmission } = await process({
      job,
      sourceState: matchingSourceState(job),
      bookState: matchingBookState(job, { status: 2, verifiedMask: 12 }),
    });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({
      entrypoint: "finalize_claim_book_entry",
    }));
    expect(BigInt(submit.mock.calls[0]![0].contractAddress)).toBe(BigInt(bookSealAddress));
    expect(recordSubmission).toHaveBeenCalledWith(job, "book_finalize", "0xabc", now);
  });

  it("completes claim and remediation only from their canonical terminal book states", async () => {
    const claim = leasedJob({ activeStep: "book_finalize", transactionHash: "0x555" });
    const claimResult = await process({
      job: claim,
      sourceState: matchingSourceState(claim),
      bookState: matchingBookState(claim, { status: 3, verifiedMask: 12 }),
    });
    expect(claimResult.complete).toHaveBeenCalledWith(claim, now);

    const remediation = leasedJob({
      workflowType: "wage_remediation",
      activeStep: "book_transition1",
      transactionHash: "0x777",
    });
    const remediationResult = await process({
      job: remediation,
      sourceState: matchingSourceState(remediation),
      bookState: matchingBookState(remediation, { status: 2, verifiedMask: 12 }),
    });
    expect(remediationResult.complete).toHaveBeenCalledWith(remediation, now);
  });

  it("fails closed for changed book bindings and clears a failed invoke for retry", async () => {
    const mismatchJob = leasedJob({ activeStep: "book_transition0" });
    const changedBook = matchingBookState(mismatchJob, { status: 1, verifiedMask: 0 });
    changedBook.transitionState = [...changedBook.transitionState];
    changedBook.transitionState[0] = "999";
    const mismatch = await process({
      job: mismatchJob,
      sourceState: matchingSourceState(mismatchJob),
      bookState: changedBook,
    });
    expect(mismatch.defer).toHaveBeenCalledWith(mismatchJob, expect.objectContaining({
      errorCode: "EXCEPTION_BOOK_ONCHAIN_BINDING_MISMATCH",
      permanent: true,
    }), now);

    const failedJob = leasedJob({ activeStep: "source", transactionHash: "0xabc" });
    const failed = await process({
      job: failedJob,
      observation: {
        state: "failed",
        confirmationDepth: 1,
        errorCode: "TX_REVERTED",
        errorMessage: "Verifier rejected the invoke.",
      },
    });
    expect(failed.defer).toHaveBeenCalledWith(failedJob, expect.objectContaining({
      errorCode: "TX_REVERTED",
      clearTransaction: true,
    }), now);
  });
});
