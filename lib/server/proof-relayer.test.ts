import { describe, expect, it, vi } from "vitest";
import type { LeasedProofVerificationJob } from "@/lib/persistence/proof-verification-repository";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import {
  PAYO_RUN_STATUS_CLAIMED,
  PAYO_RUN_STATUS_PROVEN,
  PAYO_RUN_STATUS_REMEDIATED,
  PAYO_RUN_STATUS_SEALED,
  processProofVerificationBatch,
  readProofSealState,
  type ProofRelayerDependencies,
  type ProofRelayerRpc,
} from "./proof-relayer";

const sealAddress = "0x12345";
const deployment = { chainId: "0x1", sealAddress };
const calldata = ["0x1"];

function leasedJob(overrides: Partial<LeasedProofVerificationJob> = {}): LeasedProofVerificationJob {
  return {
    id: "job-1",
    settlementId: "settlement-1",
    proofBundleId: "bundle-1",
    runId: "run-1",
    organizationId: "organization-1",
    attempts: 0,
    nextShard: 0,
    activeTransactionHash: null,
    shard0TransactionHash: null,
    shard1TransactionHash: null,
    runNullifierHigh: "1",
    runNullifierLow: "2",
    chainId: "0x1",
    sealAddress,
    validityExpiry: "2000000000",
    proofVersion: "1",
    shardCalldataHashes: [hashProofCalldata(calldata), hashProofCalldata(calldata)],
    shards: [calldata, calldata],
    leaseOwner: "worker-1",
    ...overrides,
  };
}

function rpc(): ProofRelayerRpc {
  return {
    callContract: vi.fn(),
    getTransactionReceipt: vi.fn(),
    getBlockNumber: vi.fn(),
    getBlockWithTxHashes: vi.fn(),
  };
}

function dependencies(input: {
  job?: LeasedProofVerificationJob;
  states: Array<{ status: number; shardsVerified: readonly [boolean, boolean] }>;
  observation?: Awaited<ReturnType<ProofRelayerDependencies["observe"]>>;
}) {
  const recordSubmission = vi.fn().mockResolvedValue({ state: "pending" });
  const defer = vi.fn().mockResolvedValue({ state: "pending" });
  const recordProgress = vi.fn().mockResolvedValue({ state: "pending" });
  const deps = {
    lease: vi.fn().mockResolvedValue([input.job ?? leasedJob()]),
    readState: vi.fn()
      .mockImplementation(() => Promise.resolve(input.states.shift())),
    observe: vi.fn().mockResolvedValue(input.observation ?? {
      state: "pending",
      confirmationDepth: 0,
    }),
    recordSubmission,
    defer,
    recordProgress,
  } as unknown as ProofRelayerDependencies;
  return { deps, recordSubmission, defer, recordProgress };
}

describe("PAYO proof relayer", () => {
  it("reads the on-chain run and both shard states", async () => {
    const callContract = vi.fn()
      .mockResolvedValueOnce({ result: ["0x1"] })
      .mockResolvedValueOnce(["0x1"])
      .mockResolvedValueOnce({ result: ["0x0"] });
    await expect(readProofSealState({ callContract, getBlockNumber: vi.fn().mockResolvedValue(100) }, {
      sealAddress,
      runNullifierHigh: "1",
      runNullifierLow: "2",
    })).resolves.toEqual({ status: PAYO_RUN_STATUS_SEALED, shardsVerified: [true, false] });
    expect(callContract).toHaveBeenCalledTimes(3);
  });

  it("submits only the next hash-bound shard from a sealed run", async () => {
    const { deps, recordSubmission } = dependencies({
      states: [{ status: PAYO_RUN_STATUS_SEALED, shardsVerified: [false, false] }],
    });
    const submit = vi.fn().mockResolvedValue({ transactionHash: "0xabc" });
    await expect(processProofVerificationBatch({
      rpc: rpc(),
      submitter: { submit },
      deployment,
      workerId: "worker-1",
      dependencies: deps,
      now: new Date("2026-08-24T00:00:00.000Z"),
    })).resolves.toMatchObject({ leased: 1, results: [{ state: "submitted" }] });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({
      entrypoint: "verify_sealed_shard",
      calldata: ["0x1", "0x2", "0x0", "0x1", "0x1"],
    }));
    expect(BigInt(submit.mock.calls[0][0].contractAddress)).toBe(BigInt(sealAddress));
    expect(recordSubmission).toHaveBeenCalledWith(expect.anything(), 0, "0xabc", expect.any(Date));
  });

  it("resumes an active transaction and advances only after contract state records the shard", async () => {
    const job = leasedJob({ activeTransactionHash: "0xabc", shard0TransactionHash: "0xabc" });
    const { deps, recordProgress } = dependencies({
      job,
      states: [
        { status: PAYO_RUN_STATUS_SEALED, shardsVerified: [false, false] },
        { status: PAYO_RUN_STATUS_SEALED, shardsVerified: [true, false] },
      ],
      observation: { state: "finalized", confirmationDepth: 3 },
    });
    await processProofVerificationBatch({
      rpc: rpc(),
      submitter: { submit: vi.fn() },
      deployment,
      workerId: "worker-1",
      dependencies: deps,
      now: new Date("2026-08-24T00:00:00.000Z"),
    });
    expect(recordProgress).toHaveBeenCalledWith(job, { nextShard: 1 }, expect.any(Date));
  });

  it("marks a bundle complete only from the PAYO PROVEN state", async () => {
    const job = leasedJob({
      nextShard: 1,
      activeTransactionHash: "0xdef",
      shard0TransactionHash: "0xabc",
      shard1TransactionHash: "0xdef",
    });
    const { deps, recordProgress, recordSubmission } = dependencies({
      job,
      states: [{ status: PAYO_RUN_STATUS_PROVEN, shardsVerified: [true, true] }],
    });
    await processProofVerificationBatch({
      rpc: rpc(),
      submitter: { submit: vi.fn() },
      deployment,
      workerId: "worker-1",
      dependencies: deps,
      now: new Date("2026-08-24T00:00:00.000Z"),
    });
    expect(recordProgress).toHaveBeenCalledWith(job, {
      complete: true,
      verificationTransactionHash: "0xdef",
    }, expect.any(Date));
    expect(recordSubmission).not.toHaveBeenCalled();
  });

  it.each([
    ["3", PAYO_RUN_STATUS_CLAIMED],
    ["4", PAYO_RUN_STATUS_REMEDIATED],
  ])("marks proof version %s complete only at its mode-specific terminal state", async (proofVersion, status) => {
    const job = leasedJob({
      proofVersion,
      activeTransactionHash: "0xdef",
      shard0TransactionHash: "0xabc",
      shard1TransactionHash: "0xdef",
    });
    const { deps, recordProgress } = dependencies({
      job,
      states: [{ status, shardsVerified: [true, true] }],
    });
    await processProofVerificationBatch({
      rpc: rpc(),
      submitter: { submit: vi.fn() },
      deployment,
      workerId: "worker-1",
      dependencies: deps,
      now: new Date("2026-08-24T00:00:00.000Z"),
    });
    expect(recordProgress).toHaveBeenCalledWith(job, {
      complete: true,
      verificationTransactionHash: "0xdef",
    }, expect.any(Date));
  });

  it("fails closed on deployment mismatch instead of submitting", async () => {
    const { deps, defer } = dependencies({
      job: leasedJob({ chainId: "0x2" }),
      states: [],
    });
    const submit = vi.fn();
    await processProofVerificationBatch({
      rpc: rpc(),
      submitter: { submit },
      deployment,
      workerId: "worker-1",
      dependencies: deps,
      now: new Date("2026-08-24T00:00:00.000Z"),
    });
    expect(defer).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      errorCode: "PROOF_DEPLOYMENT_MISMATCH",
      permanent: true,
    }), expect.any(Date));
    expect(submit).not.toHaveBeenCalled();
  });
});
