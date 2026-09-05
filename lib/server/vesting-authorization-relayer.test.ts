import { describe, expect, it, vi } from "vitest";
import {
  hiddenPayrollBookTotals,
  payrollBookTotalsCommitment,
  universalPayrollBookEntryCommitment,
} from "@/lib/domain/universal-payroll-book";
import type { LeasedVestingAuthorizationJob } from "@/lib/persistence/vesting-authorization-repository";
import {
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import {
  processVestingAuthorizationBatch,
  readVestingAuthorizationChainState,
  type VestingAuthorizationRelayerDependencies,
  type VestingAuthorizationRpc,
} from "./vesting-authorization-relayer";
import {
  serializeVestingPayrollProofState,
  serializeVestingTransitionProofState,
} from "@/lib/starknet/payo-vesting-book";

const sealAddress = "0x12345";
const deployment = { chainId: "0x1", sealAddress };
const now = new Date("2026-08-28T00:00:00.000Z");
const proof = ["0x1"];
const zero = `0x${"00".repeat(32)}` as const;

function joined(high: string, low: string): `0x${string}` {
  return `0x${((BigInt(high) << 128n) | BigInt(low)).toString(16).padStart(64, "0")}`;
}

function leasedJob(overrides: Partial<LeasedVestingAuthorizationJob> = {}): LeasedVestingAuthorizationJob {
  const common = {
    chainId: "0x1",
    sealAddress,
    agreementRootHigh: "3",
    agreementRootLow: "4",
    manifestRootHigh: "5",
    manifestRootLow: "6",
    runNullifierHigh: "11",
    runNullifierLow: "12",
    validityStart: "1",
    validityExpiry: "2000000000",
  };
  const subjectNullifier = joined("11", "12");
  const publicTotals = hiddenPayrollBookTotals();
  const totalsCommitment = payrollBookTotalsCommitment({
    subjectNullifier,
    contributorCount: 2,
    totals: publicTotals,
    salt: `0x${"a1".repeat(32)}`,
  });
  const totalsValue = BigInt(totalsCommitment);
  const totalsHigh = (totalsValue >> 128n).toString();
  const totalsLow = (totalsValue & ((1n << 128n) - 1n)).toString();
  const bookEntry = {
    entryVersion: "payo-payroll-book-entry-v2" as const,
    entryKind: "ordinary" as const,
    chainId: "0x1",
    sealAddress,
    sourceSealAddress: sealAddress,
    ownerAddress: "0x456",
    periodStart: "1",
    periodEnd: "2000000001",
    agreementRoot: joined("3", "4"),
    manifestRoot: joined("5", "6"),
    policyRoot: joined("7", "8"),
    fxRoot: joined("9", "10"),
    runNullifier: subjectNullifier,
    subjectNullifier,
    parentFactCommitment: zero,
    factCommitment: zero,
    sourceProofVersion: 2,
    attestationRoot: zero,
    contributorCount: 2,
    totalsDisclosure: "hidden" as const,
    totalsCommitment,
    totals: publicTotals,
    vestingScheduleId: zero,
    vestingStateCommitment: zero,
  };
  const entryCommitment = universalPayrollBookEntryCommitment(bookEntry);
  const entry = BigInt(entryCommitment);
  const entryHigh = (entry >> 128n).toString();
  const entryLow = (entry & ((1n << 128n) - 1n)).toString();
  const payrollShards = [0, 1].map((shardIndex) => ({
    shardIndex: shardIndex as 0 | 1,
    proof: new Uint8Array(),
    proofCalldata: proof,
    calldataHash: hashProofCalldata(proof),
    publicInputs: {
      ...common,
      proofVersion: "2",
      schemaVersion: "1",
      policyRootHigh: "7",
      policyRootLow: "8",
      fxRootHigh: "9",
      fxRootLow: "10",
      shardIndex: String(shardIndex),
    },
  })) as LeasedVestingAuthorizationJob["payrollShards"];
  const transitionShards = [0, 1].map((shardIndex) => ({
    shardIndex: shardIndex as 0 | 1,
    proof: new Uint8Array(),
    proofCalldata: ["0x2"],
    calldataHash: hashProofCalldata(["0x2"]),
    publicInputs: {
      ...common,
      proofVersion: "3" as const,
      schemaVersion: "1" as const,
      entryKind: "0" as const,
      policyRootHigh: "7",
      policyRootLow: "8",
      fxRootHigh: "9",
      fxRootLow: "10",
      subjectNullifierHigh: "11",
      subjectNullifierLow: "12",
      parentFactHigh: "0",
      parentFactLow: "0",
      factHigh: "0",
      factLow: "0",
      ownerAddress: "0x456",
      sourceSealAddress: sealAddress,
      sourceProofVersion: "2",
      attestationRootHigh: "0",
      attestationRootLow: "0",
      shard0ContributorCount: "1",
      shard1ContributorCount: "1",
      totalsDisclosed: "0" as const,
      totalsCommitmentHigh: totalsHigh,
      totalsCommitmentLow: totalsLow,
      shard0StrkGross: "0",
      shard0StrkDeductions: "0",
      shard0StrkNet: "0",
      shard0UsdcGross: "0",
      shard0UsdcDeductions: "0",
      shard0UsdcNet: "0",
      shard1StrkGross: "0",
      shard1StrkDeductions: "0",
      shard1StrkNet: "0",
      shard1UsdcGross: "0",
      shard1UsdcDeductions: "0",
      shard1UsdcNet: "0",
      scheduleIdHigh: "0",
      scheduleIdLow: "0",
      previousStateHigh: "0",
      previousStateLow: "0",
      nextStateHigh: "0",
      nextStateLow: "0",
      releaseNullifierHigh: "0",
      releaseNullifierLow: "0",
      bookEntryHigh: entryHigh,
      bookEntryLow: entryLow,
      periodStart: "1",
      periodEnd: "2000000001",
      shardIndex: String(shardIndex) as "0" | "1",
    },
  })) as LeasedVestingAuthorizationJob["vestingBook"]["shards"];
  return {
    id: "job-1",
    organizationId: "organization-1",
    runId: "run-1",
    payrollProofBundleId: "payroll-bundle",
    attempts: 0,
    activeStep: "begin",
    transactionHash: null,
    beginTransactionHash: null,
    payrollShard0TransactionHash: null,
    payrollShard1TransactionHash: null,
    transitionShard0TransactionHash: null,
    transitionShard1TransactionHash: null,
    payrollShards,
    vestingBook: {
      proofVersion: 3,
      entryKind: "ordinary",
      circuitSha256: VESTING_TRANSITION_CIRCUIT_SHA256,
      verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
      provingTimeMs: 0,
      scheduleId: zero,
      previousStateCommitment: zero,
      nextStateCommitment: zero,
      releaseNullifier: zero,
      bookEntry,
      bookEntryCommitment: entryCommitment,
      shards: transitionShards,
    },
    leaseOwner: "worker-1",
    ...overrides,
  };
}

function payrollState(job: LeasedVestingAuthorizationJob): string[] {
  return serializeVestingPayrollProofState(job.payrollShards[0].publicInputs);
}

function transitionState(job: LeasedVestingAuthorizationJob): string[] {
  return serializeVestingTransitionProofState(job.vestingBook);
}

function chainState(job = leasedJob(), input: { exists?: boolean; status?: number; mask?: number } = {}) {
  return {
    exists: input.exists ?? false,
    status: input.status ?? 0,
    payrollState: payrollState(job),
    transitionState: transitionState(job),
    proofHashes: [
      job.payrollShards[0].calldataHash,
      job.payrollShards[1].calldataHash,
      job.vestingBook.shards[0].calldataHash,
      job.vestingBook.shards[1].calldataHash,
    ] as [string, string, string, string],
    verifiedMask: input.mask ?? 0,
  };
}

function rpc(): VestingAuthorizationRpc {
  return {
    callContract: vi.fn(),
    getTransactionReceipt: vi.fn(),
    getBlockNumber: vi.fn(),
    getBlockWithTxHashes: vi.fn(),
  };
}

function dependencies(job: LeasedVestingAuthorizationJob, state: ReturnType<typeof chainState>) {
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
  } as unknown as VestingAuthorizationRelayerDependencies;
  return { deps, recordSubmission, advance, defer, complete };
}

describe("PAYO state/book authorization relayer", () => {
  it("reads one canonical pending state at a pinned block", async () => {
    const job = leasedJob();
    const response = [
      "1", "1", ...payrollState(job), ...transitionState(job),
      ...chainState(job).proofHashes, "7", "100", "101",
    ];
    const callContract = vi.fn().mockResolvedValue({ result: response });
    await expect(readVestingAuthorizationChainState({
      callContract,
      getBlockNumber: vi.fn().mockResolvedValue(321),
    }, {
      sealAddress,
      runNullifierHigh: "11",
      runNullifierLow: "12",
    })).resolves.toMatchObject({ exists: true, status: 1, verifiedMask: 7 });
    expect(callContract).toHaveBeenCalledWith(expect.objectContaining({
      entrypoint: "get_pending_authorization",
    }), 321);
  });

  it("submits the compact begin call before proof calldata", async () => {
    const job = leasedJob();
    const { deps, recordSubmission } = dependencies(job, chainState(job));
    const submit = vi.fn().mockResolvedValue({ transactionHash: "0xabc" });
    await processVestingAuthorizationBatch({
      rpc: rpc(), submitter: { submit }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({
      entrypoint: "begin_vesting_authorization",
    }));
    expect(recordSubmission).toHaveBeenCalledWith(job, "begin", "0xabc", now);
  });

  it.each([
    ["begin", 0, "payroll0"],
    ["payroll0", 1, "payroll1"],
    ["payroll1", 3, "transition0"],
    ["transition0", 7, "transition1"],
  ] as const)("advances %s from canonical mask %i to %s without replay", async (activeStep, mask, nextStep) => {
    const job = leasedJob({ activeStep });
    const { deps, advance, recordSubmission } = dependencies(
      job,
      chainState(job, { exists: true, status: 1, mask }),
    );
    await processVestingAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(advance).toHaveBeenCalledWith(job, nextStep, now);
    expect(recordSubmission).not.toHaveBeenCalled();
  });

  it("submits the exact next proof kind and calldata", async () => {
    const job = leasedJob({ activeStep: "transition1" });
    const { deps, recordSubmission } = dependencies(
      job,
      chainState(job, { exists: true, status: 1, mask: 7 }),
    );
    const submit = vi.fn().mockResolvedValue({ transactionHash: "0xdef" });
    await processVestingAuthorizationBatch({
      rpc: rpc(), submitter: { submit }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({
      entrypoint: "verify_vesting_authorization_proof",
      calldata: ["0xb", "0xc", "0x3", "0x1", "0x2"],
    }));
    expect(recordSubmission).toHaveBeenCalledWith(job, "transition1", "0xdef", now);
  });

  it("completes only after all four linked proofs are authorized", async () => {
    const job = leasedJob({ activeStep: "transition1" });
    const { deps, complete } = dependencies(
      job,
      chainState(job, { exists: true, status: 2, mask: 15 }),
    );
    await processVestingAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(complete).toHaveBeenCalledWith(job, now);
  });

  it("fails closed when chain state differs from the durable proof", async () => {
    const job = leasedJob();
    const state = chainState(job, { exists: true, status: 1 });
    state.transitionState[10] = "99";
    const { deps, defer } = dependencies(job, state);
    await processVestingAuthorizationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "VESTING_PENDING_BINDING_MISMATCH",
      permanent: true,
    }), now);
  });

  it("observes an existing transaction instead of submitting a replay", async () => {
    const job = leasedJob({ transactionHash: "0xabc" });
    const { deps, defer } = dependencies(job, chainState(job));
    const submit = vi.fn();
    await processVestingAuthorizationBatch({
      rpc: rpc(), submitter: { submit }, deployment, workerId: "worker-1", now, dependencies: deps,
    });
    expect(submit).not.toHaveBeenCalled();
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "VESTING_AUTHORIZATION_TRANSACTION_PENDING",
    }), now);
  });
});
