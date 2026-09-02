import { describe, expect, it, vi } from "vitest";
import type { LeasedFxPublicationJob } from "@/lib/persistence/fx-publication-repository";
import {
  processFxPublicationBatch,
  type FxPublicationWorkerDependencies,
  type FxPublicationWorkerRpc,
} from "./fx-publication-worker";

const now = new Date("2026-08-27T12:00:00.000Z");
const nowSeconds = Math.floor(now.getTime() / 1_000);
const deployment = { chainId: "0x1", sealAddress: "0x123" };
const policyRegistryAddress = "0x456";

function leasedJob(overrides: Partial<LeasedFxPublicationJob> = {}): LeasedFxPublicationJob {
  return {
    id: "job-1",
    organizationId: "organization-1",
    principalId: "principal-1",
    catalogRoot: `0x${"12".repeat(32)}`,
    proofVersion: 2,
    proofDigest: `0x${"34".repeat(32)}`,
    shards: [["0x1"], ["0x2"]],
    observedAt: nowSeconds - 60,
    maximumAgeSeconds: 3_600,
    historicalRenewal: false,
    renewalRunId: null,
    transactionHash: null,
    attempts: 0,
    leaseOwner: "worker-1",
    ...overrides,
  };
}

function rpc(): FxPublicationWorkerRpc {
  return {
    callContract: vi.fn(),
    getBlockNumber: vi.fn(),
    getBlockTimestamp: vi.fn(),
    getTransactionReceipt: vi.fn(),
    getBlockWithTxHashes: vi.fn(),
  };
}

function dependencies(input: {
  job?: LeasedFxPublicationJob;
  active?: boolean;
  verificationError?: Error;
  revocationError?: Error;
  observation?: { state: "pending" | "confirmed" | "finalized" | "reorged" | "failed"; confirmationDepth: number; errorMessage?: string };
}) {
  const recordSubmission = vi.fn().mockResolvedValue({ state: "pending" });
  const recordComplete = vi.fn().mockResolvedValue({ state: "complete" });
  const defer = vi.fn().mockImplementation((_job, options) => Promise.resolve({
    state: options.permanent ? "dead" : "pending",
  }));
  const verify = input.verificationError
    ? vi.fn().mockRejectedValue(input.verificationError)
    : vi.fn().mockResolvedValue({
        blockNumber: 100,
        blockTimestamp: nowSeconds,
        verifierAddress: "0x789",
      });
  const assertNotRevoked = input.revocationError
    ? vi.fn().mockRejectedValue(input.revocationError)
    : vi.fn().mockResolvedValue(undefined);
  const deps = {
    lease: vi.fn().mockResolvedValue([input.job ?? leasedJob()]),
    isActive: vi.fn().mockResolvedValue(input.active ?? false),
    assertNotRevoked,
    verify,
    observe: vi.fn().mockResolvedValue(input.observation ?? { state: "pending", confirmationDepth: 0 }),
    recordSubmission,
    recordComplete,
    defer,
  } as unknown as FxPublicationWorkerDependencies;
  return { deps, verify, assertNotRevoked, recordSubmission, recordComplete, defer };
}

describe("durable FX publication worker", () => {
  it("verifies and submits an unpublished root without holding a browser request", async () => {
    const { deps, verify, recordSubmission } = dependencies({});
    const submit = vi.fn().mockResolvedValue({ transactionHash: "0xabc" });
    const additionalDeployments = [{ chainId: "0x1", sealAddress: "0x789" }];
    await expect(processFxPublicationBatch({
      rpc: rpc(),
      submitter: { submit },
      deployment,
      additionalDeployments,
      policyRegistryAddress,
      workerId: "worker-1",
      now,
      dependencies: deps,
    })).resolves.toEqual({
      leased: 1,
      results: [{ jobId: "job-1", catalogRoot: leasedJob().catalogRoot, state: "pending" }],
    });
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({
      job: expect.objectContaining({ id: "job-1" }),
      call: expect.objectContaining({ entrypoint: "publish_fx_root" }),
    }));
    expect(recordSubmission).toHaveBeenCalledWith(expect.anything(), "0xabc", now);
    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ additionalDeployments }));
  });

  it("completes idempotently when the root is already active", async () => {
    const job = leasedJob({ transactionHash: "0xabc" });
    const { deps, verify, recordComplete } = dependencies({ job, active: true });
    const submit = vi.fn();
    await processFxPublicationBatch({
      rpc: rpc(), submitter: { submit }, deployment, policyRegistryAddress,
      workerId: "worker-1", now, dependencies: deps,
    });
    expect(recordComplete).toHaveBeenCalledWith(job, "0xabc", now);
    expect(verify).not.toHaveBeenCalled();
    expect(submit).not.toHaveBeenCalled();
  });

  it("tracks an existing transaction instead of submitting a duplicate", async () => {
    const job = leasedJob({ transactionHash: "0xabc" });
    const { deps, verify, defer } = dependencies({ job });
    const submit = vi.fn();
    await processFxPublicationBatch({
      rpc: rpc(), submitter: { submit }, deployment, policyRegistryAddress,
      workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "FX_PUBLICATION_PENDING",
    }), now);
    expect(verify).not.toHaveBeenCalled();
    expect(submit).not.toHaveBeenCalled();
  });

  it("clears a reorged transaction so a valid publication can be retried", async () => {
    const job = leasedJob({ transactionHash: "0xabc" });
    const { deps, defer } = dependencies({
      job,
      observation: { state: "reorged", confirmationDepth: 0, errorMessage: "reorg" },
    });
    await processFxPublicationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, policyRegistryAddress,
      workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "FX_PUBLICATION_REORGED",
      clearTransactionHash: true,
    }), now);
  });

  it("fails an expired publication window before verifying or submitting", async () => {
    const job = leasedJob({ observedAt: nowSeconds - 4_000, maximumAgeSeconds: 3_600 });
    const { deps, verify, defer } = dependencies({ job });
    const submit = vi.fn();
    await processFxPublicationBatch({
      rpc: rpc(), submitter: { submit }, deployment, policyRegistryAddress,
      workerId: "worker-1", now, dependencies: deps,
    });
    expect(defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "FX_PUBLICATION_WINDOW_EXPIRED",
      permanent: true,
    }), now);
    expect(verify).not.toHaveBeenCalled();
    expect(submit).not.toHaveBeenCalled();
  });

  it("renews only after checking revocation and permits the historical proof window", async () => {
    const job = leasedJob({ historicalRenewal: true, renewalRunId: "run-1" });
    const state = dependencies({ job });
    const renewalRpc = rpc();
    vi.mocked(renewalRpc.getBlockNumber).mockResolvedValue(123);
    await processFxPublicationBatch({
      rpc: renewalRpc,
      submitter: { submit: vi.fn().mockResolvedValue({ transactionHash: "0xabc" }) },
      deployment,
      policyRegistryAddress,
      workerId: "worker-1",
      now,
      dependencies: state.deps,
    });
    expect(state.assertNotRevoked).toHaveBeenCalledWith(expect.objectContaining({
      catalogRoot: job.catalogRoot,
      toBlock: 123,
    }));
    expect(state.verify).toHaveBeenCalledWith(expect.objectContaining({
      requireActiveWindow: false,
    }));
  });

  it("permanently blocks renewal of an administrator-revoked FX root", async () => {
    const job = leasedJob({ historicalRenewal: true, renewalRunId: "run-1" });
    const state = dependencies({
      job,
      revocationError: new Error("The historical FX root was revoked and cannot be renewed."),
    });
    const renewalRpc = rpc();
    vi.mocked(renewalRpc.getBlockNumber).mockResolvedValue(123);
    await processFxPublicationBatch({
      rpc: renewalRpc,
      submitter: { submit: vi.fn() },
      deployment,
      policyRegistryAddress,
      workerId: "worker-1",
      now,
      dependencies: state.deps,
    });
    expect(state.defer).toHaveBeenCalledWith(job, expect.objectContaining({
      errorCode: "FX_RENEWAL_REVOKED",
      permanent: true,
    }), now);
    expect(state.verify).not.toHaveBeenCalled();
  });

  it("fails closed on deterministic proof mismatch but retries RPC failures", async () => {
    const deterministic = dependencies({
      verificationError: new Error("The payroll proof is not bound to this PAYO FX catalog and deployment."),
    });
    await processFxPublicationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, policyRegistryAddress,
      workerId: "worker-1", now, dependencies: deterministic.deps,
    });
    expect(deterministic.defer).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      errorCode: "FX_PUBLICATION_PROOF_INVALID",
      permanent: true,
    }), now);

    const transient = dependencies({ verificationError: new Error("fetch failed") });
    await processFxPublicationBatch({
      rpc: rpc(), submitter: { submit: vi.fn() }, deployment, policyRegistryAddress,
      workerId: "worker-1", now, dependencies: transient.deps,
    });
    expect(transient.defer).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      errorCode: "FX_PROOF_RPC_FAILED",
      permanent: false,
    }), now);
  });
});
