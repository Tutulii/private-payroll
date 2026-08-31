import { describe, expect, it, vi } from "vitest";
import type { AgentExecutionRequest } from "@/lib/domain/capability";
import type { LeasedAgentExecution } from "@/lib/persistence/agent-execution-worker-repository";
import {
  AgentExecutionDriverError,
  processAgentExecution,
  type AgentExecutionWorkerDependencies,
  type PreparedAgentExecution,
  type StructuredAgentExecutionDriver,
} from "./agent-execution-worker";

const request: AgentExecutionRequest = {
  requestVersion: "payo-agent-execution-v1",
  runId: "agent-run-worker-0001",
  intents: [{
    intentVersion: "payo-payment-intent-v1",
    intentId: "agent-intent-worker-0001",
    organizationId: "agent-organization-worker-0001",
    runId: "agent-run-worker-0001",
    action: "request_execution",
    token: "STRK",
    recipientAddress: "0x123",
    amountAtomic: "10",
    purposeCode: "private_payroll",
    capabilityNonce: "agent-worker-capability-nonce-0001",
    createdAt: "2026-08-30T10:00:00.000Z",
    validUntil: "2026-08-30T10:05:00.000Z",
  }],
};
const baseJob: LeasedAgentExecution = {
  id: "agent-execution-worker-0001",
  capabilityId: "agent-capability-worker-0001",
  reservationId: "agent-reservation-worker-0001",
  organizationId: request.intents[0].organizationId,
  runId: request.runId,
  state: "reserved",
  attempts: 1,
  runVersion: 1,
  requestCommitment: `0x${"11".repeat(32)}`,
  request,
  submissionCommitment: null,
  transactionHash: null,
  leaseOwner: "agent-worker-test",
};
const prepared: PreparedAgentExecution = {
  version: "payo-prepared-agent-execution-v1",
  executionId: baseJob.id,
  requestCommitment: baseJob.requestCommitment,
  submissionCommitment: `0x${"22".repeat(32)}`,
  opaque: { private: true },
};

function dependencies(): AgentExecutionWorkerDependencies {
  return {
    lease: vi.fn(async () => []),
    markPreparing: vi.fn(async () => ({ state: "preparing" }) as never),
    commitSubmission: vi.fn(async () => ({ state: "submitting" }) as never),
    recordSubmission: vi.fn(async () => ({ state: "submitted" }) as never),
    complete: vi.fn(async () => ({ state: "confirmed" }) as never),
    reconcile: vi.fn(async () => ({ state: "reconciled" }) as never),
    defer: vi.fn(async () => ({ state: "failed" }) as never),
  };
}

function driver(overrides: Partial<StructuredAgentExecutionDriver> = {}): StructuredAgentExecutionDriver {
  return {
    prepareAndVerify: vi.fn(async () => prepared),
    simulate: vi.fn(async () => undefined),
    submit: vi.fn(async () => "0x1234"),
    recoverSubmission: vi.fn(async () => null),
    observe: vi.fn(async () => ({ state: "pending" as const })),
    ...overrides,
  };
}

describe("structured agent execution worker", () => {
  it("prepares, verifies, simulates, commits, and submits in order", async () => {
    const calls: string[] = [];
    const deps = dependencies();
    deps.markPreparing = vi.fn(async () => { calls.push("preparing"); return {} as never; });
    deps.commitSubmission = vi.fn(async () => { calls.push("commit"); return {} as never; });
    deps.recordSubmission = vi.fn(async () => { calls.push("record"); return {} as never; });
    const executionDriver = driver({
      prepareAndVerify: vi.fn(async () => { calls.push("prove"); return prepared; }),
      simulate: vi.fn(async () => { calls.push("simulate"); }),
      submit: vi.fn(async () => { calls.push("submit"); return "0x1234"; }),
    });
    await expect(processAgentExecution({ job: baseJob, driver: executionDriver, dependencies: deps }))
      .resolves.toBe("submitted");
    expect(calls).toEqual(["preparing", "prove", "simulate", "commit", "submit", "record"]);
  });

  it("abandons a persisted unsigned plan when simulation fails before commit", async () => {
    const deps = dependencies();
    const abandon = vi.fn(async () => undefined);
    const executionDriver = driver({
      simulate: vi.fn(async () => {
        throw new AgentExecutionDriverError("DIRECT_SIMULATION_FAILED", "Simulation failed.");
      }),
      abandon,
    });
    await expect(processAgentExecution({ job: baseJob, driver: executionDriver, dependencies: deps }))
      .resolves.toBe("preparing");
    expect(abandon).toHaveBeenCalledWith(prepared);
    expect(deps.commitSubmission).not.toHaveBeenCalled();
    expect(executionDriver.submit).not.toHaveBeenCalled();
  });

  it("releases a permanently invalid request before signing", async () => {
    const deps = dependencies();
    const executionDriver = driver({
      prepareAndVerify: vi.fn(async () => {
        throw new AgentExecutionDriverError("AGENT_PROOF_INVALID", "Proof failed local verification.", true);
      }),
    });
    await expect(processAgentExecution({ job: baseJob, driver: executionDriver, dependencies: deps }))
      .resolves.toBe("failed");
    expect(deps.commitSubmission).not.toHaveBeenCalled();
    expect(deps.defer).toHaveBeenCalledWith(baseJob, expect.objectContaining({
      errorCode: "AGENT_PROOF_INVALID",
      permanent: true,
      preSubmission: true,
    }), expect.any(Date));
  });

  it("never resubmits when the original submission outcome is unknown", async () => {
    const deps = dependencies();
    const executionDriver = driver({ recoverSubmission: vi.fn(async () => null) });
    const uncertain: LeasedAgentExecution = {
      ...baseJob,
      state: "submitting",
      submissionCommitment: prepared.submissionCommitment,
    };
    await expect(processAgentExecution({ job: uncertain, driver: executionDriver, dependencies: deps }))
      .resolves.toBe("submitting");
    expect(executionDriver.recoverSubmission).toHaveBeenCalledOnce();
    expect(executionDriver.submit).not.toHaveBeenCalled();
    expect(deps.defer).toHaveBeenCalledWith(uncertain, {
      errorCode: "AGENT_SUBMISSION_RECOVERY_PENDING",
    }, expect.any(Date));
  });

  it("records a recovered hash and confirms only a successful receipt", async () => {
    const deps = dependencies();
    const uncertain: LeasedAgentExecution = {
      ...baseJob,
      state: "submitting",
      submissionCommitment: prepared.submissionCommitment,
    };
    await expect(processAgentExecution({
      job: uncertain,
      driver: driver({ recoverSubmission: vi.fn(async () => "0x9876") }),
      dependencies: deps,
    })).resolves.toBe("submitted");
    expect(deps.recordSubmission).toHaveBeenCalledWith(uncertain, "0x9876", expect.any(Date));

    const submitted = { ...uncertain, state: "submitted" as const, transactionHash: "0x9876" };
    await expect(processAgentExecution({
      job: submitted,
      driver: driver({ observe: vi.fn(async () => ({ state: "confirmed" as const })) }),
      dependencies: deps,
    })).resolves.toBe("confirmed");
    expect(deps.complete).toHaveBeenCalledWith(submitted, expect.any(Date));
  });

  it("marks direct-SDK execution reconciled only after FINALIZE observation", async () => {
    const deps = dependencies();
    const submitted: LeasedAgentExecution = {
      ...baseJob,
      state: "submitted",
      submissionCommitment: prepared.submissionCommitment,
      transactionHash: "0x9876",
    };
    await expect(processAgentExecution({
      job: submitted,
      driver: driver({ observe: vi.fn(async () => ({ state: "reconciled" as const })) }),
      dependencies: deps,
    })).resolves.toBe("reconciled");
    expect(deps.reconcile).toHaveBeenCalledWith(submitted, expect.any(Date));
    expect(deps.complete).not.toHaveBeenCalled();
  });

  it("fails closed when post-settlement proof reconciliation is permanently invalid", async () => {
    const deps = dependencies();
    const submitted: LeasedAgentExecution = {
      ...baseJob,
      state: "submitted",
      submissionCommitment: prepared.submissionCommitment,
      transactionHash: "0x9876",
    };
    await expect(processAgentExecution({
      job: submitted,
      driver: driver({
        observe: vi.fn(async () => {
          throw new AgentExecutionDriverError(
            "DIRECT_SETTLEMENT_BINDING_INVALID",
            "SettlementMatch binding failed.",
            true,
          );
        }),
      }),
      dependencies: deps,
    })).resolves.toBe("failed");
    expect(deps.defer).toHaveBeenCalledWith(submitted, expect.objectContaining({
      errorCode: "DIRECT_SETTLEMENT_BINDING_INVALID",
      permanent: true,
    }), expect.any(Date));
  });

  it("rejects driver binding substitution before the reservation is committed", async () => {
    const deps = dependencies();
    const executionDriver = driver({
      prepareAndVerify: vi.fn(async () => ({ ...prepared, executionId: "another-execution" })),
    });
    await expect(processAgentExecution({ job: baseJob, driver: executionDriver, dependencies: deps }))
      .resolves.toBe("failed");
    expect(deps.commitSubmission).not.toHaveBeenCalled();
    expect(deps.defer).toHaveBeenCalledWith(baseJob, expect.objectContaining({
      errorCode: "AGENT_PREPARED_BINDING_INVALID",
      permanent: true,
    }), expect.any(Date));
  });
});
