import "server-only";

import {
  commitAgentExecutionForSubmission,
  completeAgentExecution,
  deferAgentExecution,
  leaseAgentExecutions,
  markAgentExecutionPreparing,
  reconcileAgentExecution,
  recordAgentExecutionSubmission,
  type LeasedAgentExecution,
} from "@/lib/persistence/agent-execution-worker-repository";

const COMMITMENT_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const HASH_PATTERN = /^0x[0-9a-fA-F]{1,64}$/;

export type PreparedAgentExecution = {
  version: "payo-prepared-agent-execution-v1";
  executionId: string;
  requestCommitment: string;
  submissionCommitment: string;
  /** Driver-private proof/actions. Never serialize this into an API response. */
  opaque: unknown;
};

export type AgentExecutionObservation =
  | { state: "pending" }
  | { state: "confirmed" }
  | { state: "reconciled" }
  | { state: "reverted"; errorCode?: string }
  | { state: "reorged" };

/**
 * A trusted local adapter, never an MCP/API input. The production adapter must
 * load authoritative encrypted payroll data, build STRK20 actions, prove,
 * locally verify, and simulate before returning from `prepareAndVerify`.
 */
export interface StructuredAgentExecutionDriver {
  prepareAndVerify(job: LeasedAgentExecution): Promise<PreparedAgentExecution>;
  simulate(prepared: PreparedAgentExecution): Promise<void>;
  submit(prepared: PreparedAgentExecution): Promise<string>;
  recoverSubmission(input: {
    executionId: string;
    requestCommitment: string;
    submissionCommitment: string;
  }): Promise<string | null>;
  observe(transactionHash: string): Promise<AgentExecutionObservation>;
  /** Releases an encrypted, never-signed plan after a pre-submission failure. */
  abandon?(prepared: PreparedAgentExecution): Promise<void>;
}

export type AgentExecutionWorkerDependencies = {
  lease: typeof leaseAgentExecutions;
  markPreparing: typeof markAgentExecutionPreparing;
  commitSubmission: typeof commitAgentExecutionForSubmission;
  recordSubmission: typeof recordAgentExecutionSubmission;
  complete: typeof completeAgentExecution;
  reconcile: typeof reconcileAgentExecution;
  defer: typeof deferAgentExecution;
};

const defaultDependencies: AgentExecutionWorkerDependencies = {
  lease: leaseAgentExecutions,
  markPreparing: markAgentExecutionPreparing,
  commitSubmission: commitAgentExecutionForSubmission,
  recordSubmission: recordAgentExecutionSubmission,
  complete: completeAgentExecution,
  reconcile: reconcileAgentExecution,
  defer: deferAgentExecution,
};

function errorCode(error: unknown, fallback: string): string {
  if (error instanceof AgentExecutionDriverError) return error.code;
  // Low-level adapters intentionally throw opaque machine codes. Preserve only
  // that strict, privacy-safe form so receipts remain actionable without ever
  // leaking RPC responses, URLs, ciphertext, or private execution data.
  if (error instanceof Error && /^[A-Z][A-Z0-9_]{2,79}$/.test(error.message)) {
    return error.message;
  }
  return fallback;
}

export class AgentExecutionDriverError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly permanent = false,
  ) {
    super(message);
    this.name = "AgentExecutionDriverError";
  }
}

function assertPrepared(job: LeasedAgentExecution, prepared: PreparedAgentExecution): void {
  if (
    prepared.version !== "payo-prepared-agent-execution-v1"
    || prepared.executionId !== job.id
    || prepared.requestCommitment.toLowerCase() !== job.requestCommitment.toLowerCase()
    || !COMMITMENT_PATTERN.test(prepared.submissionCommitment)
  ) throw new AgentExecutionDriverError(
    "AGENT_PREPARED_BINDING_INVALID",
    "The structured execution driver returned mismatched bindings.",
    true,
  );
}

export async function processAgentExecution(input: {
  job: LeasedAgentExecution;
  driver: StructuredAgentExecutionDriver;
  dependencies?: AgentExecutionWorkerDependencies;
  now?: Date;
}): Promise<"preparing" | "submitting" | "submitted" | "confirmed" | "reconciled" | "failed"> {
  const dependencies = input.dependencies ?? defaultDependencies;
  const now = input.now ?? new Date();
  const job = input.job;

  if (job.state === "submitted") {
    if (!job.transactionHash || !HASH_PATTERN.test(job.transactionHash)) {
      await dependencies.defer(job, {
        errorCode: "AGENT_SUBMITTED_HASH_INVALID",
        permanent: true,
      }, now);
      return "failed";
    }
    try {
      const observation = await input.driver.observe(job.transactionHash);
      if (observation.state === "confirmed") {
        await dependencies.complete(job, now);
        return "confirmed";
      }
      if (observation.state === "reconciled") {
        await dependencies.reconcile(job, now);
        return "reconciled";
      }
      if (observation.state === "reverted") {
        await dependencies.defer(job, {
          errorCode: observation.errorCode ?? "AGENT_EXECUTION_REVERTED",
          permanent: true,
        }, now);
        return "failed";
      }
      await dependencies.defer(job, {
        errorCode: observation.state === "reorged"
          ? "AGENT_EXECUTION_REORGED"
          : "AGENT_EXECUTION_PENDING",
      }, now);
      return "submitted";
    } catch (error) {
      const driverError = error instanceof AgentExecutionDriverError ? error : undefined;
      await dependencies.defer(job, {
        errorCode: errorCode(error, "AGENT_RECEIPT_READ_FAILED"),
        permanent: driverError?.permanent ?? false,
      }, now);
      return driverError?.permanent ? "failed" : "submitted";
    }
  }

  if (job.state === "submitting") {
    if (!job.submissionCommitment || !COMMITMENT_PATTERN.test(job.submissionCommitment)) {
      await dependencies.defer(job, {
        errorCode: "AGENT_SUBMISSION_COMMITMENT_MISSING",
        permanent: true,
      }, now);
      return "failed";
    }
    try {
      const recoveredHash = await input.driver.recoverSubmission({
        executionId: job.id,
        requestCommitment: job.requestCommitment,
        submissionCommitment: job.submissionCommitment,
      });
      if (!recoveredHash) {
        await dependencies.defer(job, { errorCode: "AGENT_SUBMISSION_RECOVERY_PENDING" }, now);
        return "submitting";
      }
      if (!HASH_PATTERN.test(recoveredHash)) {
        throw new AgentExecutionDriverError(
          "AGENT_RECOVERED_HASH_INVALID",
          "The driver returned an invalid recovered hash.",
          false,
        );
      }
      await dependencies.recordSubmission(job, recoveredHash, now);
      return "submitted";
    } catch (error) {
      // Never sign again while the first submission's outcome is unknown.
      await dependencies.defer(job, {
        errorCode: errorCode(error, "AGENT_SUBMISSION_RECOVERY_FAILED"),
      }, now);
      return "submitting";
    }
  }

  let pointOfNoReturn = false;
  let prepared: PreparedAgentExecution | undefined;
  try {
    await dependencies.markPreparing(job, now);
    prepared = await input.driver.prepareAndVerify(job);
    assertPrepared(job, prepared);
    await input.driver.simulate(prepared);
    await dependencies.commitSubmission(job, prepared.submissionCommitment, now);
    pointOfNoReturn = true;
    const transactionHash = await input.driver.submit(prepared);
    if (!HASH_PATTERN.test(transactionHash)) {
      throw new AgentExecutionDriverError(
        "AGENT_SUBMITTED_HASH_INVALID",
        "The driver did not return a Starknet transaction hash.",
      );
    }
    await dependencies.recordSubmission(job, transactionHash, now);
    return "submitted";
  } catch (error) {
    const driverError = error instanceof AgentExecutionDriverError ? error : undefined;
    if (!pointOfNoReturn && prepared && input.driver.abandon) {
      try {
        await input.driver.abandon(prepared);
      } catch {
        // Keep the originating error; cleanup is idempotently retried by the driver.
      }
    }
    await dependencies.defer(job, {
      errorCode: errorCode(error, pointOfNoReturn
        ? "AGENT_SUBMISSION_OUTCOME_UNKNOWN"
        : "AGENT_PREPARATION_FAILED"),
      permanent: pointOfNoReturn ? false : (driverError?.permanent ?? false),
      preSubmission: !pointOfNoReturn,
    }, now);
    return pointOfNoReturn ? "submitting" : driverError?.permanent ? "failed" : "preparing";
  }
}

export async function runAgentExecutionWorker(input: {
  workerId: string;
  driver: StructuredAgentExecutionDriver;
  limit?: number;
  now?: Date;
  dependencies?: AgentExecutionWorkerDependencies;
}): Promise<Array<{ id: string; state: Awaited<ReturnType<typeof processAgentExecution>> }>> {
  const dependencies = input.dependencies ?? defaultDependencies;
  const now = input.now ?? new Date();
  const jobs = await dependencies.lease(input.workerId, input.limit ?? 2, now);
  const results = [];
  for (const job of jobs) {
    results.push({
      id: job.id,
      state: await processAgentExecution({
        job,
        driver: input.driver,
        dependencies,
        now,
      }),
    });
  }
  return results;
}
