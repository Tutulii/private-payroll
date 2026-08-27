import { createHash } from "node:crypto";
import type { ProofWorkerSuccess } from "./protocol";
import type { RemoteProofRequest } from "./remote-prover";

export type ProverJobState = "queued" | "processing" | "complete" | "failed";

export type ProverJobSnapshot = {
  requestId: string;
  state: ProverJobState;
  createdAt: string;
  updatedAt: string;
  result?: ProofWorkerSuccess;
  error?: { code: string; message: string };
};

type ProverJob = ProverJobSnapshot & {
  key: string;
  principalId: string;
  fingerprint: string;
  run?: () => Promise<ProofWorkerSuccess>;
};

const COMPLETED_JOB_TTL_MS = 30 * 60_000;
const MAXIMUM_RETAINED_JOBS = 12;

const jobs = new Map<string, ProverJob>();
const queue: string[] = [];
let draining = false;

function jobKey(principalId: string, requestId: string): string {
  return `${principalId}:${requestId}`;
}

function requestFingerprint(request: RemoteProofRequest): string {
  return createHash("sha256").update(JSON.stringify(request)).digest("hex");
}

function publicSnapshot(job: ProverJob): ProverJobSnapshot {
  return {
    requestId: job.requestId,
    state: job.state,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    ...(job.result ? { result: job.result } : {}),
    ...(job.error ? { error: job.error } : {}),
  };
}

function removeExpiredJobs(now = Date.now()): void {
  for (const [key, job] of jobs) {
    if (
      (job.state === "complete" || job.state === "failed")
      && now - Date.parse(job.updatedAt) >= COMPLETED_JOB_TTL_MS
    ) {
      jobs.delete(key);
    }
  }
}

async function drainQueue(): Promise<void> {
  if (draining) return;
  draining = true;
  try {
    while (queue.length > 0) {
      const key = queue.shift()!;
      const job = jobs.get(key);
      if (!job || !job.run || job.state !== "queued") continue;
      const run = job.run;
      job.run = undefined;
      job.state = "processing";
      job.updatedAt = new Date().toISOString();
      try {
        job.result = await run();
        job.state = "complete";
        job.updatedAt = new Date().toISOString();
        console.info(`PAYO prover job ${job.requestId} completed in ${job.result.provingTimeMs} ms.`);
      } catch (error) {
        job.state = "failed";
        job.updatedAt = new Date().toISOString();
        job.error = {
          code: "PROVER_JOB_FAILED",
          message: "The remote ZK prover could not generate this proof.",
        };
        console.error(`PAYO prover job ${job.requestId} failed.`, error);
      }
      removeExpiredJobs();
    }
  } finally {
    draining = false;
    // A request can enqueue after the loop observes an empty queue but before
    // the finally block releases the drain lock.
    if (queue.length > 0) void drainQueue();
  }
}

export function enqueueProverJob(input: {
  principalId: string;
  request: RemoteProofRequest;
  run: () => Promise<ProofWorkerSuccess>;
}): ProverJobSnapshot {
  removeExpiredJobs();
  const key = jobKey(input.principalId, input.request.requestId);
  const fingerprint = requestFingerprint(input.request);
  const existing = jobs.get(key);
  if (existing) {
    if (existing.fingerprint !== fingerprint) {
      throw new Error("PROVER_REQUEST_ID_REUSED");
    }
    return publicSnapshot(existing);
  }
  if (jobs.size >= MAXIMUM_RETAINED_JOBS) {
    throw new Error("PROVER_QUEUE_FULL");
  }
  const now = new Date().toISOString();
  const job: ProverJob = {
    key,
    principalId: input.principalId,
    requestId: input.request.requestId,
    fingerprint,
    state: "queued",
    createdAt: now,
    updatedAt: now,
    run: input.run,
  };
  jobs.set(key, job);
  queue.push(key);
  void drainQueue();
  return publicSnapshot(job);
}

export function getProverJob(principalId: string, requestId: string): ProverJobSnapshot | undefined {
  removeExpiredJobs();
  const job = jobs.get(jobKey(principalId, requestId));
  return job ? publicSnapshot(job) : undefined;
}

export async function waitForProverJob(
  principalId: string,
  requestId: string,
  timeoutMs = 30 * 60_000,
): Promise<ProverJobSnapshot> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const job = getProverJob(principalId, requestId);
    if (!job) throw new Error("PROVER_JOB_NOT_FOUND");
    if (job.state === "complete" || job.state === "failed") return job;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("PROVER_JOB_TIMEOUT");
}

export function resetProverJobsForTests(): void {
  jobs.clear();
  queue.splice(0, queue.length);
  draining = false;
}
