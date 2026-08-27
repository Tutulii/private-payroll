// Keep co-located worker traffic off Fly's public proxy. PAYO_API_URL is the
// browser/authentication origin and must not make the machine call itself over
// the public network for every poll.
const baseUrl = (process.env.PAYO_WORKER_API_URL ?? "http://127.0.0.1:3000").replace(/\/$/, "");
const workerSecret = process.env.PAYO_WORKER_SECRET;

if (!workerSecret || workerSecret.length < 32) {
  throw new Error("PAYO_WORKER_SECRET must be configured before starting Phase 2 workers.");
}

const jobs = [
  { name: "confirmations", path: "/api/internal/confirmations", intervalMs: 8_000 },
  { name: "proof-verifications", path: "/api/internal/proof-verifications", intervalMs: 5_000 },
  { name: "indexer", path: "/api/internal/indexer", intervalMs: 10_000, catchUpDelayMs: 1_000 },
  { name: "recurring-scheduler", path: "/api/internal/recurring-scheduler", intervalMs: 15_000 },
];

let stopping = false;
const controllers = new Set();

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function compactResult(payload) {
  if (!payload || typeof payload !== "object") return String(payload);
  if (payload.error && typeof payload.error === "object") {
    return `${payload.error.code ?? "WORKER_ERROR"}: ${payload.error.message ?? "Worker request failed"}`;
  }
  return JSON.stringify(payload);
}

async function runJob(job) {
  let failures = 0;
  while (!stopping) {
    let successDelay = job.intervalMs;
    const controller = new AbortController();
    controllers.add(controller);
    try {
      const response = await fetch(`${baseUrl}${job.path}`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${workerSecret}`,
          "x-payo-worker-id": `local-${job.name}-${process.pid}`,
        },
        signal: controller.signal,
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(compactResult(payload));
      }
      failures = 0;
      const indexed = Number(payload?.indexed);
      const headBlockNumber = Number(payload?.headBlockNumber);
      const nextBlockNumber = Number(payload?.nextBlockNumber);
      const stillBehindHead = Number.isFinite(headBlockNumber)
        && Number.isFinite(nextBlockNumber)
        && nextBlockNumber <= headBlockNumber;
      if (
        job.catchUpDelayMs
        && indexed > 0
        && stillBehindHead
      ) {
        successDelay = job.catchUpDelayMs;
      }
      console.log(`[${new Date().toISOString()}] ${job.name} ${compactResult(payload)}`);
    } catch (error) {
      if (stopping) break;
      failures += 1;
      const message = error instanceof Error ? error.message : "Worker request failed";
      console.error(`[${new Date().toISOString()}] ${job.name} failed: ${message}`);
    } finally {
      controllers.delete(controller);
    }
    const backoff = failures === 0
      ? successDelay
      : Math.min(job.intervalMs * 2 ** Math.min(failures, 4), 60_000);
    await delay(backoff);
  }
}

function stop() {
  if (stopping) return;
  stopping = true;
  for (const controller of controllers) controller.abort();
}

process.once("SIGINT", stop);
process.once("SIGTERM", stop);

console.log(`PAYO durable workers targeting ${baseUrl}`);
await Promise.all(jobs.map(runJob));
