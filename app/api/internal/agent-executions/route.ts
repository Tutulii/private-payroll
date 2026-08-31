import { authorizeInternalWorker } from "@/lib/server/internal-auth";
import { runAgentExecutionWorker } from "@/lib/server/agent-execution-worker";
import { createDirectPrivacyAgentExecutionDriver } from "@/lib/server/direct-privacy-agent-driver";

export const runtime = "nodejs";
export const maxDuration = 3_600;

let driverPromise: ReturnType<typeof createDirectPrivacyAgentExecutionDriver> | undefined;

function workerLimit(): number {
  const parsed = Number(process.env.PAYO_AGENT_WORKER_LIMIT ?? "1");
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 2) {
    throw new Error("PAYO_AGENT_WORKER_LIMIT must be 1 or 2.");
  }
  return parsed;
}

export async function POST(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json(
      { error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." } },
      { status: 401 },
    );
  }
  if (process.env.PAYO_AGENT_EXECUTOR_ENABLED !== "true") {
    return Response.json({
      error: {
        code: "AGENT_EXECUTOR_DISABLED",
        message: "The bounded-autonomy executor is disabled on this machine.",
      },
    }, { status: 503 });
  }
  try {
    driverPromise ??= createDirectPrivacyAgentExecutionDriver().catch((error) => {
      driverPromise = undefined;
      throw error;
    });
    const results = await runAgentExecutionWorker({
      workerId: request.headers.get("x-payo-worker-id") || "payo-agent-executor",
      driver: await driverPromise,
      limit: workerLimit(),
    });
    return Response.json({
      leased: results.length,
      results,
    });
  } catch {
    return Response.json({
      error: {
        code: "AGENT_EXECUTOR_FAILURE",
        message: "The bounded-autonomy executor failed closed.",
      },
    }, { status: 500 });
  }
}
