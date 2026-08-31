import { agentExecutionRequestSchema } from "@/lib/domain/capability";
import {
  getAgentExecution,
  requestAgentExecution,
} from "@/lib/persistence/agent-execution-repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

type ExecutionContext = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: ExecutionContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id: capabilityId } = await context.params;
    const idempotencyKey = request.headers.get("idempotency-key");
    if (!idempotencyKey) throw new ApiError(400, "Idempotency-Key is required.", "IDEMPOTENCY_KEY_REQUIRED");
    const execution = await requestAgentExecution({
      capabilityId,
      idempotencyKey,
      request: agentExecutionRequestSchema.parse(await readJson(request)),
      principal,
    });
    return Response.json({ execution }, { status: execution.replayed ? 200 : 202 });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function GET(request: Request, context: ExecutionContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id: capabilityId } = await context.params;
    const executionId = new URL(request.url).searchParams.get("executionId");
    if (!executionId) throw new ApiError(400, "executionId is required.", "AGENT_EXECUTION_ID_REQUIRED");
    return Response.json({
      execution: await getAgentExecution({ capabilityId, executionId, principal }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
