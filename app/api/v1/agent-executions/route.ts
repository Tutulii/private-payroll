import { uuidV7Schema } from "@/lib/domain/records";
import { listAgentExecutions } from "@/lib/persistence/agent-execution-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const search = new URL(request.url).searchParams;
    const organizationId = uuidV7Schema.parse(search.get("organizationId"));
    const limit = search.get("limit") === null ? 50 : Number(search.get("limit"));
    return Response.json({
      executions: await listAgentExecutions({ organizationId, principal, limit }),
    }, { headers: { "cache-control": "private, no-store, max-age=0" } });
  } catch (error) {
    return apiFailure(error);
  }
}
