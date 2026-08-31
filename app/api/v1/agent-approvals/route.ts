import { uuidV7Schema } from "@/lib/domain/records";
import { listHumanApprovalExecutions } from "@/lib/persistence/agent-execution-approval-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const search = new URL(request.url).searchParams;
    const organizationId = uuidV7Schema.parse(search.get("organizationId"));
    const limit = search.get("limit") === null ? 50 : Number(search.get("limit"));
    return Response.json({
      executions: await listHumanApprovalExecutions({ organizationId, principal, limit }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
