import { materializeDueObligationSchedules } from "@/lib/persistence/obligation-schedule-repository";
import { authorizeInternalWorker } from "@/lib/server/internal-auth";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json(
      { error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." } },
      { status: 401 },
    );
  }
  try {
    return Response.json(await materializeDueObligationSchedules({ limit: 100 }));
  } catch {
    return Response.json(
      { error: { code: "WORKER_FAILURE", message: "Recurring obligation scheduling failed." } },
      { status: 500 },
    );
  }
}
