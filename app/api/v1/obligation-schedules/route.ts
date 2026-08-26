import { obligationScheduleBatchSchema } from "@/lib/domain/obligation-schedule";
import { uuidV7Schema } from "@/lib/domain/records";
import { z } from "zod";
import {
  listDueObligationSchedules,
  registerObligationSchedules,
} from "@/lib/persistence/obligation-schedule-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

export const runtime = "nodejs";

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const search = new URL(request.url).searchParams;
    const organizationId = uuidV7Schema.parse(search.get("organizationId"));
    const limitValue = search.get("limit");
    const limit = limitValue === null
      ? undefined
      : z.coerce.number().int().min(1).max(500).parse(limitValue);
    return Response.json({
      schedules: await listDueObligationSchedules({ organizationId, principal, limit }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = obligationScheduleBatchSchema.parse(await readJson(request));
    const schedules = await registerObligationSchedules({ ...input, principal });
    return Response.json(
      { schedules },
      { status: schedules.every(({ replayed }) => replayed) ? 200 : 201 },
    );
  } catch (error) {
    return apiFailure(error);
  }
}
