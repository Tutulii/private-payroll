import { z } from "zod";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  attachWageRemediationSettlement,
  getWageRemediation,
} from "@/lib/persistence/wage-remediation-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: RouteContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({
      remediation: await getWageRemediation(uuidV7Schema.parse(id), principal),
    }, { headers: { "cache-control": "private, no-store, max-age=0" } });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function PATCH(request: Request, context: RouteContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const body = z.object({ settlementId: uuidV7Schema }).strict().parse(
      await readJson(request),
    );
    return Response.json({
      remediation: await attachWageRemediationSettlement({
        remediationId: uuidV7Schema.parse(id),
        settlementId: body.settlementId,
        principal,
      }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
