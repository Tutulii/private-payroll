import { z } from "zod";
import { obligationSnapshotPlanCreateSchema } from "@/lib/domain/obligation-snapshot-plan";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  createObligationSnapshotPlan,
  findRegisteredObligationSnapshotPlan,
  listObligationSnapshotPlans,
} from "@/lib/persistence/obligation-snapshot-plan-repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const listQuerySchema = z.object({
  organizationId: uuidV7Schema,
  cycleId: z.string().min(1).max(160).optional(),
  agreementRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
}).strict().superRefine((query, context) => {
  if ((query.cycleId === undefined) !== (query.agreementRoot === undefined)) {
    context.addIssue({
      code: "custom",
      path: [query.cycleId === undefined ? "cycleId" : "agreementRoot"],
      message: "Finding a registered snapshot requires both cycleId and agreementRoot.",
    });
  }
});

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const deployment = getPayoDeploymentConfig();
    if (!principal.chainId || BigInt(principal.chainId) !== BigInt(deployment.chainId)) {
      throw new ApiError(
        403,
        "The authenticated Ready session is on the wrong chain for this PAYO deployment.",
        "SNAPSHOT_CHAIN_MISMATCH",
      );
    }
    const plan = obligationSnapshotPlanCreateSchema.parse(await readJson(request));
    const result = await createObligationSnapshotPlan({ plan, principal });
    return Response.json(
      { plan: result },
      {
        status: result.replayed ? 200 : 201,
        headers: { "cache-control": "private, no-store, max-age=0" },
      },
    );
  } catch (error) {
    return apiFailure(error);
  }
}

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const search = new URL(request.url).searchParams;
    const query = listQuerySchema.parse({
      organizationId: search.get("organizationId"),
      ...(search.has("cycleId") ? { cycleId: search.get("cycleId") } : {}),
      ...(search.has("agreementRoot") ? { agreementRoot: search.get("agreementRoot") } : {}),
    });
    const result = query.cycleId && query.agreementRoot
      ? { plan: await findRegisteredObligationSnapshotPlan({
          organizationId: query.organizationId,
          cycleId: query.cycleId,
          agreementRoot: query.agreementRoot,
          principal,
        }) }
      : { plans: await listObligationSnapshotPlans(query.organizationId, principal) };
    return Response.json(result, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
