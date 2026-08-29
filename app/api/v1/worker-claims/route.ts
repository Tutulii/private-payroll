import { workerClaimCreateSchema } from "@/lib/domain/worker-claim";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  createWorkerClaim,
  listWorkerClaims,
} from "@/lib/persistence/worker-claim-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const organizationId = new URL(request.url).searchParams.get("organizationId");
    return Response.json({
      claims: await listWorkerClaims({
        principal,
        ...(organizationId ? { organizationId: uuidV7Schema.parse(organizationId) } : {}),
      }),
    }, { headers: { "cache-control": "private, no-store, max-age=0" } });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const claim = workerClaimCreateSchema.parse(await readJson(request));
    const stored = await createWorkerClaim({ claim, principal });
    return Response.json(
      { claim: stored },
      { status: stored.replayed ? 200 : 201 },
    );
  } catch (error) {
    return apiFailure(error);
  }
}
