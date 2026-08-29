import { listObligationClaimAccessGrants } from "@/lib/persistence/obligation-snapshot-plan-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    return Response.json({
      grants: await listObligationClaimAccessGrants(principal),
    }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
