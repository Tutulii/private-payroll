import { uuidV7Schema } from "@/lib/domain/records";
import { wageRemediationCreateSchema } from "@/lib/domain/wage-remediation";
import {
  createWageRemediation,
  listWageRemediations,
} from "@/lib/persistence/wage-remediation-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const organizationId = new URL(request.url).searchParams.get("organizationId");
    return Response.json({
      remediations: await listWageRemediations({
        principal,
        ...(organizationId
          ? { organizationId: uuidV7Schema.parse(organizationId) }
          : {}),
      }),
    }, { headers: { "cache-control": "private, no-store, max-age=0" } });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const remediation = wageRemediationCreateSchema.parse(await readJson(request));
    const stored = await createWageRemediation({ remediation, principal });
    return Response.json(
      { remediation: stored },
      { status: stored.replayed ? 200 : 201 },
    );
  } catch (error) {
    return apiFailure(error);
  }
}
