import { z } from "zod";
import { uuidV7Schema } from "@/lib/domain/records";
import { listAuditEvents } from "@/lib/persistence/repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const search = new URL(request.url).searchParams;
    const organizationId = uuidV7Schema.parse(search.get("organizationId"));
    const limit = search.get("limit") === null
      ? 100
      : z.coerce.number().int().min(1).max(200).parse(search.get("limit"));
    return Response.json({ events: await listAuditEvents(organizationId, principal, limit) });
  } catch (error) {
    return apiFailure(error);
  }
}
