import { z } from "zod";
import { starknetAddressSchema, uuidV7Schema } from "@/lib/domain/records";
import { listPayrollBookReportSources } from "@/lib/persistence/payroll-book-report-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const querySchema = z.object({
  organizationId: uuidV7Schema,
  ownerAddress: starknetAddressSchema,
  periodStart: z.string().regex(/^(0|[1-9]\d*)$/),
  periodEnd: z.string().regex(/^(0|[1-9]\d*)$/),
}).strict();

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const query = querySchema.parse(Object.fromEntries(new URL(request.url).searchParams));
    const sources = await listPayrollBookReportSources({ ...query, principal });
    return Response.json({ sources }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
