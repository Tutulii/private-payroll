import { payrollAuthorizationRequestSchema } from "@/lib/domain/proof-bundle";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  enqueuePayrollAuthorization,
  getPayrollAuthorizationJob,
} from "@/lib/persistence/payroll-authorization-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

type AuthorizationContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: AuthorizationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({
      authorization: await getPayrollAuthorizationJob(uuidV7Schema.parse(id), principal),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request, context: AuthorizationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const authorization = await enqueuePayrollAuthorization({
      runId: uuidV7Schema.parse(id),
      request: payrollAuthorizationRequestSchema.parse(await readJson(request)),
      principal,
    });
    return Response.json(
      { authorization },
      { status: authorization.replayed ? 200 : 201 },
    );
  } catch (error) {
    return apiFailure(error);
  }
}
