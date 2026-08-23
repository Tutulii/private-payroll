import { z } from "zod";
import { payrollRunStateSchema } from "@/lib/domain/payroll";
import { getEncryptedRun, transitionRun } from "@/lib/persistence/repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const transitionSchema = z.object({
  state: payrollRunStateSchema,
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]+$/).optional(),
  manifestRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
  runNullifier: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
}).strict();

type RunRouteContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: RunRouteContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({ run: await getEncryptedRun(id, principal) });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function PATCH(request: Request, context: RunRouteContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const input = transitionSchema.parse(await readJson(request));
    const run = await transitionRun({ runId: id, ...input, principal });
    return Response.json({ run });
  } catch (error) {
    return apiFailure(error);
  }
}
