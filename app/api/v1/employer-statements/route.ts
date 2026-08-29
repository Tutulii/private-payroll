import { z } from "zod";
import { employerStatementCreateSchema } from "@/lib/domain/employer-statement";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  createEmployerStatement,
  listEmployerStatements,
} from "@/lib/persistence/employer-statement-repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const listQuerySchema = z.object({
  organizationId: uuidV7Schema,
}).strict();

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const deployment = getPayoDeploymentConfig();
    if (!principal.chainId || BigInt(principal.chainId) !== BigInt(deployment.chainId)) {
      throw new ApiError(
        403,
        "The authenticated Ready session is on the wrong chain for this PAYO deployment.",
        "STATEMENT_CHAIN_MISMATCH",
      );
    }
    const statement = employerStatementCreateSchema.parse(await readJson(request));
    const result = await createEmployerStatement({ statement, principal });
    return Response.json(
      { statement: result },
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
    const query = listQuerySchema.parse({
      organizationId: new URL(request.url).searchParams.get("organizationId"),
    });
    return Response.json({
      statements: await listEmployerStatements(query.organizationId, principal),
    }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
