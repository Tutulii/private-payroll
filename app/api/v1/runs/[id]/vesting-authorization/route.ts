import { vestingAuthorizationRequestSchema } from "@/lib/domain/proof-bundle";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  enqueueVestingAuthorization,
  getVestingAuthorizationJob,
} from "@/lib/persistence/vesting-authorization-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoVestingBookConfig } from "@/lib/server/payo-deployment";

type AuthorizationContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: AuthorizationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({
      authorization: await getVestingAuthorizationJob(uuidV7Schema.parse(id), principal),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request, context: AuthorizationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const deployment = getPayoVestingBookConfig();
    const authorization = await enqueueVestingAuthorization({
      runId: uuidV7Schema.parse(id),
      request: vestingAuthorizationRequestSchema.parse(await readJson(request)),
      principal,
      chainId: deployment.chainId,
      sealAddress: deployment.sealAddress,
    });
    return Response.json(
      { authorization },
      { status: authorization.replayed ? 200 : 201 },
    );
  } catch (error) {
    return apiFailure(error);
  }
}
