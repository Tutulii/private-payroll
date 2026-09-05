import { exceptionAuthorizationRequestSchema } from "@/lib/domain/proof-bundle";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  enqueueExceptionAuthorization,
  getExceptionAuthorizationJob,
} from "@/lib/persistence/exception-authorization-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { getPayoDeploymentConfig, getPayoVestingBookConfig } from "@/lib/server/payo-deployment";
import { apiFailure, readJson } from "@/lib/server/http";

type AuthorizationContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: AuthorizationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({
      authorization: await getExceptionAuthorizationJob(uuidV7Schema.parse(id), principal),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request, context: AuthorizationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const body = exceptionAuthorizationRequestSchema.parse(await readJson(request));
    const deployment = getPayoDeploymentConfig();
    const book = getPayoVestingBookConfig();
    const authorization = await enqueueExceptionAuthorization({
      proofBundleId: uuidV7Schema.parse(id),
      request: body,
      principal,
      chainId: deployment.chainId,
      exceptionSealAddress: deployment.sealAddress,
      bookSealAddress: book.sealAddress,
    });
    return Response.json(
      { authorization },
      { status: authorization.replayed ? 200 : 201 },
    );
  } catch (error) {
    return apiFailure(error);
  }
}
