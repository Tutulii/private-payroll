import { RpcProvider } from "starknet";
import { payoReadinessRequestSchema } from "@/lib/starknet/readiness";
import { requirePrincipal, ApiError } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";
import { checkPayoDeploymentReadiness } from "@/lib/server/payo-readiness";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    await requirePrincipal(request);
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    if (!rpcUrl) throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const readiness = await checkPayoDeploymentReadiness({
      request: payoReadinessRequestSchema.parse(await readJson(request)),
      deployment: getPayoDeploymentConfig(),
      rpc: {
        getChainId: () => provider.getChainId(),
        getBlockNumber: () => provider.getBlockNumber(),
        callContract: (call, blockIdentifier) => provider.callContract(call, blockIdentifier),
      },
    });
    return Response.json({ readiness }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
