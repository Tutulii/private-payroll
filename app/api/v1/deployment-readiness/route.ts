import { RpcProvider } from "starknet";
import { payoReadinessRequestSchema } from "@/lib/starknet/readiness";
import { requirePrincipal, ApiError } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";
import { getDirectPrivacyDeploymentConfig } from "@/lib/server/direct-privacy-deployment";
import { checkPayoDeploymentReadiness } from "@/lib/server/payo-readiness";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    await requirePrincipal(request);
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    if (!rpcUrl) throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const readinessRequest = payoReadinessRequestSchema.parse(await readJson(request));
    const humanDeployment = getPayoDeploymentConfig();
    const deployment = BigInt(readinessRequest.sealAddress) === BigInt(humanDeployment.sealAddress)
      ? humanDeployment
      : (() => {
          const direct = getDirectPrivacyDeploymentConfig();
          if (BigInt(readinessRequest.sealAddress) !== BigInt(direct.sealAddress)) {
            throw new ApiError(
              409,
              "The requested PAYO seal is not a reviewed deployment.",
              "PAYO_SEAL_NOT_REVIEWED",
            );
          }
          return { chainId: direct.chainId, sealAddress: direct.sealAddress };
        })();
    const readiness = await checkPayoDeploymentReadiness({
      request: readinessRequest,
      deployment,
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
