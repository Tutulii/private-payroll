import { RpcProvider } from "starknet";
import { requirePrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";
import { readPragmaFxSnapshots } from "@/lib/server/pragma-fx";

export const runtime = "nodejs";

export async function GET(request: Request) {
  try {
    await requirePrincipal(request);
    const requested = new URL(request.url).searchParams.get("tokens")?.split(",") ?? [];
    const tokens = requested.filter((token): token is "STRK" | "USDC" =>
      token === "STRK" || token === "USDC");
    if (tokens.length !== requested.length || tokens.length === 0) {
      throw new ApiError(400, "Request at least one supported FX token.", "FX_TOKEN_UNSUPPORTED");
    }
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    if (!rpcUrl) throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const result = await readPragmaFxSnapshots({
      rpc: {
        getBlockNumber: () => provider.getBlockNumber(),
        callContract: (call, blockIdentifier) => provider.callContract(call, blockIdentifier),
      },
      tokens,
    });
    return Response.json(result, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
