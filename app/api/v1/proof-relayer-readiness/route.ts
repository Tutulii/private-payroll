import { RpcProvider } from "starknet";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";
import {
  PROOF_RELAYER_FUNDING_CODE,
  proofRelayerReserve,
  readProofRelayerBalance,
} from "@/lib/server/proof-relayer-funding";

export const runtime = "nodejs";

export async function GET(request: Request) {
  try {
    await requirePrincipal(request);
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    const relayerAddress = process.env.PAYO_PROOF_RELAYER_ADDRESS;
    if (!rpcUrl || !relayerAddress || !process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY) {
      throw new ApiError(503, "PAYO's proof service is unavailable. Try again later.", "PROOF_RELAYER_NOT_CONFIGURED");
    }
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    if (BigInt(await provider.getChainId()) !== BigInt(getPayoDeploymentConfig().chainId)) {
      throw new ApiError(503, "PAYO's proof service is connected to the wrong network.", "PROOF_RELAYER_CHAIN_MISMATCH");
    }
    const ready = await readProofRelayerBalance(provider, relayerAddress) >= proofRelayerReserve();
    return Response.json({ readiness: {
      ready,
      code: ready ? "PROOF_RELAYER_READY" : PROOF_RELAYER_FUNDING_CODE,
      message: ready ? "Proof service gas reserve is available."
        : "PAYO's proof service needs gas funding. Proof generation has not started; try again after the service is funded.",
    } }, { headers: { "cache-control": "private, no-store, max-age=0" } });
  } catch (error) { return apiFailure(error); }
}
