import { RpcProvider } from "starknet";
import { z } from "zod";
import { starknetAddressSchema, uuidV7Schema } from "@/lib/domain/records";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";
import { getPayoVestingBookConfig } from "@/lib/server/payo-deployment";
import { readTrustedPayrollBookSnapshot } from "@/lib/server/vesting-book-reader";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const querySchema = z.object({
  // Kept for backward-compatible clients. The snapshot itself is public chain
  // data, so verification must not require membership in the payer's vault.
  organizationId: uuidV7Schema.optional(),
  ownerAddress: starknetAddressSchema,
  periodStart: z.string().regex(/^(0|[1-9]\d*)$/),
  periodEnd: z.string().regex(/^(0|[1-9]\d*)$/),
}).strict();

export async function GET(request: Request) {
  try {
    await requirePrincipal(request);
    const url = new URL(request.url);
    const query = querySchema.parse(Object.fromEntries(url.searchParams));
    const deployment = getPayoVestingBookConfig();
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    if (!rpcUrl) {
      throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    }
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const chainId = await provider.getChainId();
    if (BigInt(chainId) !== BigInt(deployment.chainId)) {
      throw new ApiError(
        503,
        "The payroll-book RPC is on a different Starknet chain.",
        "PAYROLL_BOOK_CHAIN_MISMATCH",
      );
    }
    const blockNumber = await provider.getBlockNumber();
    const snapshot = await readTrustedPayrollBookSnapshot({
      rpc: {
        callContract: (call, blockIdentifier) => provider.callContract(call, blockIdentifier),
      },
      chainId: deployment.chainId,
      sealAddress: deployment.sealAddress,
      ownerAddress: query.ownerAddress,
      periodStart: BigInt(query.periodStart),
      periodEnd: BigInt(query.periodEnd),
      blockNumber,
    });
    return Response.json({ snapshot }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
