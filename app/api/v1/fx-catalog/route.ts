import { RpcProvider } from "starknet";
import { z } from "zod";
import { protectedFxSnapshotToPayrollSnapshot } from "@/lib/domain/fx";
import { requireOrganizationRole } from "@/lib/persistence/repository";
import { buildFxCatalogRoot } from "@/lib/proof/input-builder";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { issueFxPublicationTicket } from "@/lib/server/fx-publication-ticket";
import { apiFailure } from "@/lib/server/http";
import { getPayoDeploymentConfig, getPayoRegistryConfig } from "@/lib/server/payo-deployment";
import {
  PragmaProtectedPairUnavailableError,
  readPragmaFxSnapshots,
  readPragmaProtectedFxSnapshots,
} from "@/lib/server/pragma-fx";
import { fxCatalogPublicationWindow } from "@/lib/domain/fx";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const querySchema = z.object({
  organizationId: z.string().uuid(),
  medianTokens: z.string().max(16).default(""),
  protectedTokens: z.string().max(16).default(""),
}).strict();

function tokenList(value: string, label: string): ("STRK" | "USDC")[] {
  if (!value) return [];
  const values = value.split(",");
  if (values.some((token) => token !== "STRK" && token !== "USDC")) {
    throw new ApiError(400, `${label} contains an unsupported token.`, "FX_TOKEN_UNSUPPORTED");
  }
  return [...new Set(values)] as ("STRK" | "USDC")[];
}

export async function GET(request: Request) {
  try {
    const authenticated = await requirePrincipal(request);
    const url = new URL(request.url);
    const query = querySchema.parse({
      organizationId: url.searchParams.get("organizationId"),
      medianTokens: url.searchParams.get("medianTokens") ?? "",
      protectedTokens: url.searchParams.get("protectedTokens") ?? "",
    });
    await requireOrganizationRole(query.organizationId, authenticated, ["admin", "operator"]);
    const medianTokens = tokenList(query.medianTokens, "Median FX catalog");
    const protectedTokens = tokenList(query.protectedTokens, "Protected FX catalog");
    if (medianTokens.length + protectedTokens.length === 0) {
      throw new ApiError(400, "Request at least one FX token.", "FX_TOKEN_UNSUPPORTED");
    }
    if (medianTokens.some((token) => protectedTokens.includes(token))) {
      throw new ApiError(400, "An FX token cannot use two profiles in one catalog.", "FX_PROFILE_CONFLICT");
    }
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    if (!rpcUrl) throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const rpc = {
      getBlockNumber: () => provider.getBlockNumber(),
      getBlockTimestamp: async (blockNumber: number) => {
        const block = await provider.getBlock(blockNumber);
        return Number(block.timestamp);
      },
      callContract: (call: Parameters<typeof provider.callContract>[0], blockIdentifier?: number) =>
        provider.callContract(call, blockIdentifier),
    };
    const [protectedResult, medianResult] = await Promise.all([
      protectedTokens.length
        ? readPragmaProtectedFxSnapshots({ rpc, tokens: protectedTokens })
        : Promise.resolve({ blockNumber: null, blockTimestamp: null, snapshots: [] }),
      medianTokens.length
        ? readPragmaFxSnapshots({ rpc, tokens: medianTokens })
        : Promise.resolve({ blockNumber: null, snapshots: [] }),
    ]);
    const snapshots = [
      ...protectedResult.snapshots.map(protectedFxSnapshotToPayrollSnapshot),
      ...medianResult.snapshots,
    ];
    const catalogRoot = await buildFxCatalogRoot(snapshots);
    const publicationWindow = fxCatalogPublicationWindow(snapshots);
    const deployment = getPayoDeploymentConfig();
    const registries = getPayoRegistryConfig();
    const publicationTicket = issueFxPublicationTicket({
      organizationId: query.organizationId,
      principalId: authenticated.principalId,
      chainId: deployment.chainId,
      registryAddress: registries.policyRegistryAddress,
      catalogRoot,
      observedAt: publicationWindow.observedAt,
      maximumAgeSeconds: publicationWindow.maximumAgeSeconds,
      expiresAt: publicationWindow.expiresAt,
    });
    return Response.json({
      snapshots,
      catalogRoot,
      publicationWindow,
      publicationTicket,
      sourceBlocks: {
        protected: protectedResult.blockNumber,
        median: medianResult.blockNumber,
      },
    }, { headers: { "cache-control": "private, no-store, max-age=0" } });
  } catch (error) {
    if (error instanceof PragmaProtectedPairUnavailableError) {
      return apiFailure(new ApiError(
        422,
        `${error.pair} cannot use the protected FX profile because Pragma's ${error.component} is unavailable.`,
        error.component === "twap" ? "FX_TWAP_UNSUPPORTED" : "FX_MEDIAN_UNSUPPORTED",
      ));
    }
    return apiFailure(error);
  }
}
