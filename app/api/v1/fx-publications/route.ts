import { Account, RpcProvider, constants, num, validateAndParseAddress } from "starknet";
import { z } from "zod";
import { requireOrganizationRole } from "@/lib/persistence/repository";
import { withStarknetRelayerSubmissionLock } from "@/lib/persistence/relayer-lock";
import { PAYO_MAX_PROOF_CALLDATA_FELTS } from "@/lib/proof/protocol";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { verifyFxPublicationTicket } from "@/lib/server/fx-publication-ticket";
import { isFxRootActive, verifyFxPublicationProof } from "@/lib/server/fx-root-publisher";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig, getPayoRegistryConfig } from "@/lib/server/payo-deployment";
import { prepareFxRootPublication } from "@/lib/starknet/payo-registry";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const proofFeltSchema = z.string().regex(/^0x[0-9a-fA-F]+$/);
const requestSchema = z.object({
  organizationId: z.string().uuid(),
  catalogRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  publicationTicket: z.string().min(32).max(8_000),
  proofVersion: z.union([z.literal(1), z.literal(2)]),
  shards: z.tuple([
    z.array(proofFeltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    z.array(proofFeltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
  ]),
}).strict();

function singleAddress(response: unknown, label: string): string {
  const values = Array.isArray(response)
    ? response.map(String)
    : response && typeof response === "object" && Array.isArray((response as { result?: unknown }).result)
      ? (response as { result: unknown[] }).result.map(String)
      : [];
  if (values.length !== 1) throw new ApiError(502, `${label} returned an invalid response.`, "FX_REGISTRY_INVALID");
  return validateAndParseAddress(values[0]);
}

export async function POST(request: Request) {
  try {
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > 2_500_000) {
      throw new ApiError(413, "The FX proof request is too large.", "FX_PROOF_TOO_LARGE");
    }
    const authenticated = await requirePrincipal(request);
    const input = requestSchema.parse(await readJson(request));
    await requireOrganizationRole(input.organizationId, authenticated, ["admin", "operator"]);
    const deployment = getPayoDeploymentConfig();
    const registries = getPayoRegistryConfig();
    const ticket = verifyFxPublicationTicket(input.publicationTicket, {
      organizationId: input.organizationId,
      principalId: authenticated.principalId,
      chainId: deployment.chainId,
      registryAddress: registries.policyRegistryAddress,
      catalogRoot: input.catalogRoot,
    });
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    const relayerAddressRaw = process.env.PAYO_PROOF_RELAYER_ADDRESS;
    const relayerPrivateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
    if (!rpcUrl || !relayerAddressRaw || !relayerPrivateKey) {
      throw new ApiError(503, "The trusted PAYO FX publisher is not configured.", "FX_PUBLISHER_NOT_CONFIGURED");
    }
    const relayerAddress = validateAndParseAddress(relayerAddressRaw);
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const chainId = await provider.getChainId();
    if (BigInt(chainId) !== BigInt(constants.StarknetChainId.SN_MAIN)
      || BigInt(chainId) !== BigInt(deployment.chainId)) {
      throw new ApiError(503, "The FX publisher RPC is on the wrong chain.", "FX_PUBLISHER_CHAIN_MISMATCH");
    }
    const rpc = {
      getBlockNumber: () => provider.getBlockNumber(),
      getBlockTimestamp: async (blockNumber: number) => Number((await provider.getBlock(blockNumber)).timestamp),
      callContract: (call: Parameters<typeof provider.callContract>[0], blockIdentifier?: number) =>
        provider.callContract(call, blockIdentifier),
    };
    if (await isFxRootActive({
      rpc,
      policyRegistryAddress: registries.policyRegistryAddress,
      catalogRoot: input.catalogRoot,
    })) {
      return Response.json({ catalogRoot: input.catalogRoot, alreadyActive: true, transactionHash: null });
    }
    try {
      await verifyFxPublicationProof({
        rpc,
        deployment,
        policyRegistryAddress: registries.policyRegistryAddress,
        catalogRoot: input.catalogRoot,
        proofVersion: input.proofVersion,
        shards: input.shards,
      });
    } catch (error) {
      throw new ApiError(
        422,
        error instanceof Error ? error.message : "The payroll proof did not authorize this FX root.",
        "FX_PUBLICATION_PROOF_INVALID",
      );
    }
    const publisher = singleAddress(await provider.callContract({
      contractAddress: registries.policyRegistryAddress,
      entrypoint: "get_fx_publisher",
      calldata: [],
    }, "latest"), "PAYO FX publisher");
    if (BigInt(publisher) !== BigInt(relayerAddress)) {
      throw new ApiError(503, "The configured relayer is not the active PAYO FX publisher.", "FX_PUBLISHER_MISMATCH");
    }
    const account = new Account({
      provider,
      address: relayerAddress,
      signer: relayerPrivateKey,
      cairoVersion: "1",
    });
    const submitted = await withStarknetRelayerSubmissionLock(relayerAddress, async () => {
      if (await isFxRootActive({
        rpc,
        policyRegistryAddress: registries.policyRegistryAddress,
        catalogRoot: input.catalogRoot,
      })) return null;
      const latest = await provider.getBlock("latest");
      const call = prepareFxRootPublication({
        registryAddress: registries.policyRegistryAddress,
        fxRoot: input.catalogRoot,
        observedAt: ticket.observedAt,
        maximumAgeSeconds: ticket.maximumAgeSeconds,
        blockTimestamp: Number(latest.timestamp),
      });
      const estimate = await account.estimateInvokeFee(call);
      const response = await account.execute(call, { resourceBounds: estimate.resourceBounds });
      return response.transaction_hash;
    });
    if (!submitted) {
      return Response.json({ catalogRoot: input.catalogRoot, alreadyActive: true, transactionHash: null });
    }
    await provider.waitForTransaction(submitted, { retries: 200, retryInterval: 3_000 });
    if (!await isFxRootActive({
      rpc,
      policyRegistryAddress: registries.policyRegistryAddress,
      catalogRoot: input.catalogRoot,
    })) {
      throw new ApiError(502, "The FX publication confirmed but its root is not active.", "FX_PUBLICATION_NOT_ACTIVE");
    }
    return Response.json({
      catalogRoot: input.catalogRoot,
      alreadyActive: false,
      transactionHash: num.toHex(BigInt(submitted)),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
