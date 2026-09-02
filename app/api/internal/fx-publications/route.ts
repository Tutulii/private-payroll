import { Account, RpcProvider, validateAndParseAddress } from "starknet";
import { withStarknetRelayerSubmissionLock } from "@/lib/persistence/relayer-lock";
import { authorizeInternalWorker } from "@/lib/server/internal-auth";
import { getPayoFxProofDeployments, getPayoRegistryConfig } from "@/lib/server/payo-deployment";
import { isFxRootActive } from "@/lib/server/fx-root-publisher";
import { processFxPublicationBatch } from "@/lib/server/fx-publication-worker";

export const runtime = "nodejs";

let verifiedConfigurationAt = 0;
const CONFIGURATION_CACHE_MILLISECONDS = 5 * 60_000;

function resultAddress(response: unknown): string {
  const values = Array.isArray(response)
    ? response.map(String)
    : response && typeof response === "object" && Array.isArray((response as { result?: unknown }).result)
      ? (response as { result: unknown[] }).result.map(String)
      : [];
  if (values.length !== 1) throw new Error("PAYO FX publisher returned an invalid response.");
  return validateAndParseAddress(values[0]);
}

async function requirePublisherConfiguration(input: {
  provider: RpcProvider;
  chainId: string;
  policyRegistryAddress: string;
  relayerAddress: string;
}) {
  const now = Date.now();
  if (now - verifiedConfigurationAt < CONFIGURATION_CACHE_MILLISECONDS) return;
  const [providerChainId, publisherResponse] = await Promise.all([
    input.provider.getChainId(),
    input.provider.callContract({
      contractAddress: input.policyRegistryAddress,
      entrypoint: "get_fx_publisher",
      calldata: [],
    }, "latest"),
  ]);
  if (BigInt(providerChainId) !== BigInt(input.chainId)) {
    throw new Error("The FX publisher RPC is on the wrong chain.");
  }
  if (BigInt(resultAddress(publisherResponse)) !== BigInt(input.relayerAddress)) {
    throw new Error("The configured relayer is not the active PAYO FX publisher.");
  }
  verifiedConfigurationAt = now;
}

export async function POST(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json(
      { error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." } },
      { status: 401 },
    );
  }
  const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  const relayerAddressRaw = process.env.PAYO_PROOF_RELAYER_ADDRESS;
  const relayerPrivateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!rpcUrl || !relayerAddressRaw || !relayerPrivateKey) {
    return Response.json({
      error: { code: "FX_PUBLISHER_NOT_CONFIGURED", message: "The PAYO FX publisher is not configured." },
    }, { status: 503 });
  }

  try {
    const [deployment, ...additionalDeployments] = getPayoFxProofDeployments();
    const registries = getPayoRegistryConfig();
    const relayerAddress = validateAndParseAddress(relayerAddressRaw);
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    await requirePublisherConfiguration({
      provider,
      chainId: deployment.chainId,
      policyRegistryAddress: registries.policyRegistryAddress,
      relayerAddress,
    });
    const rpc = {
      getBlockNumber: () => provider.getBlockNumber(),
      getBlockTimestamp: async (blockNumber: number) => Number((await provider.getBlock(blockNumber)).timestamp),
      getBlockWithTxHashes: (blockNumber: number) => provider.getBlockWithTxHashes(blockNumber),
      getTransactionReceipt: (transactionHash: string) => provider.getTransactionReceipt(transactionHash),
      getEvents: (filter: Parameters<typeof provider.getEvents>[0]) => provider.getEvents(filter),
      callContract: (call: Parameters<typeof provider.callContract>[0], blockIdentifier?: number) =>
        provider.callContract(call, blockIdentifier),
    };
    const account = new Account({
      provider,
      address: relayerAddress,
      signer: relayerPrivateKey,
      cairoVersion: "1",
    });
    const result = await processFxPublicationBatch({
      rpc,
      deployment,
      additionalDeployments,
      policyRegistryAddress: registries.policyRegistryAddress,
      workerId: request.headers.get("x-payo-worker-id") || "payo-fx-publisher",
      limit: 1,
      submitter: {
        submit: ({ job, call }) => withStarknetRelayerSubmissionLock(relayerAddress, async () => {
          if (await isFxRootActive({
            rpc,
            policyRegistryAddress: registries.policyRegistryAddress,
            catalogRoot: job.catalogRoot,
          })) return null;
          const estimate = await account.estimateInvokeFee(call);
          const response = await account.execute(call, { resourceBounds: estimate.resourceBounds });
          return { transactionHash: response.transaction_hash };
        }),
      },
    });
    return Response.json(result);
  } catch {
    return Response.json({
      error: { code: "FX_PUBLISHER_FAILURE", message: "FX publication processing failed closed." },
    }, { status: 500 });
  }
}
