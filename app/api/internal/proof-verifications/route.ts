import { Account, RpcProvider } from "starknet";
import { authorizeInternalWorker } from "@/lib/server/internal-auth";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";
import { processProofVerificationBatch } from "@/lib/server/proof-relayer";
import { withStarknetRelayerSubmissionLock } from "@/lib/persistence/relayer-lock";

export const runtime = "nodejs";

let verifiedChainIdAt = 0;
const CHAIN_ID_CACHE_MILLISECONDS = 5 * 60 * 1_000;

async function requireConfiguredChain(provider: RpcProvider, expectedChainId: string) {
  const now = Date.now();
  if (now - verifiedChainIdAt < CHAIN_ID_CACHE_MILLISECONDS) return true;
  const providerChainId = await provider.getChainId();
  if (BigInt(providerChainId) !== BigInt(expectedChainId)) return false;
  verifiedChainIdAt = now;
  return true;
}

export async function POST(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json(
      { error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." } },
      { status: 401 },
    );
  }
  const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  const relayerAddress = process.env.PAYO_PROOF_RELAYER_ADDRESS;
  const relayerPrivateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!rpcUrl || !relayerAddress || !relayerPrivateKey) {
    return Response.json({
      error: {
        code: "PROOF_RELAYER_NOT_CONFIGURED",
        message: "The Starknet proof relayer is not configured.",
      },
    }, { status: 503 });
  }

  try {
    const deployment = getPayoDeploymentConfig();
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    if (!(await requireConfiguredChain(provider, deployment.chainId))) {
      return Response.json({
        error: { code: "PROOF_RELAYER_CHAIN_MISMATCH", message: "The relayer RPC is on the wrong chain." },
      }, { status: 503 });
    }
    const account = new Account({
      provider,
      address: relayerAddress,
      signer: relayerPrivateKey,
    });
    const result = await processProofVerificationBatch({
      rpc: {
        callContract: (call, blockIdentifier) => provider.callContract(call, blockIdentifier),
        getTransactionReceipt: (transactionHash) => provider.getTransactionReceipt(transactionHash),
        getBlockNumber: () => provider.getBlockNumber(),
        getBlockWithTxHashes: (blockNumber) => provider.getBlockWithTxHashes(blockNumber),
      },
      submitter: {
        submit: (call) => withStarknetRelayerSubmissionLock(relayerAddress, async () => {
          const response = await account.execute(call);
          return { transactionHash: response.transaction_hash };
        }),
      },
      deployment,
      workerId: request.headers.get("x-payo-worker-id") || "payo-proof-relayer",
      limit: 2,
    });
    return Response.json(result);
  } catch {
    return Response.json({
      error: { code: "PROOF_RELAYER_FAILURE", message: "Proof relay processing failed closed." },
    }, { status: 500 });
  }
}
