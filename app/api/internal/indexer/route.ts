import { RpcProvider } from "starknet";
import { processEventIndexBatch } from "@/lib/server/chain-indexer";
import { authorizeInternalWorker } from "@/lib/server/internal-auth";

export const runtime = "nodejs";

function configuredBlockNumber(value: string | undefined): bigint | null {
  if (!value || !/^\d+$/.test(value)) return null;
  return BigInt(value);
}

function configuredNumber(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number | null {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null;
}

export async function POST(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json({ error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." } }, { status: 401 });
  }
  const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  const contractAddress = process.env.PAYO_INDEX_CONTRACT_ADDRESS;
  const fromBlock = configuredBlockNumber(process.env.PAYO_INDEX_FROM_BLOCK);
  const batchSize = configuredNumber(process.env.PAYO_INDEX_BATCH_SIZE, 100, 1, 100);
  const finalityLag = configuredNumber(process.env.PAYO_INDEX_FINALITY_LAG, 2, 0, 10_000);
  const prefetchConcurrency = configuredNumber(process.env.PAYO_INDEX_PREFETCH_CONCURRENCY, 4, 1, 16);
  const maxReorgDepth = configuredNumber(process.env.PAYO_INDEX_MAX_REORG_DEPTH, 128, 1, 10_000);
  if (
    !rpcUrl
    || !contractAddress
    || fromBlock === null
    || batchSize === null
    || finalityLag === null
    || prefetchConcurrency === null
    || maxReorgDepth === null
  ) {
    return Response.json({
      error: {
        code: "INDEXER_NOT_CONFIGURED",
        message: "The event indexer configuration is missing or outside its safe bounds.",
      },
    }, { status: 503 });
  }
  try {
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const result = await processEventIndexBatch({
      rpc: {
        getBlockNumber: () => provider.getBlockNumber(),
        getBlockWithTxHashes: (blockNumber) => provider.getBlockWithTxHashes(blockNumber),
        getEvents: (filter) => provider.getEvents(filter),
      },
      chainId: process.env.PAYO_INDEX_CHAIN_ID ?? "SN_MAIN",
      consumer: process.env.PAYO_INDEX_CONSUMER ?? "payo-seal",
      fromBlock,
      maxBlocks: batchSize,
      finalityLag,
      prefetchConcurrency,
      maxReorgDepth,
      address: contractAddress,
    });
    return Response.json({
      ...result,
      rolledBack: result.rolledBack.toString(),
      headBlockNumber: result.headBlockNumber.toString(),
      nextBlockNumber: result.nextBlockNumber.toString(),
    });
  } catch (error) {
    console.error("PAYO event indexer failed", error instanceof Error ? error.message : "Unknown indexer failure");
    const code = error instanceof Error && error.message === "REORG_DEPTH_EXCEEDED"
      ? "REORG_DEPTH_EXCEEDED"
      : "INDEXER_FAILURE";
    return Response.json({ error: { code, message: "Event indexing failed closed." } }, { status: 500 });
  }
}
