import { RpcProvider } from "starknet";
import { replaceIndexedRecoveryEvents } from "@/lib/persistence/chain-indexer-repository";
import { recoverApprovalSubmissionsFromSealEvents } from "@/lib/persistence/settlement-repository";
import { processEventIndexBatch, type StarknetEventIndexerRpc } from "@/lib/server/chain-indexer";
import { authorizeInternalWorker } from "@/lib/server/internal-auth";
import {
  buildRecoveryTailIndexPlan,
  scanRecoveryTailEvents,
} from "@/lib/server/recovery-tail-index";
import { PAYO_RECOVERY_EVENT_SELECTORS } from "@/lib/starknet/payo-event-selectors";

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
  const bookSealAddress = process.env.PAYO_VESTING_BOOK_SEAL_ADDRESS
    ?? process.env.NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS;
  const fromBlock = configuredBlockNumber(process.env.PAYO_INDEX_FROM_BLOCK);
  const batchSize = configuredNumber(process.env.PAYO_INDEX_BATCH_SIZE, 100, 1, 100);
  const finalityLag = configuredNumber(process.env.PAYO_INDEX_FINALITY_LAG, 2, 0, 10_000);
  const prefetchConcurrency = configuredNumber(process.env.PAYO_INDEX_PREFETCH_CONCURRENCY, 4, 1, 16);
  const maxReorgDepth = configuredNumber(process.env.PAYO_INDEX_MAX_REORG_DEPTH, 128, 1, 10_000);
  const recoveryLookback = configuredNumber(
    process.env.PAYO_RECOVERY_INDEX_LOOKBACK_BLOCKS,
    512,
    1,
    10_000,
  );
  if (
    !rpcUrl
    || !contractAddress
    || fromBlock === null
    || batchSize === null
    || finalityLag === null
    || prefetchConcurrency === null
    || maxReorgDepth === null
    || recoveryLookback === null
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
    const rpc: StarknetEventIndexerRpc = {
      getBlockNumber: () => provider.getBlockNumber(),
      getBlockWithTxHashes: (blockNumber) => provider.getBlockWithTxHashes(blockNumber),
      getEvents: (filter) => provider.getEvents(filter),
    };
    const chainId = process.env.PAYO_INDEX_CHAIN_ID ?? "SN_MAIN";
    const baseConsumer = process.env.PAYO_INDEX_CONSUMER ?? "payo-seal";
    const addresses = bookSealAddress
      ? [contractAddress, bookSealAddress]
      : [contractAddress];
    let primaryIndex: Awaited<ReturnType<typeof processEventIndexBatch>> | null = null;
    let primaryFailure: unknown;
    try {
      primaryIndex = await processEventIndexBatch({
        rpc,
        chainId,
        consumer: baseConsumer,
        fromBlock,
        maxBlocks: batchSize,
        finalityLag,
        prefetchConcurrency,
        maxReorgDepth,
        addresses,
        keys: [[...PAYO_RECOVERY_EVENT_SELECTORS]],
      });
    } catch (error) {
      // Recovery is deliberately independent from the historical cursor. Run
      // it even when catch-up or reorg handling fails, then surface the primary
      // failure so worker monitoring still reports it.
      primaryFailure = error;
    }

    const recoveryPlan = buildRecoveryTailIndexPlan({
      configuredFromBlock: fromBlock,
      chainHead: BigInt(await provider.getBlockNumber()),
      finalityLag,
      lookbackBlocks: recoveryLookback,
      addresses,
      selectors: PAYO_RECOVERY_EVENT_SELECTORS,
    });
    const recoveryEvents = await scanRecoveryTailEvents({ rpc, plan: recoveryPlan });
    const recoveryIndex = recoveryPlan.hasRange
      ? await replaceIndexedRecoveryEvents({
          chainId,
          fromBlock: recoveryPlan.fromBlock,
          toBlock: recoveryPlan.toBlock,
          addresses: recoveryPlan.addresses,
          eventNames: recoveryPlan.selectors,
          events: recoveryEvents,
        })
      : { indexed: 0, fromBlock: recoveryPlan.fromBlock, toBlock: recoveryPlan.toBlock };
    const recovery = await recoverApprovalSubmissionsFromSealEvents({
      chainId,
      sealAddress: contractAddress,
      ...(bookSealAddress ? { bookSealAddress } : {}),
    });
    if (primaryFailure) throw primaryFailure;
    if (!primaryIndex) throw new Error("Historical event indexing did not return a result.");
    return Response.json({
      indexed: primaryIndex.indexed,
      recoveryIndexed: recoveryIndex.indexed,
      recoveryFromBlock: recoveryIndex.fromBlock.toString(),
      recoveryToBlock: recoveryIndex.toBlock.toString(),
      recoveredSubmissions: recovery.recovered,
      rolledBack: primaryIndex.rolledBack.toString(),
      headBlockNumber: primaryIndex.headBlockNumber.toString(),
      nextBlockNumber: primaryIndex.nextBlockNumber.toString(),
    });
  } catch (error) {
    console.error("PAYO event indexer failed", error instanceof Error ? error.message : "Unknown indexer failure");
    const code = error instanceof Error && error.message === "REORG_DEPTH_EXCEEDED"
      ? "REORG_DEPTH_EXCEEDED"
      : "INDEXER_FAILURE";
    return Response.json({ error: { code, message: "Event indexing failed closed." } }, { status: 500 });
  }
}
