import "server-only";

import type { SettlementObservation, StarknetReceiptObservation } from "@/lib/domain/settlement";
import { evaluateStarknetReceipt } from "@/lib/domain/settlement";
import {
  applySettlementObservation,
  leaseConfirmationJobs,
  type LeasedConfirmationJob,
} from "@/lib/persistence/settlement-repository";

type RpcRecord = Record<string, unknown>;

export type ConfirmationRpc = {
  getTransactionReceipt: (transactionHash: string) => Promise<unknown>;
  getBlockNumber: () => Promise<number>;
  getBlockWithTxHashes: (blockIdentifier: number) => Promise<unknown>;
};

function record(value: unknown): RpcRecord {
  return value && typeof value === "object" ? value as RpcRecord : {};
}

function textField(value: RpcRecord, snake: string, camel: string): string | undefined {
  const field = value[snake] ?? value[camel];
  return typeof field === "string" ? field : undefined;
}

function bigintField(value: RpcRecord, snake: string, camel: string): bigint | undefined {
  const field = value[snake] ?? value[camel];
  if (typeof field === "bigint") return field;
  if (typeof field === "number" && Number.isSafeInteger(field) && field >= 0) return BigInt(field);
  if (typeof field === "string" && /^(0x[0-9a-fA-F]+|\d+)$/.test(field)) return BigInt(field);
  return undefined;
}

function normalizedFinality(value?: string): StarknetReceiptObservation["finalityStatus"] {
  const status = value?.toUpperCase();
  if (status === "ACCEPTED_ON_L1") return "ACCEPTED_ON_L1";
  if (status === "ACCEPTED_ON_L2") return "ACCEPTED_ON_L2";
  if (status === "PRE_CONFIRMED" || status === "RECEIVED") return "PRE_CONFIRMED";
  if (status === "REJECTED") return "REJECTED";
  return "PENDING";
}

function normalizedExecution(value?: string): StarknetReceiptObservation["executionStatus"] {
  const status = value?.toUpperCase();
  if (status === "SUCCEEDED") return "SUCCEEDED";
  if (status === "REVERTED") return "REVERTED";
  return undefined;
}

export async function observeStarknetTransaction(
  rpc: ConfirmationRpc,
  transactionHash: string,
): Promise<SettlementObservation> {
  try {
    const receiptResponse = record(await rpc.getTransactionReceipt(transactionHash));
    const receipt = record(receiptResponse.value ?? receiptResponse);
    if (receiptResponse.statusReceipt === "ERROR") {
      return { state: "pending", confirmationDepth: 0 };
    }
    const blockNumber = bigintField(receipt, "block_number", "blockNumber");
    const blockHash = textField(receipt, "block_hash", "blockHash");
    let headBlockNumber: bigint | undefined;
    let canonicalBlockHash: string | undefined;
    if (blockNumber !== undefined && blockHash) {
      const [head, canonicalBlock] = await Promise.all([
        rpc.getBlockNumber(),
        rpc.getBlockWithTxHashes(Number(blockNumber)),
      ]);
      headBlockNumber = BigInt(head);
      canonicalBlockHash = textField(record(canonicalBlock), "block_hash", "blockHash");
    }
    return evaluateStarknetReceipt({
      finalityStatus: normalizedFinality(textField(receipt, "finality_status", "finalityStatus")),
      executionStatus: normalizedExecution(
        textField(receipt, "execution_status", "executionStatus")
        ?? (receiptResponse.statusReceipt === "REVERTED" ? "REVERTED" : undefined),
      ),
      transactionHash,
      blockNumber,
      blockHash,
      canonicalBlockHash,
      headBlockNumber,
      revertReason: textField(receipt, "revert_reason", "revertReason"),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message.toUpperCase() : "";
    if (
      message.includes("TRANSACTION_HASH_NOT_FOUND")
      || message.includes("TRANSACTION HASH NOT FOUND")
      || message.includes("NO TRACE AVAILABLE")
    ) {
      return { state: "pending", confirmationDepth: 0 };
    }
    throw error;
  }
}

type ConfirmationBatchDependencies = {
  lease: typeof leaseConfirmationJobs;
  observe: typeof observeStarknetTransaction;
  apply: typeof applySettlementObservation;
};

const defaultDependencies: ConfirmationBatchDependencies = {
  lease: leaseConfirmationJobs,
  observe: observeStarknetTransaction,
  apply: applySettlementObservation,
};

export async function processConfirmationBatch(input: {
  rpc: ConfirmationRpc;
  workerId: string;
  limit?: number;
  now?: Date;
  dependencies?: ConfirmationBatchDependencies;
}) {
  const dependencies = input.dependencies ?? defaultDependencies;
  const now = input.now ?? new Date();
  const jobs = await dependencies.lease(input.workerId, input.limit ?? 10, now);
  const results: Array<{ jobId: string; settlementId: string; state: string }> = [];
  for (const job of jobs) {
    let observation: SettlementObservation;
    try {
      observation = await dependencies.observe(input.rpc, job.transactionHash);
    } catch (error) {
      observation = {
        state: "pending",
        confirmationDepth: 0,
        errorCode: "RPC_TEMPORARY_FAILURE",
        errorMessage: error instanceof Error ? error.message : "Starknet RPC request failed.",
      };
    }
    const result = await dependencies.apply(job as LeasedConfirmationJob, observation, now);
    results.push({ jobId: job.id, settlementId: job.settlementId, state: result.state });
  }
  return { leased: jobs.length, results };
}
