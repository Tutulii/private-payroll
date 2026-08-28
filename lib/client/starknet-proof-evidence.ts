import { hash, RpcProvider, type Call } from "starknet";

type ReceiptReader = {
  getTransactionReceipt: (transactionHash: string) => Promise<unknown>;
  callContract?: (call: Call, blockIdentifier?: "latest") => Promise<unknown>;
  getChainId?: () => Promise<string>;
};

export type LiveProofTransactionEvidence = {
  status: "confirmed" | "pending" | "failed" | "unavailable";
  transactionHash: string;
  finalityStatus?: string;
  executionStatus?: string;
  proofStateStatus?: "verified" | "pending" | "mismatch" | "unavailable";
  proofStateValue?: number;
  shardsVerified?: readonly [boolean, boolean];
  checkedAt: string;
};

export type LiveProofStateBinding = {
  chainId: string;
  sealAddress: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  proofVersion: string;
};

const PROOF_COMPLETION_EVENT_SELECTORS = new Set([
  hash.getSelectorFromName("SealedShardVerified"),
  hash.getSelectorFromName("PayrollStateChanged"),
].map((value) => BigInt(value)));

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? value as Record<string, unknown> : {};
}

async function bounded<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error("Starknet proof evidence read timed out.")), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function textField(value: Record<string, unknown>, snake: string, camel: string): string | undefined {
  const field = value[snake] ?? value[camel];
  return typeof field === "string" ? field.toUpperCase() : undefined;
}

function sameFelt(left: unknown, right: string): boolean {
  try {
    return typeof left === "string" && BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

function receiptBindsProofState(
  receipt: Record<string, unknown>,
  binding: LiveProofStateBinding,
  expectedSealAddress: string,
): boolean {
  if (!Array.isArray(receipt.events)) return false;
  return receipt.events.some((candidate) => {
    const event = record(candidate);
    const address = event.from_address ?? event.fromAddress;
    const keys = Array.isArray(event.keys) ? event.keys : [];
    try {
      return sameFelt(address, expectedSealAddress)
        && keys.length >= 3
        && typeof keys[0] === "string"
        && PROOF_COMPLETION_EVENT_SELECTORS.has(BigInt(keys[0]))
        && sameFelt(keys[1], binding.runNullifierHigh)
        && sameFelt(keys[2], binding.runNullifierLow);
    } catch {
      return false;
    }
  });
}

function feltResult(response: unknown, label: string): bigint {
  const candidate = Array.isArray(response)
    ? response[0]
    : Array.isArray(record(response).result)
      ? (record(response).result as unknown[])[0]
      : undefined;
  if (candidate === undefined) throw new Error(`${label} returned no felt.`);
  return BigInt(String(candidate));
}

function proofStateSatisfied(proofVersion: string, status: bigint): boolean {
  const version = BigInt(proofVersion);
  if (version === 1n || version === 2n) return status === 2n || status === 3n;
  if (version === 3n) return status === 4n || status === 5n;
  if (version === 4n) return status === 5n;
  return false;
}

async function verifySealState(
  reader: Required<Pick<ReceiptReader, "callContract" | "getChainId">>,
  binding: LiveProofStateBinding,
  expectedSealAddress: string,
  receipt: Record<string, unknown>,
  timeoutMs: number,
): Promise<Pick<LiveProofTransactionEvidence, "proofStateStatus" | "proofStateValue" | "shardsVerified">> {
  if (BigInt(binding.sealAddress) !== BigInt(expectedSealAddress)) {
    return { proofStateStatus: "mismatch" };
  }
  const connectedChainId = await bounded(reader.getChainId(), timeoutMs);
  if (BigInt(binding.chainId) !== BigInt(connectedChainId)) {
    return { proofStateStatus: "mismatch" };
  }
  if (!receiptBindsProofState(receipt, binding, expectedSealAddress)) {
    return { proofStateStatus: "mismatch" };
  }
  const calldata = [binding.runNullifierHigh, binding.runNullifierLow];
  const [statusResponse, shardZeroResponse, shardOneResponse] = await bounded(Promise.all([
    reader.callContract({ contractAddress: binding.sealAddress, entrypoint: "get_run_status", calldata }, "latest"),
    reader.callContract({ contractAddress: binding.sealAddress, entrypoint: "is_sealed_shard_verified", calldata: [...calldata, "0"] }, "latest"),
    reader.callContract({ contractAddress: binding.sealAddress, entrypoint: "is_sealed_shard_verified", calldata: [...calldata, "1"] }, "latest"),
  ]), timeoutMs);
  const status = feltResult(statusResponse, "PAYO proof state");
  const shardsVerified = [
    feltResult(shardZeroResponse, "PAYO proof shard 0") !== 0n,
    feltResult(shardOneResponse, "PAYO proof shard 1") !== 0n,
  ] as const;
  const hasSealedShardEvidence = shardsVerified.every(Boolean);
  const hasDirectBundleEvidence = shardsVerified.every((value) => !value);
  const verified = proofStateSatisfied(binding.proofVersion, status)
    && (hasSealedShardEvidence || hasDirectBundleEvidence);
  const knownPending = status === 0n || status === 1n;
  return {
    proofStateStatus: verified ? "verified" : knownPending ? "pending" : "mismatch",
    proofStateValue: Number(status),
    shardsVerified,
  };
}

export async function verifyLiveProofTransaction(input: {
  transactionHash: string;
  proofState?: LiveProofStateBinding;
  expectedSealAddress?: string;
  reader?: ReceiptReader;
  now?: Date;
  timeoutMs?: number;
}): Promise<LiveProofTransactionEvidence> {
  const now = input.now ?? new Date();
  const timeoutMs = input.timeoutMs ?? 12_000;
  try {
    const reader = input.reader ?? new RpcProvider({
      nodeUrl: process.env.NEXT_PUBLIC_STARKNET_RPC_URL ?? "https://rpc.starknet.lava.build",
    });
    const response = record(await bounded(reader.getTransactionReceipt(input.transactionHash), timeoutMs));
    const receipt = record(response.value ?? response);
    const finalityStatus = textField(receipt, "finality_status", "finalityStatus")
      ?? textField(response, "finality_status", "finalityStatus");
    const executionStatus = textField(receipt, "execution_status", "executionStatus")
      ?? textField(response, "execution_status", "executionStatus")
      ?? (response.statusReceipt === "REVERTED" ? "REVERTED" : undefined);
    const failed = finalityStatus === "REJECTED" || executionStatus === "REVERTED";
    const confirmed = (finalityStatus === "ACCEPTED_ON_L1" || finalityStatus === "ACCEPTED_ON_L2")
      && executionStatus === "SUCCEEDED";
    let proofStateEvidence: Pick<LiveProofTransactionEvidence, "proofStateStatus" | "proofStateValue" | "shardsVerified"> = {};
    if (confirmed && input.proofState) {
      proofStateEvidence = reader.callContract && reader.getChainId && input.expectedSealAddress
        ? await verifySealState(
            reader as Required<Pick<ReceiptReader, "callContract" | "getChainId">>,
            input.proofState,
            input.expectedSealAddress,
            receipt,
            timeoutMs,
          )
          .catch(() => ({ proofStateStatus: "unavailable" as const }))
        : { proofStateStatus: "unavailable" };
    }
    return {
      status: failed ? "failed" : confirmed ? "confirmed" : "pending",
      transactionHash: input.transactionHash,
      ...(finalityStatus ? { finalityStatus } : {}),
      ...(executionStatus ? { executionStatus } : {}),
      ...proofStateEvidence,
      checkedAt: now.toISOString(),
    };
  } catch {
    return {
      status: "unavailable",
      transactionHash: input.transactionHash,
      checkedAt: now.toISOString(),
    };
  }
}
