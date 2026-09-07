const TRANSACTION_HASH = /^0x[0-9a-fA-F]{1,64}$/;

const DEFINITIVE_WALLET_ERROR_CODES = new Set([
  "111", // NOT_ERC20
  "112", // UNLISTED_NETWORK
  "113", // USER_REFUSED_OP
  "114", // INVALID_REQUEST_PAYLOAD
  "117", // CHAIN_ID_NOT_SUPPORTED
  "118", // NOT_REGISTERED
  "119", // INSUFFICIENT_PRIVATE_BALANCE
  "120", // PRIVACY_LEAK
  "162", // API_VERSION_NOT_SUPPORTED
  "4001", // EIP-1193 user rejection
  "4100", // EIP-1193 unauthorized
  "4200", // EIP-1193 unsupported method
  "-32601", // JSON-RPC method not found
  "-32602", // JSON-RPC invalid params
]);

const DEFINITIVE_WALLET_ERROR_NAMES = [
  "NOT_ERC20",
  "UNLISTED_NETWORK",
  "USER_REFUSED_OP",
  "USER REJECTED",
  "USER_REJECTED",
  "USER DENIED",
  "USER_DENIED",
  "INVALID_REQUEST_PAYLOAD",
  "CHAIN_ID_NOT_SUPPORTED",
  "NOT_REGISTERED",
  "INSUFFICIENT_PRIVATE_BALANCE",
  "PRIVACY_LEAK",
  "API_VERSION_NOT_SUPPORTED",
  "METHOD_NOT_FOUND",
  "METHOD NOT FOUND",
  "UNSUPPORTED METHOD",
] as const;

function walletErrorDetails(error: unknown): { codes: Set<string>; text: string } {
  const codes = new Set<string>();
  const messages: string[] = [];
  const seen = new WeakSet<object>();

  const visit = (value: unknown, depth: number) => {
    if (depth > 4 || value === null || value === undefined) return;
    if (typeof value === "string") {
      messages.push(value);
      return;
    }
    if (typeof value === "number" || typeof value === "bigint") {
      messages.push(String(value));
      return;
    }
    if (typeof value !== "object" || seen.has(value)) return;
    seen.add(value);
    const candidate = value as Record<string, unknown>;
    if (typeof candidate.code === "string" || typeof candidate.code === "number") {
      codes.add(String(candidate.code));
    }
    for (const key of ["message", "name", "data", "cause", "error"] as const) {
      visit(candidate[key], depth + 1);
    }
  };

  visit(error, 0);
  return { codes, text: messages.join(" ").toUpperCase() };
}

/**
 * Only errors which prove that the wallet did not submit may stop canonical
 * recovery. Ready can report a generic timeout/UNKNOWN_ERROR after broadcast;
 * treating that as a failed payment can invite a duplicate payroll.
 */
export function isDefinitiveWalletNonSubmission(error: unknown): boolean {
  const { codes, text } = walletErrorDetails(error);
  if ([...codes].some((code) => DEFINITIVE_WALLET_ERROR_CODES.has(code))) return true;
  return DEFINITIVE_WALLET_ERROR_NAMES.some((name) => text.includes(name));
}

function requireTransactionHash(value: unknown): string {
  if (typeof value !== "string" || !TRANSACTION_HASH.test(value)) {
    throw new Error("Ready submitted without returning a valid transaction hash.");
  }
  return `0x${BigInt(value).toString(16)}`;
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, milliseconds));
}

export async function readRecoveredSettlementTransactionHash(
  client: {
    getSettlement: (settlementId: string) => Promise<{ settlement: Record<string, unknown> }>;
  },
  settlementId: string,
): Promise<string | null> {
  const { settlement } = await client.getSettlement(settlementId);
  return typeof settlement.transactionHash === "string"
    ? requireTransactionHash(settlement.transactionHash)
    : null;
}

export async function awaitWalletOrRecoveredTransaction(input: {
  submit: () => Promise<string>;
  readRecoveredTransactionHash: () => Promise<string | null | undefined>;
  onRecoveryPolling?: () => void | Promise<void>;
  onRecoveredTransactionHash?: (transactionHash: string) => void | Promise<void>;
  pollIntervalMs?: number;
  timeoutMs?: number;
  recoveryNoticeDelayMs?: number;
}): Promise<string> {
  const pollIntervalMs = input.pollIntervalMs ?? 2_000;
  const timeoutMs = input.timeoutMs ?? 20 * 60_000;
  const recoveryNoticeDelayMs = input.recoveryNoticeDelayMs
    ?? Math.min(15_000, Math.max(0, timeoutMs - pollIntervalMs));
  if (!Number.isFinite(pollIntervalMs) || pollIntervalMs < 1) {
    throw new Error("Wallet recovery polling requires a positive interval.");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < pollIntervalMs) {
    throw new Error("Wallet recovery timeout must cover at least one polling interval.");
  }
  if (
    !Number.isFinite(recoveryNoticeDelayMs)
    || recoveryNoticeDelayMs < 0
    || recoveryNoticeDelayMs > timeoutMs
  ) throw new Error("Wallet recovery notice delay must fit inside the polling window.");

  let settled = false;
  let recoveryPollingNotified = false;
  const notifyRecoveryPolling = async () => {
    if (recoveryPollingNotified) return;
    recoveryPollingNotified = true;
    try {
      await input.onRecoveryPolling?.();
    } catch {
      // Display callbacks must never interrupt canonical transaction recovery.
    }
  };
  const recovered = async (): Promise<string> => {
    const startedAt = Date.now();
    const deadline = Date.now() + timeoutMs;
    while (!settled && Date.now() < deadline) {
      await wait(pollIntervalMs);
      if (settled) break;
      if (!recoveryPollingNotified && Date.now() - startedAt >= recoveryNoticeDelayMs) {
        await notifyRecoveryPolling();
      }
      try {
        const transactionHash = await input.readRecoveredTransactionHash();
        if (transactionHash) {
          const canonicalHash = requireTransactionHash(transactionHash);
          try {
            await input.onRecoveredTransactionHash?.(canonicalHash);
          } catch {
            // The durable hash remains authoritative if a browser-only state
            // callback fails; the caller will still finish recording it.
          }
          return canonicalHash;
        }
      } catch {
        // Auth refreshes and transient network failures are retried while Ready
        // remains open. Definitive wallet rejection still fails independently.
      }
    }
    throw new Error(
      "Ready approval is still pending. PAYO will continue recovering the sealed transaction without another signature.",
    );
  };

  const submitted = Promise.resolve()
    .then(input.submit)
    .then(requireTransactionHash)
    .catch(async (error: unknown) => {
      if (isDefinitiveWalletNonSubmission(error)) throw error;
      // A timeout, UNKNOWN_ERROR, transport loss, or malformed post-submit
      // response does not prove the transaction was never broadcast. Keep the
      // durable on-chain recovery race alive instead of inviting a second pay.
      await notifyRecoveryPolling();
      return new Promise<string>(() => undefined);
    });

  try {
    return await Promise.race([submitted, recovered()]);
  } finally {
    settled = true;
  }
}
