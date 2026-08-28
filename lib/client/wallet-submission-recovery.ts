const TRANSACTION_HASH = /^0x[0-9a-fA-F]{1,64}$/;

function requireTransactionHash(value: unknown): string {
  if (typeof value !== "string" || !TRANSACTION_HASH.test(value)) {
    throw new Error("Ready submitted without returning a valid transaction hash.");
  }
  return value;
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
  pollIntervalMs?: number;
  timeoutMs?: number;
}): Promise<string> {
  const pollIntervalMs = input.pollIntervalMs ?? 2_000;
  const timeoutMs = input.timeoutMs ?? 20 * 60_000;
  if (!Number.isFinite(pollIntervalMs) || pollIntervalMs < 1) {
    throw new Error("Wallet recovery polling requires a positive interval.");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < pollIntervalMs) {
    throw new Error("Wallet recovery timeout must cover at least one polling interval.");
  }

  let settled = false;
  const recovered = async (): Promise<string> => {
    const deadline = Date.now() + timeoutMs;
    while (!settled && Date.now() < deadline) {
      await wait(pollIntervalMs);
      if (settled) break;
      try {
        const transactionHash = await input.readRecoveredTransactionHash();
        if (transactionHash) return requireTransactionHash(transactionHash);
      } catch {
        // Auth refreshes and transient network failures are retried while Ready
        // remains open. The wallet promise still fails fast on an explicit reject.
      }
    }
    throw new Error(
      "Ready approval is still pending. PAYO will continue recovering the sealed transaction without another signature.",
    );
  };

  try {
    return await Promise.race([
      Promise.resolve().then(input.submit).then(requireTransactionHash),
      recovered(),
    ]);
  } finally {
    settled = true;
  }
}
