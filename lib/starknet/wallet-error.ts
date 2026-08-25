const MAX_DETAIL_LENGTH = 1_200;
const MAX_DETAIL_DEPTH = 4;

function renderDetail(value: unknown, depth: number, seen: WeakSet<object>): string {
  if (value === null) return "null";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return String(value);
  }
  if (typeof value === "undefined") return "undefined";
  if (typeof value === "symbol" || typeof value === "function") return String(value);
  if (depth >= MAX_DETAIL_DEPTH) return "[nested detail]";
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[circular]";
  seen.add(value);

  if (value instanceof Error) {
    const candidate = value as Error & { code?: unknown; data?: unknown; cause?: unknown };
    const fields = [
      candidate.message,
      candidate.code === undefined ? "" : `code=${renderDetail(candidate.code, depth + 1, seen)}`,
      candidate.data === undefined ? "" : `data=${renderDetail(candidate.data, depth + 1, seen)}`,
      candidate.cause === undefined ? "" : `cause=${renderDetail(candidate.cause, depth + 1, seen)}`,
    ].filter(Boolean);
    return fields.join("; ");
  }

  if (Array.isArray(value)) {
    return `[${value.map((entry) => renderDetail(entry, depth + 1, seen)).join(", ")}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return "{}";
  return `{${entries
    .map(([key, entry]) => `${key}: ${renderDetail(entry, depth + 1, seen)}`)
    .join(", ")}}`;
}

function boundedDetail(value: unknown): string {
  const rendered = renderDetail(value, 0, new WeakSet());
  if (rendered.length <= MAX_DETAIL_LENGTH) return rendered;
  return `${rendered.slice(0, MAX_DETAIL_LENGTH - 1)}…`;
}

/**
 * Preserve structured Wallet API error data without exposing an Error stack.
 * Ready sometimes nests the actionable Starknet/paymaster failure inside
 * `data`, `cause`, or an inner `error`; reducing it to the outer message hides
 * the only useful diagnostic.
 */
export function describeWalletError(error: unknown): string {
  if (typeof error === "string") return error;
  if (!error || typeof error !== "object") return "The wallet did not complete the request.";

  const candidate = error as {
    code?: unknown;
    message?: unknown;
    data?: unknown;
    cause?: unknown;
    error?: { code?: unknown; message?: unknown; data?: unknown; cause?: unknown };
  };
  const inner = candidate.error;
  const message = candidate.message ?? inner?.message;
  const code = candidate.code ?? inner?.code;
  const data = candidate.data ?? inner?.data;
  const cause = candidate.cause ?? inner?.cause;

  const headline = typeof message === "string" && message.trim()
    ? message.trim()
    : typeof code === "string" || typeof code === "number"
      ? "Wallet request failed"
      : error instanceof Error && error.message
        ? error.message
        : "The wallet did not complete the request.";
  const codeSuffix = typeof code === "string" || typeof code === "number"
    ? ` (${String(code)})`
    : "";
  const detailParts = [data, cause]
    .filter((value) => value !== undefined)
    .map(boundedDetail)
    .filter((value, index, values) => value && values.indexOf(value) === index);

  return `${headline}${codeSuffix}${detailParts.length > 0 ? `: ${detailParts.join("; caused by ")}` : ""}`;
}
