import { quotePrivateExit } from "@/lib/server/private-exit-quote";
import type { PayrollTokenSymbol } from "@/lib/starknet/tokens";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ATOMIC_PATTERN = /^[1-9][0-9]{0,77}$/;

export async function GET(request: Request) {
  const parameters = new URL(request.url).searchParams;
  const from = parameters.get("from")?.toUpperCase();
  const to = parameters.get("to")?.toUpperCase();
  const amountAtomic = parameters.get("amountAtomic") ?? "";
  const slippageRaw = parameters.get("slippageBps") ?? "100";
  const slippageBps = Number(slippageRaw);
  if (
    (from !== "STRK" && from !== "USDC")
    || (to !== "STRK" && to !== "USDC")
    || from === to
    || !ATOMIC_PATTERN.test(amountAtomic)
    || !/^[0-9]{1,4}$/.test(slippageRaw)
    || !Number.isInteger(slippageBps)
    || slippageBps < 10 || slippageBps > 500
  ) {
    return Response.json({
      error: {
        code: "PRIVATE_EXIT_INPUT_INVALID",
        message: "Request different STRK/USDC tokens, a positive atomic amount and valid slippage.",
      },
    }, { status: 400, headers: { "cache-control": "no-store" } });
  }

  try {
    const quote = await quotePrivateExit({
      fromToken: from as PayrollTokenSymbol,
      toToken: to as PayrollTokenSymbol,
      amountAtomic: BigInt(amountAtomic),
      slippageBps,
    });
    return Response.json({ quote }, {
      status: 200,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return Response.json({
      error: {
        code: "PRIVATE_EXIT_QUOTE_UNAVAILABLE",
        message: error instanceof Error ? error.message : "The private swap quote is unavailable.",
      },
    }, { status: 503, headers: { "cache-control": "no-store" } });
  }
}
