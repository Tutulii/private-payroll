import { num, RpcProvider } from "starknet";
import { STRK20_MAINNET_POOL_ADDRESS } from "@/lib/starknet/deployment";
import {
  convertStrkPoolFeeToToken,
  PAYMASTER_NON_STRK_QUOTE_BUFFER_BPS,
  PAYMASTER_PRICE_SCALE,
} from "@/lib/starknet/strk20-fee";
import { PAYROLL_TOKENS, type PayrollTokenSymbol } from "@/lib/starknet/tokens";

const AVNU_MAINNET_PAYMASTER_URL = "https://starknet.paymaster.avnu.fi";

type PaymasterTokenPrice = {
  token_address: string;
  decimals: number;
  price_in_strk: string;
};

function rpcUrl() {
  const value = process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  if (!value) throw new Error("The Starknet Mainnet RPC is not configured.");
  return value;
}

function sameAddress(left: string, right: string) {
  return num.toBigInt(left) === num.toBigInt(right);
}

async function readPoolFee(): Promise<bigint> {
  const provider = new RpcProvider({ nodeUrl: rpcUrl() });
  const response = await provider.callContract({
    contractAddress: STRK20_MAINNET_POOL_ADDRESS,
    entrypoint: "get_fee_amount",
    calldata: [],
  }, "latest");
  const fee = response[0] ? num.toBigInt(response[0]) : 0n;
  if (fee <= 0n) throw new Error("The STRK20 pool returned no usable fee.");
  return fee;
}

async function readPaymasterTokenPrice(token: PayrollTokenSymbol): Promise<PaymasterTokenPrice> {
  const response = await fetch(AVNU_MAINNET_PAYMASTER_URL, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    cache: "no-store",
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "paymaster_getSupportedTokens",
      params: {},
    }),
  });
  if (!response.ok) throw new Error(`The paymaster price service returned HTTP ${response.status}.`);
  const payload = await response.json() as {
    result?: PaymasterTokenPrice[];
    error?: { message?: string };
  };
  if (payload.error || !Array.isArray(payload.result)) {
    throw new Error(payload.error?.message ?? "The paymaster returned no token prices.");
  }
  const expected = PAYROLL_TOKENS[token];
  const price = payload.result.find((candidate) => sameAddress(candidate.token_address, expected.address));
  if (!price || price.decimals !== expected.decimals || num.toBigInt(price.price_in_strk) <= 0n) {
    throw new Error(`The paymaster returned no valid ${token} price.`);
  }
  return price;
}

export async function GET(request: Request) {
  try {
    const requestedToken = new URL(request.url).searchParams.get("token")?.toUpperCase();
    if (requestedToken !== "STRK" && requestedToken !== "USDC") {
      return Response.json(
        { error: { code: "INVALID_TOKEN", message: "Request a STRK or native-USDC fee quote." } },
        { status: 400 },
      );
    }
    const token: PayrollTokenSymbol = requestedToken;
    const poolFee = await readPoolFee();
    if (token === "STRK") {
      return Response.json({
        token,
        walletFee: poolFee.toString(),
        exact: true,
        source: "pool-onchain",
        quotedAt: Date.now(),
        poolFeeStrk: poolFee.toString(),
      }, { headers: { "cache-control": "no-store" } });
    }

    const price = await readPaymasterTokenPrice(token);
    const walletFee = convertStrkPoolFeeToToken({
      poolFeeStrkAtomic: poolFee,
      tokenDecimals: price.decimals,
      tokenPriceInStrk: num.toBigInt(price.price_in_strk),
      bufferBps: PAYMASTER_NON_STRK_QUOTE_BUFFER_BPS,
    });
    return Response.json({
      token,
      walletFee: walletFee.toString(),
      exact: false,
      source: "paymaster-live-estimate",
      quotedAt: Date.now(),
      poolFeeStrk: poolFee.toString(),
      priceScale: PAYMASTER_PRICE_SCALE.toString(),
      bufferBps: PAYMASTER_NON_STRK_QUOTE_BUFFER_BPS.toString(),
    }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return Response.json({
      error: {
        code: "FEE_QUOTE_UNAVAILABLE",
        message: error instanceof Error ? error.message : "The live STRK20 fee quote is unavailable.",
      },
    }, { status: 503, headers: { "cache-control": "no-store" } });
  }
}
