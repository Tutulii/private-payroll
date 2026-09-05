import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import type { PayrollTokenSymbol } from "@/lib/starknet/tokens";

export const PAYO_PRIVATE_EXIT_QUOTE_VERSION = "payo-private-exit-quote-v1" as const;
export const PAYO_PRIVATE_EXIT_ROUTE_ID = "ekubo-strk-usdc-single-hop-v1" as const;

const decimalUintSchema = z.string().regex(/^(0|[1-9][0-9]{0,77})$/);
const positiveDecimalUintSchema = decimalUintSchema.refine((value) => BigInt(value) > 0n, {
  message: "Amount must be greater than zero.",
});
const feltSchema = z.string().regex(/^0x[0-9a-f]{1,64}$/);
const hashSchema = z.string().regex(/^0x[0-9a-f]{64}$/);

export const privateExitPoolKeySchema = z.object({
  token0: feltSchema,
  token1: feltSchema,
  fee: positiveDecimalUintSchema,
  tickSpacing: positiveDecimalUintSchema,
  extension: feltSchema,
}).strict();

export const privateExitQuoteBodySchema = z.object({
  version: z.literal(PAYO_PRIVATE_EXIT_QUOTE_VERSION),
  routeId: z.literal(PAYO_PRIVATE_EXIT_ROUTE_ID),
  chainId: feltSchema,
  privacyMode: z.literal("anonymous-swap-to-open-private-note"),
  fromToken: z.enum(["STRK", "USDC"]),
  toToken: z.enum(["STRK", "USDC"]),
  amountInAtomic: positiveDecimalUintSchema,
  expectedOutAtomic: positiveDecimalUintSchema,
  minimumOutAtomic: positiveDecimalUintSchema,
  slippageBps: z.number().int().min(10).max(500),
  priceImpact: z.number().finite().min(0).max(1),
  quoteBlockNumber: z.number().int().positive(),
  quoteBlockHash: hashSchema,
  quotedAt: z.number().int().positive(),
  expiresAt: z.number().int().positive(),
  executorAddress: feltSchema,
  executorClassHash: feltSchema,
  routerAddress: feltSchema,
  pool: privateExitPoolKeySchema,
  skipAhead: decimalUintSchema,
}).strict().superRefine((quote, context) => {
  if (quote.fromToken === quote.toToken) {
    context.addIssue({ code: "custom", path: ["toToken"], message: "Swap tokens must differ." });
  }
  if (BigInt(quote.minimumOutAtomic) > BigInt(quote.expectedOutAtomic)) {
    context.addIssue({
      code: "custom",
      path: ["minimumOutAtomic"],
      message: "Minimum output cannot exceed the expected output.",
    });
  }
  if (quote.expiresAt <= quote.quotedAt) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "Quote expiry is invalid." });
  }
});

export type PrivateExitQuoteBody = z.infer<typeof privateExitQuoteBodySchema>;

export const privateExitQuoteSchema = privateExitQuoteBodySchema.extend({
  routeCommitment: hashSchema,
}).strict();

export type PrivateExitQuote = z.infer<typeof privateExitQuoteSchema>;

export type PrivateExitBoundary = {
  kind: "private_swap" | "private_transfer" | "public_withdrawal" | "unsupported";
  title: string;
  privacyPreserved: boolean;
  executable: boolean;
  disclosure: string;
};

export const PRIVATE_EXIT_BOUNDARIES: readonly PrivateExitBoundary[] = [
  {
    kind: "private_swap",
    title: "Swap inside STRK20",
    privacyPreserved: true,
    executable: true,
    disclosure: "The source account and resulting note stay shielded. Ekubo still observes the anonymous swap amount and pool route.",
  },
  {
    kind: "private_transfer",
    title: "Send to a registered private account",
    privacyPreserved: true,
    executable: false,
    disclosure: "The recipient receives an encrypted STRK20 note. Use PAYO payroll or remediation for this route.",
  },
  {
    kind: "public_withdrawal",
    title: "Withdraw to a public address",
    privacyPreserved: false,
    executable: true,
    disclosure: "The recipient, token and amount become publicly linkable on Starknet. PAYO cannot protect funds after this exit.",
  },
  {
    kind: "unsupported",
    title: "Bridge or unsupported exchange",
    privacyPreserved: false,
    executable: false,
    disclosure: "PAYO will not label an unsupported destination private. Use a reviewed private route or explicitly withdraw publicly first.",
  },
] as const;

export function commitPrivateExitQuote(body: PrivateExitQuoteBody): `0x${string}` {
  const parsed = privateExitQuoteBodySchema.parse(body);
  return hashCanonicalJson({ domain: "PAYO_PRIVATE_EXIT_QUOTE_V1", quote: parsed });
}

export function sealPrivateExitQuote(body: PrivateExitQuoteBody): PrivateExitQuote {
  const parsed = privateExitQuoteBodySchema.parse(body);
  return privateExitQuoteSchema.parse({ ...parsed, routeCommitment: commitPrivateExitQuote(parsed) });
}

export function assertPrivateExitQuoteIntegrity(
  input: unknown,
  now = Date.now(),
): PrivateExitQuote {
  const quote = privateExitQuoteSchema.parse(input);
  const { routeCommitment, ...body } = quote;
  if (routeCommitment !== commitPrivateExitQuote(body)) {
    throw new Error("The private-exit quote commitment does not match its route.");
  }
  if (now < quote.quotedAt - 5_000) {
    throw new Error("The private-exit quote was created in the future.");
  }
  if (now > quote.expiresAt) {
    throw new Error("The private-exit quote expired. Request a fresh quote.");
  }
  return quote;
}

export function oppositePrivateExitToken(token: PayrollTokenSymbol): PayrollTokenSymbol {
  return token === "STRK" ? "USDC" : "STRK";
}
