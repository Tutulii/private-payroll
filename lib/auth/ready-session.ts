import { hash, num, validateAndParseAddress, type TypedData } from "starknet";
import { z } from "zod";

export const READY_AUTH_CHAIN_ID = "0x534e5f4d41494e" as const;
export const READY_AUTH_CHALLENGE_TTL_SECONDS = 5 * 60;

export const readyWalletAddressSchema = z.string().transform((value, context) => {
  try {
    return validateAndParseAddress(value);
  } catch {
    context.addIssue({ code: "custom", message: "A valid Starknet wallet address is required." });
    return z.NEVER;
  }
});

export const readySignatureSchema = z.array(
  z.string().regex(/^0x[0-9a-fA-F]+$/, "A Starknet felt signature is required."),
).min(2).max(64);

export const readyAuthChallengeRequestSchema = z.object({
  walletAddress: readyWalletAddressSchema,
  chainId: z.literal(READY_AUTH_CHAIN_ID),
}).strict();

export const readyAuthVerificationRequestSchema = z.object({
  challengeId: z.string().uuid(),
  signature: readySignatureSchema,
}).strict();

export const readyRecoveryLinkRequestSchema = z.object({
  organizationId: z.string().min(8).max(128),
  legacyPrincipalId: z.string().min(1).max(160),
}).strict();

export const readyRecoveryLinkCompletionSchema = z.object({
  challengeId: z.string().uuid(),
  proof: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
}).strict();

export const readySessionPayloadSchema = z.object({
  accessToken: z.string().min(32).max(512),
  principalId: z.string().min(1).max(160),
  walletAddress: readyWalletAddressSchema,
  chainId: z.literal(READY_AUTH_CHAIN_ID),
  expiresAt: z.string().datetime(),
}).strict();
export type ReadySessionPayload = z.infer<typeof readySessionPayloadSchema>;

export function readyWalletPrincipalId(chainId: string, walletAddress: string): string {
  return `starknet:${chainId}:${validateAndParseAddress(walletAddress)}`;
}

export function buildReadyAuthTypedData(input: {
  walletAddress: string;
  nonce: string;
  audience: string;
  issuedAt: number;
  expiresAt: number;
}): TypedData {
  const walletAddress = validateAndParseAddress(input.walletAddress);
  const audienceHash = num.toHex(hash.starknetKeccak(input.audience));
  return {
    types: {
      StarkNetDomain: [
        { name: "name", type: "felt" },
        { name: "version", type: "felt" },
        { name: "chainId", type: "felt" },
      ],
      PayoSession: [
        { name: "statement", type: "felt" },
        { name: "wallet", type: "felt" },
        { name: "challenge", type: "felt" },
        { name: "audience", type: "felt" },
        { name: "issued_at", type: "felt" },
        { name: "expires_at", type: "felt" },
      ],
    },
    primaryType: "PayoSession",
    domain: {
      name: "PAYO",
      version: "1",
      chainId: "SN_MAIN",
    },
    message: {
      statement: "Sign in to PAYO",
      wallet: walletAddress,
      challenge: input.nonce,
      audience: audienceHash,
      issued_at: input.issuedAt,
      expires_at: input.expiresAt,
    },
  };
}
