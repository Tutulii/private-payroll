import "server-only";

import { validateAndParseAddress } from "starknet";
import { ApiError } from "./auth";

const CANONICAL_CHAIN_ID = /^(?:0x[0-9a-fA-F]+|[1-9]\d*)$/;

export type PayoDeploymentConfig = {
  chainId: string;
  sealAddress: string;
};

export function getPayoDeploymentConfig(): PayoDeploymentConfig {
  const privateSeal = process.env.PAYO_SEAL_ADDRESS;
  const publicSeal = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS;
  if (!privateSeal || !publicSeal) {
    throw new ApiError(
      503,
      "The proof-bound PAYO seal is not deployed/configured.",
      "PAYO_SEAL_NOT_CONFIGURED",
    );
  }
  let canonicalPrivate: string;
  let canonicalPublic: string;
  try {
    canonicalPrivate = validateAndParseAddress(privateSeal);
    canonicalPublic = validateAndParseAddress(publicSeal);
  } catch {
    throw new ApiError(503, "The configured PAYO seal address is invalid.", "PAYO_SEAL_CONFIG_INVALID");
  }
  if (BigInt(canonicalPrivate) !== BigInt(canonicalPublic)) {
    throw new ApiError(
      503,
      "Server and browser PAYO seal addresses do not match.",
      "PAYO_SEAL_CONFIG_MISMATCH",
    );
  }
  const chainId = process.env.PAYO_CHAIN_ID;
  if (!chainId || !CANONICAL_CHAIN_ID.test(chainId)) {
    throw new ApiError(503, "The PAYO deployment chain ID is not configured.", "PAYO_CHAIN_NOT_CONFIGURED");
  }
  return { chainId, sealAddress: canonicalPrivate };
}
