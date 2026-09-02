import "server-only";

import { validateAndParseAddress } from "starknet";
import { ApiError } from "./auth";

const CANONICAL_CHAIN_ID = /^(?:0x[0-9a-fA-F]+|[1-9]\d*)$/;

export type PayoDeploymentConfig = {
  chainId: string;
  sealAddress: string;
};

export type PayoRegistryConfig = {
  policyRegistryAddress: string;
  obligationRegistryAddress: string;
};

function configuredAddress(privateName: string, publicName: string, label: string): string {
  const privateValue = process.env[privateName];
  const publicValue = process.env[publicName];
  if (!privateValue && !publicValue) {
    throw new ApiError(503, `${label} is not deployed/configured.`, "PAYO_REGISTRY_NOT_CONFIGURED");
  }
  try {
    const privateAddress = validateAndParseAddress(privateValue ?? publicValue!);
    const publicAddress = validateAndParseAddress(publicValue ?? privateValue!);
    if (BigInt(privateAddress) !== BigInt(publicAddress)) {
      throw new ApiError(503, `${label} server and browser addresses do not match.`, "PAYO_REGISTRY_CONFIG_MISMATCH");
    }
    return privateAddress;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(503, `${label} address is invalid.`, "PAYO_REGISTRY_CONFIG_INVALID");
  }
}

export function getPayoRegistryConfig(): PayoRegistryConfig {
  return {
    policyRegistryAddress: configuredAddress(
      "PAYO_POLICY_REGISTRY_ADDRESS",
      "NEXT_PUBLIC_PAYO_POLICY_REGISTRY_ADDRESS",
      "The PAYO policy registry",
    ),
    obligationRegistryAddress: configuredAddress(
      "PAYO_OBLIGATION_REGISTRY_ADDRESS",
      "NEXT_PUBLIC_PAYO_OBLIGATION_REGISTRY_ADDRESS",
      "The PAYO obligation registry",
    ),
  };
}

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

/**
 * Payroll FX roots are shared by the Ready-approved and bounded-agent paths,
 * but each path is deliberately bound to its own Payroll Seal. Return only
 * server/browser-attested deployments so the FX publisher can accept either
 * proof without accepting a caller-selected seal.
 */
export function getPayoFxProofDeployments(): readonly PayoDeploymentConfig[] {
  const primary = getPayoDeploymentConfig();
  const privateAgentSeal = process.env.PAYO_AGENT_SEAL_ADDRESS?.trim();
  const publicAgentSeal = process.env.NEXT_PUBLIC_PAYO_AGENT_SEAL_ADDRESS?.trim();
  if (!privateAgentSeal && !publicAgentSeal) return [primary];
  if (!privateAgentSeal || !publicAgentSeal) {
    throw new ApiError(
      503,
      "The autonomous PAYO seal server and browser configuration is incomplete.",
      "PAYO_AGENT_SEAL_CONFIG_INCOMPLETE",
    );
  }
  let canonicalPrivateAgent: string;
  let canonicalPublicAgent: string;
  try {
    canonicalPrivateAgent = validateAndParseAddress(privateAgentSeal);
    canonicalPublicAgent = validateAndParseAddress(publicAgentSeal);
  } catch {
    throw new ApiError(
      503,
      "The configured autonomous PAYO seal address is invalid.",
      "PAYO_AGENT_SEAL_CONFIG_INVALID",
    );
  }
  if (BigInt(canonicalPrivateAgent) !== BigInt(canonicalPublicAgent)) {
    throw new ApiError(
      503,
      "Server and browser autonomous PAYO seal addresses do not match.",
      "PAYO_AGENT_SEAL_CONFIG_MISMATCH",
    );
  }
  if (BigInt(canonicalPrivateAgent) === BigInt(primary.sealAddress)) return [primary];
  return [
    primary,
    { chainId: primary.chainId, sealAddress: canonicalPrivateAgent },
  ];
}
