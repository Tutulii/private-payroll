import "server-only";

import { validateAndParseAddress } from "starknet";
import { ApiError } from "./auth";

const FELT_PRIME = (1n << 251n) + 17n * (1n << 192n) + 1n;

function canonicalAddress(value: string): `0x${string}` {
  return `0x${BigInt(validateAndParseAddress(value)).toString(16)}`;
}

function requiredAddress(name: string, label: string): `0x${string}` {
  const value = process.env[name]?.trim();
  if (!value) throw new ApiError(503, `${label} is not configured.`, "DIRECT_PRIVACY_DEPLOYMENT_INCOMPLETE");
  try {
    return canonicalAddress(value);
  } catch {
    throw new ApiError(503, `${label} is not a canonical Starknet address.`, "DIRECT_PRIVACY_DEPLOYMENT_INVALID");
  }
}

function requiredClassHash(): `0x${string}` {
  const value = process.env.PAYO_AGENT_POLICY_ACCOUNT_CLASS_HASH?.trim();
  try {
    if (!value || !/^0x[0-9a-fA-F]{1,64}$/.test(value)) throw new Error("invalid");
    const parsed = BigInt(value);
    if (parsed <= 0n || parsed >= FELT_PRIME) throw new Error("invalid");
    return `0x${parsed.toString(16)}`;
  } catch {
    throw new ApiError(503, "The reviewed policy-account class hash is not configured.", "DIRECT_PRIVACY_CLASS_HASH_INVALID");
  }
}

export type DirectPrivacyDeploymentConfig = {
  chainId: `0x${string}`;
  sealAddress: `0x${string}`;
  poolAddress: `0x${string}`;
  policyAccountAddress: `0x${string}`;
  policyAccountClassHash: `0x${string}`;
  tokenAddresses: { STRK: `0x${string}`; USDC: `0x${string}` };
};

/** One fail-closed deployment profile shared by provisioning, activation and execution. */
export function getDirectPrivacyDeploymentConfig(): DirectPrivacyDeploymentConfig {
  const chainId = process.env.PAYO_CHAIN_ID?.trim();
  try {
    if (!chainId || BigInt(chainId) <= 0n || BigInt(chainId) >= FELT_PRIME) throw new Error("invalid");
  } catch {
    throw new ApiError(503, "The autonomous Starknet chain is not configured.", "DIRECT_PRIVACY_CHAIN_INVALID");
  }
  return {
    chainId: `0x${BigInt(chainId).toString(16)}`,
    // The autonomous FINALIZE seal is deliberately independent from the
    // Ready/exception seal used by the browser. Changing one must never retarget
    // the other flow.
    sealAddress: requiredAddress("PAYO_AGENT_SEAL_ADDRESS", "The autonomous PAYO Payroll Seal"),
    poolAddress: requiredAddress("PAYO_STRK20_POOL_ADDRESS", "The STRK20 Privacy Pool"),
    policyAccountAddress: requiredAddress(
      "PAYO_AGENT_POLICY_ACCOUNT_ADDRESS",
      "The autonomous PAYO policy account",
    ),
    policyAccountClassHash: requiredClassHash(),
    tokenAddresses: {
      STRK: requiredAddress("PAYO_AGENT_STRK_TOKEN_ADDRESS", "The autonomous STRK token"),
      USDC: requiredAddress("PAYO_AGENT_USDC_TOKEN_ADDRESS", "The autonomous USDC token"),
    },
  };
}
