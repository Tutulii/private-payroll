import "server-only";

import { num, validateAndParseAddress, type Call } from "starknet";
import { splitHashToU128 } from "@/lib/crypto/commitments";
import { STRK20_MAINNET_POOL_ADDRESS } from "@/lib/starknet/deployment";
import {
  payoReadinessRequestSchema,
  type PayoReadinessCheck,
  type PayoReadinessRequest,
  type PayoReadinessResult,
} from "@/lib/starknet/readiness";
import type { PayoDeploymentConfig } from "./payo-deployment";

export type PayoReadinessRpc = {
  getChainId: () => Promise<string>;
  getBlockNumber: () => Promise<number>;
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

function responseFelts(response: unknown): string[] {
  if (Array.isArray(response)) return response.map(String);
  if (response && typeof response === "object" && Array.isArray((response as { result?: unknown }).result)) {
    return (response as { result: unknown[] }).result.map(String);
  }
  throw new Error("The PAYO deployment returned an invalid contract response.");
}

async function readFelt(rpc: PayoReadinessRpc, call: Call, blockNumber: number): Promise<string> {
  const values = responseFelts(await rpc.callContract(call, blockNumber));
  if (values.length !== 1) throw new Error(`${call.entrypoint} returned an unexpected response.`);
  return num.toHex(BigInt(values[0]));
}

async function readBool(rpc: PayoReadinessRpc, call: Call, blockNumber: number): Promise<boolean> {
  const value = BigInt(await readFelt(rpc, call, blockNumber));
  if (value !== 0n && value !== 1n) throw new Error(`${call.entrypoint} returned a non-boolean value.`);
  return value === 1n;
}

function rootCalldata(root: string): string[] {
  const { high, low } = splitHashToU128(root);
  return [num.toHex(high), num.toHex(low)];
}

function check(code: PayoReadinessCheck["code"], ready: boolean, message: string): PayoReadinessCheck {
  return { code, ready, message };
}

/** Reads every binding at one block so a mixed-state registry update cannot pass preflight. */
export async function checkPayoDeploymentReadiness(input: {
  request: PayoReadinessRequest;
  deployment: PayoDeploymentConfig;
  rpc: PayoReadinessRpc;
}): Promise<PayoReadinessResult> {
  const request = payoReadinessRequestSchema.parse(input.request);
  const requestedSeal = validateAndParseAddress(request.sealAddress);
  const configuredSeal = validateAndParseAddress(input.deployment.sealAddress);
  const rpcChainId = await input.rpc.getChainId();
  const blockNumber = await input.rpc.getBlockNumber();
  const chainReady = BigInt(rpcChainId) === BigInt(request.chainId)
    && BigInt(rpcChainId) === BigInt(input.deployment.chainId);
  const sealReady = BigInt(requestedSeal) === BigInt(configuredSeal);

  const poolAddress = await readFelt(input.rpc, {
    contractAddress: configuredSeal,
    entrypoint: "get_pool",
  }, blockNumber);
  const catalogRegistryAddress = await readFelt(input.rpc, {
    contractAddress: configuredSeal,
    entrypoint: "get_catalog_registry",
  }, blockNumber);
  const obligationRegistryAddress = await readFelt(input.rpc, {
    contractAddress: configuredSeal,
    entrypoint: "get_obligation_registry",
  }, blockNumber);

  const [policyReady, fxReady, agreementReady, verifierReady] = await Promise.all([
    readBool(input.rpc, {
      contractAddress: catalogRegistryAddress,
      entrypoint: "is_policy_root_valid",
      calldata: rootCalldata(request.policyRoot),
    }, blockNumber),
    readBool(input.rpc, {
      contractAddress: catalogRegistryAddress,
      entrypoint: "is_fx_root_valid",
      calldata: rootCalldata(request.fxRoot),
    }, blockNumber),
    readBool(input.rpc, {
      contractAddress: obligationRegistryAddress,
      entrypoint: "is_obligation_root_valid",
      calldata: rootCalldata(request.agreementRoot),
    }, blockNumber),
    readBool(input.rpc, {
      contractAddress: catalogRegistryAddress,
      entrypoint: "is_verifier_valid",
      calldata: ["0x0", num.toHex(request.proofVersion)],
    }, blockNumber),
  ]);
  const verifierAddress = verifierReady
    ? await readFelt(input.rpc, {
      contractAddress: configuredSeal,
      entrypoint: "get_verifier",
      calldata: ["0x0", num.toHex(request.proofVersion)],
    }, blockNumber)
    : null;
  const poolReady = BigInt(poolAddress) === BigInt(STRK20_MAINNET_POOL_ADDRESS);
  const checks = [
    check("chain", chainReady, chainReady ? "RPC and proof chain IDs match." : "RPC, deployment, and proof chain IDs do not match."),
    check("seal", sealReady, sealReady ? "Proof is bound to the configured PAYO seal." : "Proof is bound to a different PAYO seal."),
    check("pool", poolReady, poolReady ? "Seal targets the canonical STRK20 Mainnet pool." : "Seal targets an unexpected privacy pool."),
    check("policy_root", policyReady, policyReady ? "Policy root is active." : "Policy root is not active or was revoked."),
    check("fx_root", fxReady, fxReady ? "FX root is active." : "FX root is not active or was revoked."),
    check("agreement_root", agreementReady, agreementReady ? "Agreement root is active." : "Agreement root is not active or was revoked."),
    check("verifier", verifierReady && verifierAddress !== null && BigInt(verifierAddress) !== 0n, verifierReady ? "Proof-bound verifier is active." : "Proof-bound verifier is not active or was revoked."),
  ];
  return {
    ready: checks.every((entry) => entry.ready),
    blockNumber,
    chainId: num.toHex(BigInt(rpcChainId)),
    sealAddress: configuredSeal,
    poolAddress,
    catalogRegistryAddress,
    obligationRegistryAddress,
    verifierAddress,
    checks,
  };
}
