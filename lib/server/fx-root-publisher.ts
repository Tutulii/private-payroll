import "server-only";

import { num, type Call } from "starknet";
import { PAYO_MAX_PROOF_CALLDATA_FELTS } from "@/lib/proof/protocol";
import type { PayoDeploymentConfig } from "./payo-deployment";

export type FxPublicationRpc = {
  getBlockNumber: () => Promise<number>;
  getBlockTimestamp: (blockNumber: number) => Promise<number>;
  callContract: (call: Call, blockIdentifier?: number) => Promise<unknown>;
};

function resultFelts(response: unknown): string[] {
  if (Array.isArray(response)) return response.map(String);
  if (response && typeof response === "object" && Array.isArray((response as { result?: unknown }).result)) {
    return (response as { result: unknown[] }).result.map(String);
  }
  throw new Error("Starknet returned an invalid FX publication response.");
}

function singleFelt(response: unknown, label: string): bigint {
  const values = resultFelts(response);
  if (values.length !== 1) throw new Error(`${label} returned an unexpected response.`);
  return BigInt(values[0]);
}

function decodeVerifierInputs(response: unknown, label: string): bigint[] {
  const values = resultFelts(response);
  if (BigInt(values[0] ?? -1) !== 0n || BigInt(values[1] ?? -1) !== 17n || values.length !== 36) {
    throw new Error(`${label} did not return Result::Ok with exactly 17 public inputs.`);
  }
  return Array.from({ length: 17 }, (_, index) =>
    BigInt(values[2 + index * 2]) + (BigInt(values[3 + index * 2]) << 128n));
}

function rootFromLimbs(high: bigint, low: bigint): string {
  if (high < 0n || high >= 1n << 128n || low < 0n || low >= 1n << 128n) {
    throw new Error("The proof returned a non-canonical FX root.");
  }
  return `0x${((high << 128n) | low).toString(16).padStart(64, "0")}`;
}

export async function verifyFxPublicationProof(input: {
  rpc: FxPublicationRpc;
  deployment: PayoDeploymentConfig;
  policyRegistryAddress: string;
  catalogRoot: string;
  proofVersion: 1 | 2;
  shards: readonly [readonly string[], readonly string[]];
}): Promise<{ blockNumber: number; blockTimestamp: number; verifierAddress: string }> {
  if (input.shards.some((shard) =>
    shard.length < 1
    || shard.length > PAYO_MAX_PROOF_CALLDATA_FELTS
    || shard.some((felt) => !/^0x[0-9a-fA-F]+$/.test(felt)))) {
    throw new Error("The FX publication proof calldata is malformed.");
  }
  const blockNumber = await input.rpc.getBlockNumber();
  const [blockTimestamp, verifierActive, verifierResponse] = await Promise.all([
    input.rpc.getBlockTimestamp(blockNumber),
    input.rpc.callContract({
      contractAddress: input.policyRegistryAddress,
      entrypoint: "is_verifier_valid",
      calldata: ["0", input.proofVersion.toString()],
    }, blockNumber),
    input.rpc.callContract({
      contractAddress: input.policyRegistryAddress,
      entrypoint: "get_verifier",
      calldata: ["0", input.proofVersion.toString()],
    }, blockNumber),
  ]);
  if (singleFelt(verifierActive, "PAYO verifier state") === 0n) {
    throw new Error("The payroll verifier required for FX publication is inactive.");
  }
  const verifierAddress = num.toHex(singleFelt(verifierResponse, "PAYO verifier address"));
  if (BigInt(verifierAddress) === 0n) throw new Error("The payroll verifier address is zero.");
  const results = await Promise.all(input.shards.map((proof, shardIndex) =>
    input.rpc.callContract({
      contractAddress: verifierAddress,
      entrypoint: "verify_payroll_integrity_shard",
      calldata: [proof.length.toString(), ...proof],
    }, blockNumber).then((response) => decodeVerifierInputs(response, `Payroll proof shard ${shardIndex}`))));
  for (let index = 0; index < 16; index += 1) {
    if (results[0][index] !== results[1][index]) {
      throw new Error("The payroll proof shards have different deployment or root bindings.");
    }
  }
  if (results[0][16] !== 0n || results[1][16] !== 1n) {
    throw new Error("The payroll proof shards are missing or reordered.");
  }
  if (
    results[0][0] !== BigInt(input.deployment.chainId)
    || results[0][1] !== BigInt(input.deployment.sealAddress)
    || results[0][2] !== BigInt(input.proofVersion)
    || results[0][3] !== 1n
    || BigInt(rootFromLimbs(results[0][10], results[0][11])) !== BigInt(input.catalogRoot)
  ) {
    throw new Error("The payroll proof is not bound to this PAYO FX catalog and deployment.");
  }
  if (results[0][14] > BigInt(blockTimestamp) || BigInt(blockTimestamp) > results[0][15]) {
    throw new Error("The payroll proof validity window is not active.");
  }
  return { blockNumber, blockTimestamp, verifierAddress };
}

export async function isFxRootActive(input: {
  rpc: Pick<FxPublicationRpc, "callContract">;
  policyRegistryAddress: string;
  catalogRoot: string;
  blockIdentifier?: number;
}): Promise<boolean> {
  const root = BigInt(input.catalogRoot);
  const response = await input.rpc.callContract({
    contractAddress: input.policyRegistryAddress,
    entrypoint: "is_fx_root_valid",
    calldata: [(root >> 128n).toString(), (root & ((1n << 128n) - 1n)).toString()],
  }, input.blockIdentifier);
  return singleFelt(response, "PAYO FX root state") !== 0n;
}
