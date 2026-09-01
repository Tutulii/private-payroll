/* eslint-disable @typescript-eslint/no-explicit-any -- The operator harness loads the digest-pinned runtime SDK, whose builder API is intentionally runtime-only. Every resulting call is target-checked before simulation or submission. */

import "server-only";

import { Account, RpcProvider, Signer, constants, ec, num, uint256 } from "starknet";
import { loadPinnedPrivacySdk } from "@/lib/server/privacy-sdk-loader";

const ACTIONS = new Set(["status", "estimate", "register"]);
const action = process.argv[2];
if (!ACTIONS.has(action)) {
  throw new Error("Usage: tsx scripts/payo-policy-treasury-bootstrap.ts <status|estimate|register>");
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

async function main() {
const rpcUrl = required("STARKNET_RPC_URL");
const policyAccountAddress = required("PAYO_AGENT_POLICY_ACCOUNT_ADDRESS");
const poolAddress = required("PAYO_STRK20_POOL_ADDRESS");
const viewingKey = required("PAYO_AGENT_POLICY_VIEWING_KEY");
const viewingScalar = BigInt(viewingKey);
if (viewingScalar <= 0n || viewingScalar > ec.starkCurve.CURVE.n / 2n) {
  throw new Error("PAYO_AGENT_POLICY_VIEWING_KEY is outside the supported private-key range.");
}
const viewingPublicKey = num.toHex(BigInt(ec.starkCurve.getStarkKey(viewingKey)));
const provider = new RpcProvider({ nodeUrl: rpcUrl });
if (!sameFelt(await provider.getChainId(), constants.StarknetChainId.SN_MAIN)) {
  throw new Error("Treasury registration is pinned to Starknet Mainnet.");
}

async function registeredKey() {
  const result = await provider.callContract({
    contractAddress: poolAddress,
    entrypoint: "get_public_key",
    calldata: [policyAccountAddress],
  }, "latest");
  if (result.length !== 1) throw new Error("STRK20 returned an invalid registration key.");
  return num.toHex(BigInt(result[0]));
}

const currentRegistration = await registeredKey();
if (BigInt(currentRegistration) !== 0n) {
  if (!sameFelt(currentRegistration, viewingPublicKey)) {
    throw new Error("The policy treasury is already registered to a different viewing key.");
  }
  process.stdout.write(`${JSON.stringify({
    registered: true,
    policyAccountAddress,
    poolAddress,
    viewingPublicKey,
  })}\n`);
  process.exit(0);
}
if (action === "status") {
  process.stdout.write(`${JSON.stringify({
    registered: false,
    policyAccountAddress,
    poolAddress,
    expectedViewingPublicKey: viewingPublicKey,
  })}\n`);
  process.exit(0);
}

const ownerPrivateKey = required("PAYO_POLICY_ROTATION_CURRENT_PRIVATE_KEY");
const onchainOwner = await provider.callContract({
  contractAddress: policyAccountAddress,
  entrypoint: "get_public_key",
  calldata: [],
}, "latest");
if (
  onchainOwner.length !== 1
  || !sameFelt(onchainOwner[0], ec.starkCurve.getStarkKey(ownerPrivateKey))
) throw new Error("The bootstrap signer does not control the policy account.");

const relayerAddress = required("PAYO_PROOF_RELAYER_ADDRESS");
const relayerPrivateKey = required("PAYO_PROOF_RELAYER_PRIVATE_KEY");
const relayerOwner = await provider.callContract({
  contractAddress: relayerAddress,
  entrypoint: "get_public_key",
  calldata: [],
}, "latest");
if (
  relayerOwner.length !== 1
  || !sameFelt(relayerOwner[0], ec.starkCurve.getStarkKey(relayerPrivateKey))
) throw new Error("The configured registration relayer key is invalid.");
const relayer = new Account({
  provider,
  address: relayerAddress,
  signer: relayerPrivateKey,
  cairoVersion: "1",
});
const sdk = await loadPinnedPrivacySdk();
const discovery = new sdk.sdk.IndexerDiscoveryProvider(
  required("PAYO_STRK20_INDEXER_URL"),
  poolAddress,
);
const health = await discovery.getHealth();
if (health.status !== "OK" || !health.chain_head || (health.lag_secs ?? Infinity) > 120) {
  throw new Error("The STRK20 discovery service is not healthy enough for registration.");
}
const provingProvider = new sdk.sdk.ProvingServiceProofProvider(
  required("PAYO_STRK20_PROVING_URL"),
  constants.StarknetChainId.SN_MAIN,
  {
    requestTimeoutMs: 30 * 60_000,
    blockIdentifier: health.chain_head.block_hash,
    nodeUrl: rpcUrl,
    poolAddress,
    retry: { maxRetries: 2 },
  },
);
const transfers = sdk.sdk.createPrivateTransfers({
  account: {
    address: policyAccountAddress,
    signer: new Signer(ownerPrivateKey),
  },
  viewingKeyProvider: { getViewingKey: async () => viewingScalar },
  provingProvider,
  discoveryProvider: discovery,
  poolContractAddress: poolAddress,
}) as any;
const result = await transfers.build({
  autoDiscover: { notes: "refresh", channels: "refresh" },
}).register().execute();
const call = result?.callAndProof?.call;
if (
  !call
  || !sameFelt(call.contractAddress, poolAddress)
  || call.entrypoint !== "apply_actions"
  || !Array.isArray(call.calldata)
  || call.calldata.length < 2
) throw new Error("The pinned SDK did not produce a canonical registration call.");
const estimate = await relayer.estimateInvokeFee(call, { skipValidate: false, tip: 1n });
const balanceResult = await provider.callContract({
  contractAddress: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
  entrypoint: "balance_of",
  calldata: [relayerAddress],
}, "latest");
const balance = uint256.uint256ToBN({ low: balanceResult[0], high: balanceResult[1] });
const evidence = {
  mutation: false,
  policyAccountAddress,
  poolAddress,
  viewingPublicKey,
  pinnedBlockNumber: health.chain_head.block_number,
  pinnedBlockHash: health.chain_head.block_hash,
  simulatedFeeFri: estimate.overall_fee.toString(),
  relayerBalanceFri: balance.toString(),
  sufficientBalance: balance >= BigInt(estimate.overall_fee),
};
if (action === "estimate") {
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
  process.exit(0);
}
if (!evidence.sufficientBalance) throw new Error("The relayer lacks public STRK for registration.");
if (process.env.PAYO_POLICY_TREASURY_CONFIRM !== "REGISTER_PAYO_POLICY_TREASURY_MAINNET") {
  throw new Error(
    "Refusing registration without PAYO_POLICY_TREASURY_CONFIRM=REGISTER_PAYO_POLICY_TREASURY_MAINNET.",
  );
}
const submitted = await relayer.execute(call, {
  resourceBounds: estimate.resourceBounds,
  tip: 1n,
});
const receipt = await provider.waitForTransaction(submitted.transaction_hash, {
  retries: 400,
  retryInterval: 3_000,
});
if (receipt.isReverted()) throw new Error("The STRK20 policy-treasury registration reverted.");
const confirmed = await registeredKey();
if (!sameFelt(confirmed, viewingPublicKey)) {
  throw new Error("The STRK20 registration failed final read-back.");
}
process.stdout.write(`${JSON.stringify({
  ...evidence,
  mutation: true,
  transactionHash: submitted.transaction_hash,
  confirmedViewingPublicKey: confirmed,
}, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : "Treasury bootstrap failed."}\n`);
  process.exitCode = 1;
});
