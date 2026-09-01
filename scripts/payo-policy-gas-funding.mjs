import {
  Account,
  RpcProvider,
  constants,
  ec,
  num,
  uint256,
  validateAndParseAddress,
} from "starknet";
import {
  hasFundingBalance,
  parsePolicyGasTargetFri,
  policyGasFundingDelta,
} from "./lib/policy-gas-funding.mjs";

const ACTIONS = new Set(["status", "estimate", "fund"]);
const action = process.argv[2];
if (!ACTIONS.has(action)) {
  throw new Error(
    "Usage: node scripts/payo-policy-gas-funding.mjs <status|estimate|fund>",
  );
}

const STRK_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function canonicalAddress(value, label) {
  try {
    return num.toHex(BigInt(validateAndParseAddress(value)));
  } catch {
    throw new Error(`${label} is not a canonical Starknet address.`);
  }
}

function sameFelt(left, right) {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

async function tokenBalance(provider, address) {
  const result = await provider.callContract(
    {
      contractAddress: STRK_ADDRESS,
      entrypoint: "balance_of",
      calldata: [address],
    },
    "latest",
  );
  if (result.length !== 2) throw new Error("STRK returned an invalid balance.");
  return uint256.uint256ToBN({ low: result[0], high: result[1] });
}

const provider = new RpcProvider({ nodeUrl: required("STARKNET_RPC_URL") });
if (!sameFelt(await provider.getChainId(), constants.StarknetChainId.SN_MAIN)) {
  throw new Error("Policy-account gas funding is pinned to Starknet Mainnet.");
}

const policyAccount = canonicalAddress(
  required("PAYO_AGENT_POLICY_ACCOUNT_ADDRESS"),
  "PAYO_AGENT_POLICY_ACCOUNT_ADDRESS",
);
const targetBalance = parsePolicyGasTargetFri(
  required("PAYO_POLICY_GAS_TARGET_FRI"),
);
const currentBalance = await tokenBalance(provider, policyAccount);
const transferAmount = policyGasFundingDelta(currentBalance, targetBalance);

const status = {
  mutation: false,
  chain: "SN_MAIN",
  policyAccount,
  token: STRK_ADDRESS,
  currentBalanceFri: currentBalance.toString(),
  targetBalanceFri: targetBalance.toString(),
  transferAmountFri: transferAmount.toString(),
  targetSatisfied: transferAmount === 0n,
};

if (action === "status" || transferAmount === 0n) {
  process.stdout.write(`${JSON.stringify(status, null, 2)}\n`);
  process.exit(0);
}

const relayerAddress = canonicalAddress(
  required("PAYO_PROOF_RELAYER_ADDRESS"),
  "PAYO_PROOF_RELAYER_ADDRESS",
);
const relayerPrivateKey = required("PAYO_PROOF_RELAYER_PRIVATE_KEY");
const relayerPublicKey = num.toHex(
  BigInt(ec.starkCurve.getStarkKey(relayerPrivateKey)),
);
const onchainRelayerOwner = await provider.callContract(
  {
    contractAddress: relayerAddress,
    entrypoint: "get_public_key",
    calldata: [],
  },
  "latest",
);
if (
  onchainRelayerOwner.length !== 1 ||
  !sameFelt(onchainRelayerOwner[0], relayerPublicKey)
) {
  throw new Error("The configured relayer key does not control the funding account.");
}

const relayer = new Account({
  provider,
  address: relayerAddress,
  signer: relayerPrivateKey,
  cairoVersion: "1",
});
const amount = uint256.bnToUint256(transferAmount);
const call = {
  contractAddress: STRK_ADDRESS,
  entrypoint: "transfer",
  calldata: [policyAccount, num.toHex(amount.low), num.toHex(amount.high)],
};
const nonce = await provider.getNonceForAddress(relayerAddress, "pre_confirmed");
const estimate = await relayer.estimateInvokeFee(call, {
  nonce,
  skipValidate: false,
  tip: 1n,
});
const relayerBalance = await tokenBalance(provider, relayerAddress);
const sufficientBalance = hasFundingBalance(
  relayerBalance,
  transferAmount,
  BigInt(estimate.overall_fee),
);
const evidence = {
  ...status,
  relayerAddress,
  nonce: num.toHex(BigInt(nonce)),
  simulatedFeeFri: estimate.overall_fee.toString(),
  relayerBalanceFri: relayerBalance.toString(),
  sufficientBalance,
};

if (action === "estimate") {
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
  process.exit(0);
}
if (!sufficientBalance) {
  throw new Error("The relayer lacks the reviewed transfer amount plus fee.");
}
if (process.env.PAYO_POLICY_GAS_CONFIRM !== "FUND_PAYO_POLICY_GAS_MAINNET") {
  throw new Error(
    "Refusing funding without PAYO_POLICY_GAS_CONFIRM=FUND_PAYO_POLICY_GAS_MAINNET.",
  );
}

const submitted = await relayer.execute(call, {
  nonce,
  resourceBounds: estimate.resourceBounds,
  tip: 1n,
});
process.stderr.write(
  `${JSON.stringify({
    checkpoint: "submitted",
    operation: "policy-gas-funding",
    transactionHash: submitted.transaction_hash,
    warning: "Do not retry until this hash has been reconciled on Starknet.",
  })}\n`,
);
const receipt = await provider.waitForTransaction(submitted.transaction_hash, {
  retries: 400,
  retryInterval: 3_000,
});
if (receipt.isReverted()) throw new Error("The policy gas funding reverted.");
const confirmedBalance = await tokenBalance(provider, policyAccount);
if (confirmedBalance < targetBalance) {
  throw new Error("Policy gas funding failed final balance read-back.");
}
process.stdout.write(
  `${JSON.stringify(
    {
      ...evidence,
      mutation: true,
      transactionHash: submitted.transaction_hash,
      confirmedBalanceFri: confirmedBalance.toString(),
    },
    null,
    2,
  )}\n`,
);
