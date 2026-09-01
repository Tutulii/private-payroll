import {
  Account,
  RpcProvider,
  constants,
  ec,
  hash,
  num,
  shortString,
  uint256,
  validateAndParseAddress,
} from "starknet";

const ACTIONS = new Set(["plan", "estimate", "rotate", "verify"]);
const action = process.argv[2];
if (!ACTIONS.has(action)) {
  throw new Error("Usage: node scripts/payo-policy-owner-rotation.mjs <plan|estimate|rotate|verify>");
}

const STRK_ADDRESS = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const POLICY_ACCOUNT = canonicalAddress(
  required("PAYO_AGENT_POLICY_ACCOUNT_ADDRESS"),
  "PAYO_AGENT_POLICY_ACCOUNT_ADDRESS",
);
const NEW_OWNER_PUBLIC_KEY = canonicalFelt(
  required("PAYO_POLICY_ROTATION_NEW_PUBLIC_KEY"),
  "PAYO_POLICY_ROTATION_NEW_PUBLIC_KEY",
);
const provider = new RpcProvider({ nodeUrl: required("STARKNET_RPC_URL") });

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function canonicalFelt(value, label) {
  try {
    const parsed = BigInt(value);
    const prime = (1n << 251n) + 17n * (1n << 192n) + 1n;
    if (parsed <= 0n || parsed >= prime) throw new Error("invalid");
    return num.toHex(parsed);
  } catch {
    throw new Error(`${label} is not a canonical nonzero felt.`);
  }
}

function canonicalAddress(value, label) {
  try { return num.toHex(BigInt(validateAndParseAddress(value))); } catch {
    throw new Error(`${label} is not a canonical Starknet address.`);
  }
}

function sameFelt(left, right) {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

async function currentOwner() {
  const result = await provider.callContract({
    contractAddress: POLICY_ACCOUNT,
    entrypoint: "get_public_key",
    calldata: [],
  }, "latest");
  if (result.length !== 1) throw new Error("The policy account returned an invalid owner key.");
  return canonicalFelt(result[0], "Current owner public key");
}

function rotationCall(currentOwnerPublicKey) {
  const signature = [
    canonicalFelt(required("PAYO_POLICY_ROTATION_ACCEPTANCE_R"), "Acceptance signature r"),
    canonicalFelt(required("PAYO_POLICY_ROTATION_ACCEPTANCE_S"), "Acceptance signature s"),
  ];
  const digest = num.toHex(hash.computePoseidonHashOnElements([
    shortString.encodeShortString("StarkNet Message"),
    shortString.encodeShortString("accept_ownership"),
    POLICY_ACCOUNT,
    currentOwnerPublicKey,
  ]));
  const starkSignature = new ec.starkCurve.Signature(BigInt(signature[0]), BigInt(signature[1]));
  const x = BigInt(NEW_OWNER_PUBLIC_KEY).toString(16).padStart(64, "0");
  const valid = ["02", "03"].some((prefix) => {
    try { return ec.starkCurve.verify(starkSignature, digest, `${prefix}${x}`); } catch { return false; }
  });
  if (!valid) throw new Error("The new owner acceptance signature is invalid.");
  return {
    digest,
    call: {
      contractAddress: POLICY_ACCOUNT,
      entrypoint: "set_public_key",
      calldata: [NEW_OWNER_PUBLIC_KEY, "0x2", ...signature],
    },
  };
}

function currentOwnerAccount(currentOwnerPublicKey) {
  const privateKey = required("PAYO_POLICY_ROTATION_CURRENT_PRIVATE_KEY");
  const derived = canonicalFelt(ec.starkCurve.getStarkKey(privateKey), "Derived current owner key");
  if (!sameFelt(derived, currentOwnerPublicKey)) {
    throw new Error("The rotation key does not control the current policy account.");
  }
  return new Account({ provider, address: POLICY_ACCOUNT, signer: privateKey, cairoVersion: "1" });
}

async function strkBalance() {
  const result = await provider.callContract({
    contractAddress: STRK_ADDRESS,
    entrypoint: "balance_of",
    calldata: [POLICY_ACCOUNT],
  }, "latest");
  return uint256.uint256ToBN({ low: result[0], high: result[1] });
}

async function estimate(currentOwnerPublicKey, call) {
  const chainId = await provider.getChainId();
  if (!sameFelt(chainId, constants.StarknetChainId.SN_MAIN)) {
    throw new Error("Owner rotation is pinned to Starknet Mainnet.");
  }
  const account = currentOwnerAccount(currentOwnerPublicKey);
  const nonce = await provider.getNonceForAddress(POLICY_ACCOUNT, "pre_confirmed");
  const fee = await account.estimateInvokeFee(call, { nonce, skipValidate: false, tip: 1n });
  const balance = await strkBalance();
  return { account, nonce, fee, balance };
}

const owner = await currentOwner();
if (action === "verify") {
  if (!sameFelt(owner, NEW_OWNER_PUBLIC_KEY)) throw new Error("The isolated signer is not the on-chain owner.");
  process.stdout.write(`${JSON.stringify({ verified: true, policyAccount: POLICY_ACCOUNT, owner })}\n`);
  process.exit(0);
}
if (sameFelt(owner, NEW_OWNER_PUBLIC_KEY)) {
  process.stdout.write(`${JSON.stringify({ alreadyRotated: true, policyAccount: POLICY_ACCOUNT, owner })}\n`);
  process.exit(0);
}
const planned = rotationCall(owner);
if (action === "plan") {
  process.stdout.write(`${JSON.stringify({
    mutation: false,
    chain: "SN_MAIN",
    policyAccount: POLICY_ACCOUNT,
    currentOwner: owner,
    newOwner: NEW_OWNER_PUBLIC_KEY,
    acceptanceDigest: planned.digest,
    call: planned.call,
  }, null, 2)}\n`);
  process.exit(0);
}
const simulated = await estimate(owner, planned.call);
const evidence = {
  mutation: false,
  policyAccount: POLICY_ACCOUNT,
  currentOwner: owner,
  newOwner: NEW_OWNER_PUBLIC_KEY,
  nonce: num.toHex(BigInt(simulated.nonce)),
  simulatedFeeFri: simulated.fee.overall_fee.toString(),
  publicStrkBalanceFri: simulated.balance.toString(),
  sufficientBalance: simulated.balance >= BigInt(simulated.fee.overall_fee),
};
if (action === "estimate") {
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
  process.exit(0);
}
if (!evidence.sufficientBalance) throw new Error("The policy account lacks public STRK for owner rotation.");
if (process.env.PAYO_POLICY_ROTATION_CONFIRM !== "ROTATE_PAYO_POLICY_OWNER_MAINNET") {
  throw new Error("Refusing rotation without PAYO_POLICY_ROTATION_CONFIRM=ROTATE_PAYO_POLICY_OWNER_MAINNET.");
}
const submitted = await simulated.account.execute(planned.call, {
  nonce: simulated.nonce,
  resourceBounds: simulated.fee.resourceBounds,
  tip: 1n,
});
process.stderr.write(
  `${JSON.stringify({
    checkpoint: "submitted",
    operation: "policy-owner-rotation",
    transactionHash: submitted.transaction_hash,
    warning: "Do not retry until this hash has been reconciled on Starknet.",
  })}\n`,
);
const receipt = await provider.waitForTransaction(submitted.transaction_hash, {
  retries: 400,
  retryInterval: 3_000,
});
if (receipt.isReverted()) throw new Error("The policy owner rotation reverted.");
const rotated = await currentOwner();
if (!sameFelt(rotated, NEW_OWNER_PUBLIC_KEY)) throw new Error("Owner rotation failed final read-back.");
process.stdout.write(`${JSON.stringify({
  ...evidence,
  mutation: true,
  transactionHash: submitted.transaction_hash,
  verifiedOwner: rotated,
}, null, 2)}\n`);
