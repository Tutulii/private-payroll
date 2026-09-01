import { readFile } from "node:fs/promises";
import { hash } from "starknet";

const STRK_ADDRESS = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const MAINNET_CHAIN_ID = "0x534e5f4d41494e";
const feltPattern = /^0x[0-9a-f]+$/i;
const evidence = JSON.parse(await readFile(
  new URL("../evidence/phase5-cutover-mainnet.json", import.meta.url),
  "utf8",
));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sameFelt(left, right) {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

function assertFelt(value, label) {
  assert(typeof value === "string" && feltPattern.test(value), `${label} is not a Starknet felt.`);
}

function u256(values, label) {
  assert(Array.isArray(values) && values.length === 2, `${label} did not return a Cairo u256.`);
  return BigInt(values[0]) + (BigInt(values[1]) << 128n);
}

assert(evidence.schemaVersion === 1, "Phase 5 cutover evidence has the wrong schema version.");
assert(evidence.network === "starknet-mainnet", "Phase 5 cutover evidence is not Mainnet-bound.");
assert(sameFelt(evidence.chainId, MAINNET_CHAIN_ID), "Phase 5 cutover evidence has the wrong chain ID.");
assertFelt(evidence.policyAccount?.address, "Policy account address");
assertFelt(evidence.policyAccount?.classHash, "Policy account class hash");
assertFelt(evidence.policyAccount?.ownerPublicKey, "Policy account owner public key");
assertFelt(evidence.treasury?.poolAddress, "STRK20 pool address");
assertFelt(evidence.treasury?.viewingPublicKey, "Treasury viewing public key");
assert(evidence.treasury?.privateStrkFundingIndexed === true,
  "Private treasury funding has not been recorded as indexed.");
assert(evidence.treasury?.privateAmountDisclosed === false,
  "Phase 5 public evidence must not disclose the private treasury amount.");
assert(Number.isInteger(evidence.treasury?.discoveryObservedBlock)
  && evidence.treasury.discoveryObservedBlock > 0,
"Private treasury discovery block is invalid.");
assert(evidence.verification?.executorEnabled === false,
  "Autonomous dispatch must remain disabled before the Mainnet canary.");
assert(evidence.verification?.offlineRecoveryCopyConfirmed === true,
  "Offline owner recovery was not confirmed.");
assert(evidence.signer?.privateNetworkOnly === true && evidence.signer?.healthPassed === true,
  "The isolated signer deployment evidence is incomplete.");
for (const [label, expected] of Object.entries({
  missingAuthenticationStatus: 401,
  malformedPolicyStatus: 400,
  replayedNonceStatus: 401,
  unknownRouteStatus: 404,
})) {
  assert(evidence.signer?.negativeControls?.[label] === expected,
    `Signer negative control ${label} is missing.`);
}

const rpcUrl = process.env.STARKNET_RPC_URL?.trim()
  || process.env.NEXT_PUBLIC_STARKNET_RPC_URL?.trim()
  || "https://api.cartridge.gg/x/starknet/mainnet";
let rpcId = 0;
async function rpc(method, params) {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  let body;
  try { body = await response.json(); } catch {
    throw new Error(`${method} returned a non-JSON response (${response.status}).`);
  }
  if (!response.ok || body.error) {
    throw new Error(`${method} failed: ${body.error?.message ?? response.statusText}`);
  }
  return body.result;
}

function callAt(contractAddress, entrypoint, calldata, blockNumber) {
  return rpc("starknet_call", [{
    contract_address: contractAddress,
    entry_point_selector: hash.getSelectorFromName(entrypoint),
    calldata,
  }, { block_number: blockNumber }]);
}

function actualFeeFri(receipt) {
  const value = typeof receipt.actual_fee === "object"
    ? receipt.actual_fee?.amount
    : receipt.actual_fee;
  return BigInt(value);
}

async function verifyReceipt(label, expected) {
  assertFelt(expected?.transactionHash, `${label} transaction hash`);
  assertFelt(expected?.blockHash, `${label} block hash`);
  assert(Number.isInteger(expected?.blockNumber) && expected.blockNumber > 0,
    `${label} block number is invalid.`);
  const receipt = await rpc("starknet_getTransactionReceipt", [expected.transactionHash]);
  assert(receipt.execution_status === "SUCCEEDED", `${label} transaction did not succeed.`);
  assert(["ACCEPTED_ON_L2", "ACCEPTED_ON_L1"].includes(receipt.finality_status),
    `${label} transaction is not accepted.`);
  assert(receipt.block_number === expected.blockNumber, `${label} block number changed.`);
  assert(sameFelt(receipt.block_hash, expected.blockHash), `${label} block hash changed.`);
  assert(actualFeeFri(receipt) === BigInt(expected.actualFeeFri), `${label} actual fee changed.`);
  return receipt;
}

const transactions = evidence.transactions ?? {};
await Promise.all([
  verifyReceipt("Funding", transactions.funding),
  verifyReceipt("Registration", transactions.registration),
  verifyReceipt("Owner rotation", transactions.ownerRotation),
]);

const chainId = await rpc("starknet_chainId", []);
assert(sameFelt(chainId, MAINNET_CHAIN_ID), "RPC is not connected to Starknet Mainnet.");
const latestBlock = await rpc("starknet_blockNumber", []);
assert(latestBlock >= evidence.treasury.discoveryObservedBlock,
  "The RPC head predates the private-funding discovery observation.");

const fundingBalance = u256(await callAt(
  STRK_ADDRESS,
  "balance_of",
  [evidence.policyAccount.address],
  transactions.funding.blockNumber,
), "Funding balance");
assert(fundingBalance === BigInt(transactions.funding.transferredFri),
  "The policy account did not hold the recorded funding amount after funding.");

const [registrationKey, registrationBalance, registrationAllowance] = await Promise.all([
  callAt(
    evidence.treasury.poolAddress,
    "get_public_key",
    [evidence.policyAccount.address],
    transactions.registration.blockNumber,
  ),
  callAt(
    STRK_ADDRESS,
    "balance_of",
    [evidence.policyAccount.address],
    transactions.registration.blockNumber,
  ),
  callAt(
    STRK_ADDRESS,
    "allowance",
    [evidence.policyAccount.address, evidence.treasury.poolAddress],
    transactions.registration.blockNumber,
  ),
]);
assert(registrationKey.length === 1
  && sameFelt(registrationKey[0], evidence.treasury.viewingPublicKey),
"The registered STRK20 viewing key does not match the evidence.");
assert(u256(registrationBalance, "Post-registration balance")
  === BigInt(evidence.policyAccount.publicStrkBalanceFriAfterRegistration),
"The post-registration public STRK balance does not match the evidence.");
assert(u256(registrationAllowance, "Post-registration allowance")
  === BigInt(evidence.policyAccount.poolAllowanceFriAfterRegistration),
"The post-registration pool allowance does not match the evidence.");

const [owner, paused, classHash] = await Promise.all([
  callAt(
    evidence.policyAccount.address,
    "get_public_key",
    [],
    transactions.ownerRotation.blockNumber,
  ),
  callAt(
    evidence.policyAccount.address,
    "is_policy_account_paused",
    [],
    transactions.ownerRotation.blockNumber,
  ),
  rpc("starknet_getClassHashAt", [
    { block_number: evidence.verification.inventoryBlockNumber },
    evidence.policyAccount.address,
  ]),
]);
assert(owner.length === 1 && sameFelt(owner[0], evidence.policyAccount.ownerPublicKey),
  "The isolated owner rotation read-back does not match the evidence.");
assert(paused.length === 1 && BigInt(paused[0]) === 0n,
  "The policy account was paused at the owner-rotation block.");
assert(sameFelt(classHash, evidence.policyAccount.classHash),
  "The Mainnet policy account class hash does not match the evidence.");
assert(evidence.signer.attestedOwnerPublicKey === evidence.policyAccount.ownerPublicKey,
  "The signer attestation does not match the on-chain owner.");

process.stdout.write(
  `Phase 5 cutover verified at Mainnet head ${latestBlock}: three accepted receipts, isolated owner, registered treasury, bounded allowance, signer controls, private funding indexed without amount disclosure; executor remains disabled.\n`,
);
