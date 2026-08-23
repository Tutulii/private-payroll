import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { hash, num, uint256 } from "starknet";
import {
  assertPrivateTransferReceipt,
  assertUsdcShieldReceipt,
  NATIVE_USDC_ADDRESS,
  receiptFee,
  tokenWithdrawalFee,
  validateEvidence,
} from "./lib/usdc-evidence.mjs";

const root = resolve(import.meta.dirname, "..");
const evidencePath = resolve(root, "evidence/usdc-mainnet.json");
const rpcUrl = process.env.PAYO_MAINNET_RPC_URL
  ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL
  ?? "https://rpc.starknet.lava.build";
let rpcId = 0;
async function rpc(method, params) {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  const body = await response.json();
  if (!response.ok || body.error) {
    throw new Error(`${method} failed: ${body.error?.message ?? response.statusText}`);
  }
  return body.result;
}

let evidence;
try {
  evidence = JSON.parse(await readFile(evidencePath, "utf8"));
} catch (error) {
  if (error?.code === "ENOENT") {
    throw new Error(
      "Missing evidence/usdc-mainnet.json. Complete docs/usdc-mainnet-compatibility.md first.",
    );
  }
  throw error;
}
const balanceEvidence = validateEvidence(evidence);

const [shieldReceipt, transferReceipt] = await Promise.all([
  rpc("starknet_getTransactionReceipt", [evidence.shield.transactionHash]),
  rpc("starknet_getTransactionReceipt", [evidence.privateTransfer.transactionHash]),
]);
assertUsdcShieldReceipt(shieldReceipt, "Shield transaction");
assertPrivateTransferReceipt(transferReceipt, "Private transfer transaction");
if (!Number.isSafeInteger(shieldReceipt.block_number) || !Number.isSafeInteger(transferReceipt.block_number)) {
  throw new Error("Accepted receipts must include safe block numbers.");
}

function callAt(contractAddress, entrypoint, calldata, blockNumber) {
  return rpc("starknet_call", [
    {
      contract_address: contractAddress,
      entry_point_selector: hash.getSelectorFromName(entrypoint),
      calldata,
    },
    { block_number: blockNumber },
  ]);
}

async function tokenBalanceAt(tokenAddress, accountAddress, blockNumber) {
  const result = await callAt(tokenAddress, "balance_of", [accountAddress], blockNumber);
  return uint256.uint256ToBN({ low: result[0] ?? "0x0", high: result[1] ?? "0x0" });
}

async function operationState(receipt) {
  const beforeBlock = receipt.block_number - 1;
  const afterBlock = receipt.block_number;
  const [publicUsdcBefore, publicUsdcAfter] = await Promise.all([
      tokenBalanceAt(NATIVE_USDC_ADDRESS, evidence.wallet.accountAddress, beforeBlock),
      tokenBalanceAt(NATIVE_USDC_ADDRESS, evidence.wallet.accountAddress, afterBlock),
    ]);
  return { publicUsdcBefore, publicUsdcAfter };
}

const [decimalsResult, shieldState] = await Promise.all([
  callAt(NATIVE_USDC_ADDRESS, "decimals", [], shieldReceipt.block_number),
  operationState(shieldReceipt),
]);
if (num.toBigInt(decimalsResult[0]) !== 6n) throw new Error("Native-USDC contract does not report six decimals.");
if (shieldState.publicUsdcBefore - shieldState.publicUsdcAfter !== balanceEvidence.gross) {
  throw new Error("On-chain public USDC shield delta does not equal the recorded gross amount.");
}
receiptFee(shieldReceipt, "Shield transaction");
receiptFee(transferReceipt, "Private transfer transaction");
const shieldTokenFee = tokenWithdrawalFee(shieldReceipt, NATIVE_USDC_ADDRESS, "Shield transaction");
if (shieldTokenFee >= balanceEvidence.gross) {
  throw new Error("The successful USDC shield fee must be lower than its gross deposit.");
}
console.log(
  `Native USDC Mainnet compatibility evidence passed: shield=${balanceEvidence.gross} atomic, shield_fee=${shieldTokenFee} atomic, private_transfer=confirmed_ready_attestation${balanceEvidence.transferred === null ? "" : `, disclosed_transfer=${balanceEvidence.transferred} atomic`}.`,
);
