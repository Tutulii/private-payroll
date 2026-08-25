import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { hash, num } from "starknet";
import {
  assertAcceptedReceipt,
  receiptHasEmitter,
  validatePayoStrkEvidence,
} from "./lib/payo-strk-evidence.mjs";

const root = resolve(import.meta.dirname, "..");
const evidence = JSON.parse(await readFile(resolve(root, "evidence/payo-strk-mainnet.json"), "utf8"));
const { orderedShards } = validatePayoStrkEvidence(evidence);
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

function callAt(entrypoint, calldata, blockNumber) {
  return rpc("starknet_call", [
    {
      contract_address: evidence.contracts.payrollSeal,
      entry_point_selector: hash.getSelectorFromName(entrypoint),
      calldata,
    },
    { block_number: blockNumber },
  ]);
}

const [payrollReceipt, shardZeroReceipt, shardOneReceipt] = await Promise.all([
  rpc("starknet_getTransactionReceipt", [evidence.payroll.transactionHash]),
  rpc("starknet_getTransactionReceipt", [orderedShards[0].transactionHash]),
  rpc("starknet_getTransactionReceipt", [orderedShards[1].transactionHash]),
]);
assertAcceptedReceipt(payrollReceipt, evidence.payroll, "Payroll transaction");
assertAcceptedReceipt(shardZeroReceipt, orderedShards[0], "Verifier shard 0");
assertAcceptedReceipt(shardOneReceipt, orderedShards[1], "Verifier shard 1");
if (!receiptHasEmitter(payrollReceipt, evidence.contracts.pool)) {
  throw new Error("Payroll transaction has no event from the reviewed STRK20 pool.");
}
if (!receiptHasEmitter(payrollReceipt, evidence.contracts.payrollSeal)) {
  throw new Error("Payroll transaction has no event from the reviewed PAYO seal.");
}
for (const [index, receipt] of [shardZeroReceipt, shardOneReceipt].entries()) {
  if (!receiptHasEmitter(receipt, evidence.contracts.payrollSeal)) {
    throw new Error(`Verifier shard ${index} has no event from the reviewed PAYO seal.`);
  }
}

const nullifier = [evidence.run.nullifierHigh, evidence.run.nullifierLow];
const stateBlock = orderedShards[1].blockNumber;
const [statusResult, shardZeroResult, shardOneResult] = await Promise.all([
  callAt("get_run_status", nullifier, stateBlock),
  callAt("is_sealed_shard_verified", [...nullifier, "0x0"], stateBlock),
  callAt("is_sealed_shard_verified", [...nullifier, "0x1"], stateBlock),
]);
const status = Number(num.toBigInt(statusResult[0] ?? "0x0"));
const shardsVerified = [shardZeroResult, shardOneResult].map(
  (result) => num.toBigInt(result[0] ?? "0x0") !== 0n,
);
if (status !== evidence.run.onchainStatus || status !== 2) {
  throw new Error(`Mainnet seal status is ${status}; expected proven status 2.`);
}
if (!shardsVerified.every(Boolean)) throw new Error("Mainnet seal does not report both proof shards verified.");

console.log(
  `PAYO STRK Mainnet evidence passed: payroll block ${evidence.payroll.blockNumber}, proof blocks ${orderedShards.map((shard) => shard.blockNumber).join("/")}, seal status proven, both shards verified; private recipient and salary remain withheld.`,
);
