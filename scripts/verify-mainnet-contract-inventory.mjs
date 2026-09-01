import { readFile } from "node:fs/promises";
import { RpcProvider, constants, num } from "starknet";

const inventory = JSON.parse(
  await readFile(
    new URL("../evidence/mainnet-contract-inventory.json", import.meta.url),
    "utf8",
  ),
);

function sameFelt(left, right) {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

if (
  inventory.schemaVersion !== 1 ||
  inventory.network !== "starknet-mainnet" ||
  !Array.isArray(inventory.contracts) ||
  inventory.contracts.length < 3
) {
  throw new Error("The Mainnet contract inventory is malformed.");
}
const addresses = new Set();
for (const contract of inventory.contracts) {
  if (
    typeof contract.name !== "string" ||
    typeof contract.role !== "string" ||
    !/^0x[0-9a-f]+$/i.test(contract.address) ||
    !/^0x[0-9a-f]+$/i.test(contract.classHash)
  ) {
    throw new Error(`Malformed contract inventory row: ${contract?.name ?? "unknown"}.`);
  }
  const canonical = num.toHex(BigInt(contract.address));
  if (addresses.has(canonical)) {
    throw new Error(`Duplicate Mainnet contract address: ${canonical}.`);
  }
  addresses.add(canonical);
}

const rpcUrl =
  process.env.STARKNET_RPC_URL?.trim() ||
  process.env.NEXT_PUBLIC_STARKNET_RPC_URL?.trim();
if (!rpcUrl) throw new Error("STARKNET_RPC_URL is required.");
const provider = new RpcProvider({ nodeUrl: rpcUrl });
const chainId = await provider.getChainId();
if (
  !sameFelt(chainId, constants.StarknetChainId.SN_MAIN) ||
  !sameFelt(chainId, inventory.chainId)
) {
  throw new Error("The contract inventory verifier is pinned to Starknet Mainnet.");
}
const blockNumber = await provider.getBlockNumber();
const checks = [];
for (const contract of inventory.contracts) {
  const actualClassHash = num.toHex(
    BigInt(await provider.getClassHashAt(contract.address, blockNumber)),
  );
  const passed = sameFelt(actualClassHash, contract.classHash);
  checks.push({
    name: contract.name,
    address: num.toHex(BigInt(contract.address)),
    expectedClassHash: num.toHex(BigInt(contract.classHash)),
    actualClassHash,
    passed,
  });
}
const failed = checks.filter((check) => !check.passed);
if (failed.length > 0) {
  throw new Error(
    `Mainnet contract inventory mismatch: ${failed.map((check) => check.name).join(", ")}.`,
  );
}
process.stdout.write(
  `${JSON.stringify(
    {
      verified: true,
      chainId: num.toHex(BigInt(chainId)),
      blockNumber,
      contracts: checks,
    },
    null,
    2,
  )}\n`,
);
