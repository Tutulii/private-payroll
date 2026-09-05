import { createHash } from "node:crypto";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Account, RpcProvider, ec, hash, num, shortString } from "starknet";

const root = resolve(import.meta.dirname, "..");
const action = process.argv[2];
const rpcUrl = process.env.PAYO_DEVNET_RPC_URL ?? "http://127.0.0.1:5050";
const deployerAddress = process.env.PAYO_DEVNET_ACCOUNT_ADDRESS
  ?? "0x009c44d7cc63ad9acbce3ac8032fbc7e0fddcc8d30e35a57ac314b4f149d8026";
const deployerPrivateKey = process.env.PAYO_DEVNET_ACCOUNT_PRIVATE_KEY
  ?? "0x0000000000000000000000000000000020bf7d7f4022a170ad277b362dbf84b1";
const expectedChainId = "0x534e5f5345504f4c4941";
const strkAddress = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const sierraPath = resolve(root, "contracts/target/dev/payo_contracts_PayoPolicyAccount.contract_class.json");
const casmPath = resolve(root, "contracts/target/dev/payo_contracts_PayoPolicyAccount.compiled_contract_class.json");
const evidencePath = resolve(root, "evidence/phase4-policy-account-devnet.json");

if (!new Set(["check-artifacts", "lifecycle"]).has(action)) {
  throw new Error("Usage: node scripts/test-phase4-policy-account-devnet.mjs <check-artifacts|lifecycle>");
}

async function filesRecursively(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  return (await Promise.all(entries.flatMap((entry) => {
    const path = resolve(directory, entry.name);
    return entry.isDirectory() && entry.name !== "target"
      ? [filesRecursively(path)]
      : entry.isFile() ? [[path]] : [];
  }))).flat();
}

async function assertFreshArtifacts() {
  const sources = [
    resolve(root, "contracts/Scarb.toml"),
    resolve(root, "contracts/Scarb.lock"),
    ...await filesRecursively(resolve(root, "contracts/src")),
  ];
  const sourceTime = Math.max(...await Promise.all(sources.map(async (path) => (await stat(path)).mtimeMs)));
  for (const path of [sierraPath, casmPath]) {
    const artifact = await stat(path);
    if (artifact.mtimeMs < sourceTime) {
      throw new Error(`Refusing stale policy-account artifact ${path}. Rebuild contracts with pinned Scarb/USC.`);
    }
  }
}

await assertFreshArtifacts();
if (action === "check-artifacts") {
  process.stdout.write("PayoPolicyAccount Sierra and CASM artifacts are fresh.\n");
  process.exit(0);
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function rpc(method, params = []) {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: method, method, params }),
  });
  if (!response.ok) throw new Error(`${method} returned HTTP ${response.status}.`);
  const payload = await response.json();
  if (payload.error) throw new Error(`${method} failed: ${JSON.stringify(payload.error)}`);
  return payload.result;
}

const toolchains = await readJson(resolve(root, "toolchains.lock.json"));
const rpcVersion = await rpc("starknet_specVersion");
if (rpcVersion !== toolchains.starknet.starknetDevnetRpc) {
  throw new Error(`Devnet RPC ${rpcVersion} does not match pinned ${toolchains.starknet.starknetDevnetRpc}.`);
}
const provider = new RpcProvider({ nodeUrl: rpcUrl });
const chainId = await provider.getChainId();
if (BigInt(chainId) !== BigInt(expectedChainId)) throw new Error(`Refusing lifecycle mutation on chain ${chainId}.`);
const deployer = new Account({
  provider,
  address: deployerAddress,
  signer: deployerPrivateKey,
  cairoVersion: "1",
});

async function waitFor(transactionHash) {
  const receipt = await provider.waitForTransaction(transactionHash, { retries: 1_200, retryInterval: 250 });
  if (receipt.isReverted()) throw new Error(`Transaction ${transactionHash} reverted: ${receipt.revert_reason}.`);
  return receipt;
}

async function invoke(account, call) {
  const response = await account.execute(call, { tip: 0 });
  await waitFor(response.transaction_hash);
  return response.transaction_hash;
}

function felt(value) {
  return num.toHex(BigInt(value));
}

function boolResult(values, label) {
  if (values.length !== 1 || ![0n, 1n].includes(BigInt(values[0]))) {
    throw new Error(`${label} returned an invalid Cairo boolean.`);
  }
  return BigInt(values[0]) === 1n;
}

async function call(address, entrypoint, calldata = [], blockIdentifier = "latest") {
  return provider.callContract({ contractAddress: address, entrypoint, calldata }, blockIdentifier);
}

const [sierra, casm] = await Promise.all([readJson(sierraPath), readJson(casmPath)]);
const declaration = await deployer.declareIfNot({ contract: sierra, casm }, { tip: 0 });
if (declaration.transaction_hash) await waitFor(declaration.transaction_hash);
const classHash = felt(declaration.class_hash);
const ownerPrivateKey = "0x314159265358979323846264338327950288419716939937510";
const replacementOwnerPrivateKey = "0x271828182845904523536028747135266249775724709369995";
const sessionPrivateKey = "0x161803398874989484820458683436563811772030917980576";
const replacementSessionPrivateKey = "0x141421356237309504880168872420969807856967187537694";
const ownerPublicKey = felt(ec.starkCurve.getStarkKey(ownerPrivateKey));
const replacementOwnerPublicKey = felt(ec.starkCurve.getStarkKey(replacementOwnerPrivateKey));
const sessionPublicKey = felt(ec.starkCurve.getStarkKey(sessionPrivateKey));
const replacementSessionPublicKey = felt(ec.starkCurve.getStarkKey(replacementSessionPrivateKey));
const deployment = await deployer.deployContract({
  classHash,
  constructorCalldata: [ownerPublicKey],
  salt: "0x7061796f3401",
  unique: false,
}, { tip: 0 });
await waitFor(deployment.transaction_hash);
const policyAccountAddress = felt(deployment.contract_address);
const actualClassHash = felt(await provider.getClassHashAt(policyAccountAddress));
if (BigInt(actualClassHash) !== BigInt(classHash)) throw new Error("Deployed policy-account class hash mismatch.");

// Fee funding is public Devnet infrastructure funding, never payroll custody.
const fundingTransactionHash = await invoke(deployer, {
  contractAddress: strkAddress,
  entrypoint: "transfer",
  calldata: [policyAccountAddress, felt(10n ** 20n), "0x0"],
});
let owner = new Account({ provider, address: policyAccountAddress, signer: ownerPrivateKey, cairoVersion: "1" });
const src6Id = "0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd";
const src9V2Id = "0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872";
if (!boolResult(await call(policyAccountAddress, "supports_interface", [src6Id]), "SNIP-6 support")) {
  throw new Error("Deployed policy account does not expose SNIP-6.");
}
if (!boolResult(await call(policyAccountAddress, "supports_interface", [src9V2Id]), "SNIP-9 V2 support")) {
  throw new Error("Deployed policy account does not expose SNIP-9 V2.");
}

const latest = await provider.getBlock("latest");
const now = BigInt(latest.timestamp);
const validAfter = now - 1n;
const validBefore = now + 3_600n;
const policyId = felt(hash.starknetKeccak("PAYO_PHASE4_DEVNET_POLICY_1"));
const policyRoot = BigInt(`0x${"11".repeat(32)}`);
const u128Mask = (1n << 128n) - 1n;
const configureCall = {
  contractAddress: policyAccountAddress,
  entrypoint: "configure_policy",
  calldata: [
    policyId,
    sessionPublicKey,
    felt(deployerAddress),
    felt(deployerAddress),
    "0x0",
    "0x0",
    "0x2",
    "0x1",
    felt(policyRoot >> 128n),
    felt(policyRoot & u128Mask),
    felt(hash.computePoseidonHashOnElements([shortString.encodeShortString("STRK"), 1])),
    felt(hash.computePoseidonHashOnElements([shortString.encodeShortString("recipient"), 1])),
    felt(hash.computePoseidonHashOnElements([shortString.encodeShortString("payroll"), 1])),
    felt(hash.computePoseidonHashOnElements([shortString.encodeShortString("amount"), 1])),
    felt(hash.computePoseidonHashOnElements([shortString.encodeShortString("runs"), 1])),
    felt(validAfter),
    felt(validBefore),
    "0x258",
    "0x1",
    "0x3",
  ],
};
const configureTransactionHash = await invoke(owner, configureCall);
let policy = await call(policyAccountAddress, "get_policy", [policyId]);
if (policy.length !== 24 || BigInt(policy[0]) !== 1n || BigInt(policy[1]) !== 0n) {
  throw new Error("Configured policy did not round-trip from chain.");
}
if (BigInt(policy[2]) !== BigInt(sessionPublicKey)) throw new Error("Initial session key mismatch.");
if (!boolResult(await call(policyAccountAddress, "is_policy_active", [policyId]), "Policy active state")) {
  throw new Error("Configured policy is not active.");
}

const rotateSessionTransactionHash = await invoke(owner, {
  contractAddress: policyAccountAddress,
  entrypoint: "rotate_session_key",
  calldata: [policyId, replacementSessionPublicKey],
});
policy = await call(policyAccountAddress, "get_policy", [policyId]);
if (BigInt(policy[2]) !== BigInt(replacementSessionPublicKey)) throw new Error("Session rotation did not persist.");

const pauseTransactionHash = await invoke(owner, {
  contractAddress: policyAccountAddress,
  entrypoint: "set_policy_account_paused",
  calldata: ["0x1"],
});
if (!boolResult(await call(policyAccountAddress, "is_policy_account_paused"), "Paused state")) {
  throw new Error("Policy account did not pause.");
}
const unpauseTransactionHash = await invoke(owner, {
  contractAddress: policyAccountAddress,
  entrypoint: "set_policy_account_paused",
  calldata: ["0x0"],
});
if (boolResult(await call(policyAccountAddress, "is_policy_account_paused"), "Unpaused state")) {
  throw new Error("Policy account did not unpause.");
}

const acceptanceHash = felt(hash.computePoseidonHashOnElements([
  shortString.encodeShortString("StarkNet Message"),
  shortString.encodeShortString("accept_ownership"),
  policyAccountAddress,
  ownerPublicKey,
]));
const acceptanceSignature = ec.starkCurve.sign(acceptanceHash, replacementOwnerPrivateKey);
const rotateOwnerTransactionHash = await invoke(owner, {
  contractAddress: policyAccountAddress,
  entrypoint: "set_public_key",
  calldata: [
    replacementOwnerPublicKey,
    "0x2",
    felt(acceptanceSignature.r),
    felt(acceptanceSignature.s),
  ],
});
const currentOwner = await call(policyAccountAddress, "get_public_key");
if (currentOwner.length !== 1 || BigInt(currentOwner[0]) !== BigInt(replacementOwnerPublicKey)) {
  throw new Error("Owner recovery did not persist the replacement key.");
}

let previousOwnerRejected = false;
try {
  await owner.execute({
    contractAddress: policyAccountAddress,
    entrypoint: "set_policy_account_paused",
    calldata: ["0x1"],
  }, { tip: 0 });
} catch {
  previousOwnerRejected = true;
}
if (!previousOwnerRejected) throw new Error("The previous owner still passed transaction validation.");

owner = new Account({
  provider,
  address: policyAccountAddress,
  signer: replacementOwnerPrivateKey,
  cairoVersion: "1",
});
const revokeTransactionHash = await invoke(owner, {
  contractAddress: policyAccountAddress,
  entrypoint: "revoke_policy",
  calldata: [policyId],
});
policy = await call(policyAccountAddress, "get_policy", [policyId]);
if (BigInt(policy[1]) !== 1n) throw new Error("Policy revocation did not persist.");
if (boolResult(await call(policyAccountAddress, "is_policy_active", [policyId]), "Revoked policy active state")) {
  throw new Error("A revoked policy remained active.");
}

const finalBlock = await provider.getBlock("latest");
const evidence = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  scope: "phase4-policy-account-lifecycle-only",
  limitations: [
    "Lifecycle targets are nonzero Devnet sentinels; private STRK20 settlement is a separate P4-04 gate.",
    "No owner or session private key is stored in this evidence.",
  ],
  toolchain: {
    starknetDevnet: toolchains.starknet.starknetDevnet,
    rpcVersion,
    scarb: toolchains.starknet.scarb,
    universalSierraCompiler: toolchains.starknet.universalSierraCompiler,
  },
  chain: {
    chainId: felt(chainId),
    finalBlockNumber: finalBlock.block_number,
    finalBlockHash: felt(finalBlock.block_hash),
  },
  artifact: {
    classHash,
    sierraSha256: createHash("sha256").update(JSON.stringify(sierra)).digest("hex"),
    casmSha256: createHash("sha256").update(JSON.stringify(casm)).digest("hex"),
    declarationTransactionHash: declaration.transaction_hash ?? null,
  },
  account: {
    address: policyAccountAddress,
    deploymentTransactionHash: deployment.transaction_hash,
    fundingTransactionHash,
    snip6: true,
    snip9V2: true,
    previousOwnerRejected,
  },
  policy: {
    policyId,
    configured: true,
    sessionRotated: true,
    pauseRoundTrip: true,
    ownerRecovered: true,
    revoked: true,
    transactions: {
      configure: configureTransactionHash,
      rotateSession: rotateSessionTransactionHash,
      pause: pauseTransactionHash,
      unpause: unpauseTransactionHash,
      rotateOwner: rotateOwnerTransactionHash,
      revoke: revokeTransactionHash,
    },
  },
};
await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
