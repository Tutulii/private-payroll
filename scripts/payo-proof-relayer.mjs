import {
  Account,
  CallData,
  RpcProvider,
  constants,
  ec,
  hash,
  num,
  uint256,
  validateAndParseAddress,
} from "starknet";

const OPENZEPPELIN_ACCOUNT_CLASS_HASH =
  "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381";
const STRK_TOKEN_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const DEPLOY_CONFIRMATION = "DEPLOY_PAYO_RELAYER_MAINNET";
const action = process.argv[2];

if (!["status", "estimate-deploy", "deploy"].includes(action)) {
  throw new Error(
    "Usage: node scripts/payo-proof-relayer.mjs <status|estimate-deploy|deploy>",
  );
}

const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
if (!rpcUrl) throw new Error("STARKNET_RPC_URL is required.");
const provider = new RpcProvider({ nodeUrl: rpcUrl });

function canonicalAddress(value, label) {
  if (!value) throw new Error(`${label} is required.`);
  try {
    const address = validateAndParseAddress(value);
    if (BigInt(address) === 0n) throw new Error();
    return num.toHex(BigInt(address));
  } catch {
    throw new Error(`${label} must be a non-zero Starknet address.`);
  }
}

function isMissingContract(error) {
  return /contract not found|contract_address_not_found|uninitialized contract/i.test(
    error instanceof Error ? error.message : String(error),
  );
}

async function requireMainnet() {
  const chainId = await provider.getChainId();
  if (BigInt(chainId) !== BigInt(constants.StarknetChainId.SN_MAIN)) {
    throw new Error(`Refusing relayer operation: RPC reports non-Mainnet chain ID ${chainId}.`);
  }
}

function relayerIdentity() {
  const privateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error("PAYO_PROOF_RELAYER_PRIVATE_KEY is missing or invalid.");
  }
  const publicKey = num.toHex(BigInt(ec.starkCurve.getStarkKey(privateKey)));
  const derivedAddress = num.toHex(BigInt(hash.calculateContractAddressFromHash(
    publicKey,
    OPENZEPPELIN_ACCOUNT_CLASS_HASH,
    CallData.compile([publicKey]),
    0,
  )));
  const configuredAddress = canonicalAddress(
    process.env.PAYO_PROOF_RELAYER_ADDRESS,
    "PAYO_PROOF_RELAYER_ADDRESS",
  );
  if (BigInt(derivedAddress) !== BigInt(configuredAddress)) {
    throw new Error("The proof-relayer private key does not derive the configured address.");
  }
  return { privateKey, publicKey, address: configuredAddress };
}

async function deployedClassHash(address) {
  try {
    return num.toHex(BigInt(await provider.getClassHashAt(address, "latest")));
  } catch (error) {
    if (isMissingContract(error)) return null;
    throw error;
  }
}

async function strkBalance(address) {
  const response = await provider.callContract({
    contractAddress: STRK_TOKEN_ADDRESS,
    entrypoint: "balanceOf",
    calldata: CallData.compile([address]),
  }, "latest");
  if (response.length !== 2) throw new Error("STRK balanceOf returned an invalid u256.");
  return uint256.uint256ToBN({ low: response[0], high: response[1] });
}

function decimalStrk(value) {
  const whole = value / 10n ** 18n;
  const fraction = (value % 10n ** 18n).toString().padStart(18, "0").slice(0, 6);
  return `${whole}.${fraction}`;
}

function accountFor(identity) {
  return new Account({
    provider,
    address: identity.address,
    signer: identity.privateKey,
    cairoVersion: "1",
  });
}

async function estimateDeployment(identity) {
  const estimate = await accountFor(identity).estimateAccountDeployFee({
    classHash: OPENZEPPELIN_ACCOUNT_CLASS_HASH,
    constructorCalldata: [identity.publicKey],
    addressSalt: identity.publicKey,
    contractAddress: identity.address,
  });
  const maximumFee = BigInt(estimate.suggestedMaxFee ?? estimate.overall_fee);
  return { estimate, maximumFee };
}

await requireMainnet();
const identity = relayerIdentity();
const [classHash, balance, accountClass] = await Promise.all([
  deployedClassHash(identity.address),
  strkBalance(identity.address),
  provider.getClass(OPENZEPPELIN_ACCOUNT_CLASS_HASH, "latest"),
]);
if (!accountClass) throw new Error("The pinned OpenZeppelin account class is not declared.");
if (classHash && BigInt(classHash) !== BigInt(OPENZEPPELIN_ACCOUNT_CLASS_HASH)) {
  throw new Error("The configured relayer address contains an unexpected account class.");
}

if (action === "status") {
  console.log(JSON.stringify({
    network: "starknet-mainnet",
    address: identity.address,
    publicKey: identity.publicKey,
    accountClassHash: OPENZEPPELIN_ACCOUNT_CLASS_HASH,
    deployed: classHash !== null,
    strkBalanceAtomic: balance.toString(),
    strkBalance: decimalStrk(balance),
  }, null, 2));
  process.exit(0);
}

if (classHash) {
  console.log(JSON.stringify({
    network: "starknet-mainnet",
    address: identity.address,
    deployed: true,
    classHash,
    strkBalanceAtomic: balance.toString(),
    strkBalance: decimalStrk(balance),
    transactionHash: null,
  }, null, 2));
  process.exit(0);
}

const { estimate, maximumFee } = await estimateDeployment(identity);
if (action === "estimate-deploy") {
  console.log(JSON.stringify({
    network: "starknet-mainnet",
    address: identity.address,
    deployed: false,
    strkBalanceAtomic: balance.toString(),
    strkBalance: decimalStrk(balance),
    estimatedMaximumFeeAtomic: maximumFee.toString(),
    estimatedMaximumFeeStrk: decimalStrk(maximumFee),
    fundedForDeployment: balance >= maximumFee,
  }, null, 2));
  process.exit(0);
}

if (process.env.PAYO_RELAYER_CONFIRM !== DEPLOY_CONFIRMATION) {
  throw new Error(
    `Set PAYO_RELAYER_CONFIRM=${DEPLOY_CONFIRMATION} only after reviewing the address, funding, and estimate.`,
  );
}
if (balance < maximumFee) {
  throw new Error(
    `Relayer balance ${decimalStrk(balance)} STRK is below the estimated ${decimalStrk(maximumFee)} STRK deployment maximum.`,
  );
}

const deployment = await accountFor(identity).deployAccount({
  classHash: OPENZEPPELIN_ACCOUNT_CLASS_HASH,
  constructorCalldata: [identity.publicKey],
  addressSalt: identity.publicKey,
  contractAddress: identity.address,
}, { resourceBounds: estimate.resourceBounds });
await provider.waitForTransaction(deployment.transaction_hash, {
  retries: 200,
  retryInterval: 3_000,
});
const verifiedClassHash = await deployedClassHash(identity.address);
if (!verifiedClassHash || BigInt(verifiedClassHash) !== BigInt(OPENZEPPELIN_ACCOUNT_CLASS_HASH)) {
  throw new Error("Relayer deployment confirmed but the pinned account class was not found.");
}
console.log(JSON.stringify({
  network: "starknet-mainnet",
  address: identity.address,
  deployed: true,
  classHash: verifiedClassHash,
  transactionHash: deployment.transaction_hash,
}, null, 2));
