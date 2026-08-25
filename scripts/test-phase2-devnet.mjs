import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Account,
  Contract,
  RpcProvider,
  hash,
  num,
} from "starknet";
import {
  assertFreshPayoDeployArtifacts,
  payoArtifactDefinitions as artifactDefinitions,
} from "./lib/payo-contract-artifacts.mjs";

const root = resolve(import.meta.dirname, "..");
const target = resolve(root, "circuits/payroll_integrity/target");
const deploymentPath = resolve(target, "phase2-devnet-deployment.json");
const evidencePath = resolve(target, "phase2-devnet-evidence.json");
const proverPath = resolve(root, "circuits/payroll_integrity/Prover-devnet.toml");
const rpcUrl = process.env.PAYO_DEVNET_RPC_URL ?? "http://127.0.0.1:5050";
const accountAddress = process.env.PAYO_DEVNET_ACCOUNT_ADDRESS
  ?? "0x009c44d7cc63ad9acbce3ac8032fbc7e0fddcc8d30e35a57ac314b4f149d8026";
const accountPrivateKey = process.env.PAYO_DEVNET_ACCOUNT_PRIVATE_KEY
  ?? "0x20bf7d7f4022a170ad277b362dbf84b1";
const action = process.argv[2];

if (!["check-artifacts", "deploy", "schedule", "verify"].includes(action)) {
  throw new Error("Usage: node scripts/test-phase2-devnet.mjs <check-artifacts|deploy|schedule|verify>");
}

if (action === "check-artifacts") {
  await assertFreshPayoDeployArtifacts();
  process.stdout.write("PAYO deploy artifacts exist and are newer than their Cairo sources.\n");
  process.exit(0);
}

async function readJson(path) {
  return JSON.parse(await readFile(resolve(root, path), "utf8"));
}

async function devnetRpc(method, params = {}) {
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

const devnetStatus = await devnetRpc("devnet_getStatus");
if (!devnetStatus || typeof devnetStatus !== "object") {
  throw new Error("PAYO Phase 2 integration requires a standalone Starknet Devnet RPC.");
}
const toolchains = await readJson("toolchains.lock.json");
if (devnetStatus.protocol_version !== toolchains.starknet.starknetDevnetRpc) {
  throw new Error(
    `Devnet RPC ${devnetStatus.protocol_version} does not match pinned ${toolchains.starknet.starknetDevnetRpc}.`,
  );
}

const provider = new RpcProvider({ nodeUrl: rpcUrl });
const chainId = await provider.getChainId();
if (chainId !== "0x534e5f5345504f4c4941") {
  throw new Error(`Refusing to run a devnet mutation against chain ID ${chainId}.`);
}
const account = new Account({
  provider,
  address: accountAddress,
  signer: accountPrivateKey,
  cairoVersion: "1",
});

async function waitFor(transactionHash) {
  if (!transactionHash) return null;
  return provider.waitForTransaction(transactionHash, { retries: 480, retryInterval: 250 });
}

async function declareContract(definition) {
  const [contract, casm] = await Promise.all([
    readJson(definition.sierra),
    readJson(definition.casm),
  ]);
  const declaration = await account.declareIfNot({ contract, casm }, { tip: 0 });
  await waitFor(declaration.transaction_hash);
  return {
    abi: contract.abi,
    classHash: num.toHex(BigInt(declaration.class_hash)),
    declarationTransactionHash: declaration.transaction_hash || null,
  };
}

async function deployContract(declaration, constructorCalldata, salt) {
  const deployment = await account.deployContract(
    {
      classHash: declaration.classHash,
      constructorCalldata,
      salt,
      unique: false,
    },
    { tip: 0 },
  );
  await waitFor(deployment.transaction_hash);
  const actualClassHash = num.toHex(BigInt(
    await provider.getClassHashAt(deployment.contract_address),
  ));
  if (actualClassHash !== declaration.classHash) {
    throw new Error(`Deployed class hash ${actualClassHash} does not match ${declaration.classHash}.`);
  }
  return {
    address: num.toHex(BigInt(deployment.contract_address)),
    transactionHash: deployment.transaction_hash,
  };
}

function contractFor(artifact, address) {
  return new Contract({ abi: artifact.abi, address, providerOrAccount: account });
}

function readTomlScalar(source, key) {
  const match = source.match(new RegExp(`^${key}\\s*=\\s*"([^"]+)"`, "m"));
  if (!match) throw new Error(`Missing ${key} in ${proverPath}.`);
  return match[1];
}

function readTomlFirstNestedScalar(source, key) {
  const match = source.match(new RegExp(`${key}\\s*=\\s*"([^"]+)"`));
  if (!match) throw new Error(`Missing nested ${key} in ${proverPath}.`);
  return match[1];
}

function parseProofCalldata(source) {
  const values = source.trim().split(/\s+/).filter(Boolean);
  if (values.length < 100) throw new Error("Generated Garaga proof calldata is unexpectedly short.");
  for (const value of values) {
    if (!/^0x[0-9a-f]+$/i.test(value)) throw new Error(`Malformed proof felt: ${value}`);
  }
  return values;
}

function asScalar(value) {
  if (["bigint", "number", "string"].includes(typeof value)) return BigInt(value);
  if (Array.isArray(value) && value.length === 1) return asScalar(value[0]);
  if (value && typeof value === "object") {
    const values = Object.values(value);
    if (values.length === 1) return asScalar(values[0]);
  }
  throw new Error(`Expected a scalar Starknet response; received ${JSON.stringify(value)}.`);
}

if (action === "deploy") {
  await assertFreshPayoDeployArtifacts();
  const declarations = {};
  for (const [name, definition] of Object.entries(artifactDefinitions)) {
    declarations[name] = await declareContract(definition);
  }

  const generatedVerifier = await deployContract(
    declarations.generatedVerifier,
    [],
    "0x7061796f2d7665726966696572",
  );
  const bundleVerifier = await deployContract(
    declarations.bundleVerifier,
    [generatedVerifier.address],
    "0x7061796f2d62756e646c65",
  );
  const policyRegistry = await deployContract(
    declarations.policyRegistry,
    [accountAddress],
    "0x7061796f2d706f6c696379",
  );
  const obligationRegistry = await deployContract(
    declarations.obligationRegistry,
    [accountAddress],
    "0x7061796f2d6f626c69676174696f6e",
  );
  const payrollSeal = await deployContract(
    declarations.payrollSeal,
    [accountAddress, policyRegistry.address, obligationRegistry.address, chainId],
    "0x7061796f2d7365616c",
  );

  const latest = await provider.getBlock("latest");
  const activationAt = Number(latest.timestamp) + 90_000;
  const expiresAt = activationAt + 7_200;
  const deployment = {
    schemaVersion: 1,
    devnetVersion: toolchains.starknet.starknetDevnet,
    rpcVersion: devnetStatus.protocol_version,
    chainId,
    rpcUrl,
    accountAddress: num.toHex(BigInt(accountAddress)),
    activationAt,
    expiresAt,
    classes: Object.fromEntries(
      Object.entries(declarations).map(([name, value]) => [name, {
        classHash: value.classHash,
        declarationTransactionHash: value.declarationTransactionHash,
      }]),
    ),
    contracts: {
      generatedVerifier,
      bundleVerifier,
      policyRegistry,
      obligationRegistry,
      payrollSeal,
    },
  };
  await writeFile(deploymentPath, `${JSON.stringify(deployment, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify(deployment, null, 2)}\n`);
}

if (action === "schedule") {
  const [deployment, prover] = await Promise.all([
    readJson("circuits/payroll_integrity/target/phase2-devnet-deployment.json"),
    readFile(proverPath, "utf8"),
  ]);
  const roots = {
    agreement: [readTomlScalar(prover, "agreement_root_high"), readTomlScalar(prover, "agreement_root_low")],
    policy: [readTomlScalar(prover, "policy_root_high"), readTomlScalar(prover, "policy_root_low")],
    fx: [readTomlScalar(prover, "fx_root_high"), readTomlScalar(prover, "fx_root_low")],
  };
  const policy = contractFor(
    { abi: await readJson(artifactDefinitions.policyRegistry.sierra).then((value) => value.abi) },
    deployment.contracts.policyRegistry.address,
  );
  const obligations = contractFor(
    { abi: await readJson(artifactDefinitions.obligationRegistry.sierra).then((value) => value.abi) },
    deployment.contracts.obligationRegistry.address,
  );
  const calls = [
    policy.populate("schedule_policy_root", [...roots.policy, deployment.activationAt, deployment.expiresAt]),
    policy.populate("schedule_verifier", [0, 1, deployment.contracts.bundleVerifier.address, deployment.activationAt, deployment.expiresAt]),
    obligations.populate("schedule_obligation_root", [...roots.agreement, deployment.activationAt, deployment.expiresAt]),
  ];
  const scheduled = await account.execute(calls, { tip: 0 });
  await waitFor(scheduled.transaction_hash);
  const [policyActive, verifierActive, obligationActive] = await Promise.all([
    policy.call("is_policy_root_valid", roots.policy),
    policy.call("is_verifier_valid", [0, 1]),
    obligations.call("is_obligation_root_valid", roots.agreement),
  ]);
  if (![policyActive, verifierActive, obligationActive].every(Boolean)) {
    throw new Error("A Phase 2 registry entry did not activate in its confirming block.");
  }
  deployment.roots = roots;
  deployment.scheduleTransactionHash = scheduled.transaction_hash;
  deployment.registryActivation = {
    immediate: true,
    verifiedAtBlock: await provider.getBlockNumber(),
  };
  await writeFile(deploymentPath, `${JSON.stringify(deployment, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ roots, transactionHash: scheduled.transaction_hash }, null, 2)}\n`);
}

if (action === "verify") {
  const deployment = await readJson("circuits/payroll_integrity/target/phase2-devnet-deployment.json");
  if (!deployment.roots || !deployment.scheduleTransactionHash) {
    throw new Error("The Phase 2 registry schedule has not been submitted.");
  }
  if (!deployment.registryActivation?.immediate) {
    throw new Error("The Phase 2 registry schedule lacks immediate-activation evidence.");
  }
  const [sealArtifact, policyArtifact, obligationArtifact, shardZeroSource, shardOneSource] = await Promise.all([
    readJson(artifactDefinitions.payrollSeal.sierra),
    readJson(artifactDefinitions.policyRegistry.sierra),
    readJson(artifactDefinitions.obligationRegistry.sierra),
    readFile(resolve(target, "proof_calldata-devnet-shard-0.txt"), "utf8"),
    readFile(resolve(target, "proof_calldata-devnet-shard-1.txt"), "utf8"),
  ]);
  const shardZero = parseProofCalldata(shardZeroSource);
  const shardOne = parseProofCalldata(shardOneSource);
  const shardZeroHash = num.toHex(hash.computePoseidonHashOnElements(shardZero));
  const shardOneHash = num.toHex(hash.computePoseidonHashOnElements(shardOne));
  const prover = await readFile(proverPath, "utf8");
  const runNullifier = [
    readTomlScalar(prover, "run_nullifier_high"),
    readTomlScalar(prover, "run_nullifier_low"),
  ];
  const publicInputs = {
    agreement: deployment.roots.agreement,
    manifest: [readTomlScalar(prover, "manifest_root_high"), readTomlScalar(prover, "manifest_root_low")],
    policy: deployment.roots.policy,
    fx: deployment.roots.fx,
    runNullifier,
    validityStart: readTomlScalar(prover, "validity_start"),
    validityExpiry: readTomlScalar(prover, "validity_expiry"),
  };
  if (Number(publicInputs.validityStart) !== deployment.activationAt) {
    throw new Error("Proof validity does not begin at the activated registry timestamp.");
  }

  await devnetRpc("devnet_setTime", { time: deployment.activationAt });
  const policy = contractFor({ abi: policyArtifact.abi }, deployment.contracts.policyRegistry.address);
  const obligations = contractFor({ abi: obligationArtifact.abi }, deployment.contracts.obligationRegistry.address);
  const seal = contractFor({ abi: sealArtifact.abi }, deployment.contracts.payrollSeal.address);
  const fxObservedAt = readTomlFirstNestedScalar(prover, "observed_at");
  const fxMaximumAge = readTomlFirstNestedScalar(prover, "maximum_age_seconds");
  const publishedFx = await account.execute(
    policy.populate("publish_fx_root", [
      ...publicInputs.fx,
      fxObservedAt,
      fxMaximumAge,
    ]),
    { tip: 0 },
  );
  await waitFor(publishedFx.transaction_hash);
  const [policyActive, fxActive, verifierActive, obligationActive] = await Promise.all([
    policy.call("is_policy_root_valid", publicInputs.policy),
    policy.call("is_fx_root_valid", publicInputs.fx),
    policy.call("is_verifier_valid", [0, 1]),
    obligations.call("is_obligation_root_valid", publicInputs.agreement),
  ]);
  if (![policyActive, fxActive, verifierActive, obligationActive].every(Boolean)) {
    throw new Error("One or more immediate Phase 2 registry entries are inactive.");
  }

  const sealCall = seal.populate("privacy_invoke", [
    0,
    1,
    1,
    ...publicInputs.agreement,
    ...publicInputs.manifest,
    ...publicInputs.policy,
    ...publicInputs.fx,
    ...runNullifier,
    publicInputs.validityStart,
    publicInputs.validityExpiry,
    shardZeroHash,
    shardOneHash,
    [],
    [],
  ]);
  const sealed = await account.execute(sealCall, { tip: 0 });
  await waitFor(sealed.transaction_hash);
  const sealedStatus = asScalar(await seal.call("get_run_status", runNullifier));
  if (sealedStatus !== 1n) throw new Error(`Expected sealed status 1; received ${sealedStatus}.`);

  const verifiedTransactions = [];
  for (const [shardIndex, calldata] of [[0, shardZero], [1, shardOne]]) {
    const verified = await account.execute(
      seal.populate("verify_sealed_shard", [...runNullifier, shardIndex, calldata]),
      { tip: 0 },
    );
    await waitFor(verified.transaction_hash);
    verifiedTransactions.push(verified.transaction_hash);
  }
  const provenStatus = asScalar(await seal.call("get_run_status", runNullifier));
  if (provenStatus !== 2n) throw new Error(`Expected proven status 2; received ${provenStatus}.`);

  let replayRejected = false;
  try {
    await account.estimateInvokeFee(sealCall, { tip: 0 });
  } catch {
    replayRejected = true;
  }
  if (!replayRejected) throw new Error("Payroll-seal replay was not rejected during simulation.");

  const evidence = {
    schemaVersion: 1,
    passed: true,
    standaloneRpc: rpcUrl,
    devnetVersion: toolchains.starknet.starknetDevnet,
    rpcVersion: devnetStatus.protocol_version,
    chainId,
    contracts: deployment.contracts,
    classes: deployment.classes,
    roots: deployment.roots,
    registryActivation: deployment.registryActivation,
    activationAt: deployment.activationAt,
    expiryAt: deployment.expiresAt,
    transactions: {
      schedule: deployment.scheduleTransactionHash,
      publishFx: publishedFx.transaction_hash,
      seal: sealed.transaction_hash,
      verifyShards: verifiedTransactions,
    },
    proofHashes: [shardZeroHash, shardOneHash],
    runNullifier,
    finalStatus: provenStatus.toString(),
    replayRejected,
  };
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}
