import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Account, Contract, RpcProvider, hash, num } from "starknet";

const root = resolve(import.meta.dirname, "..");
const fixtures = resolve(root, "evidence/phase3-devnet-fixtures");
const deploymentPath = resolve(root, "evidence/phase3-devnet-deployment.json");
const evidencePath = resolve(root, "evidence/phase3-devnet.json");
const rpcUrl = process.env.PAYO_DEVNET_RPC_URL ?? "http://127.0.0.1:5050";
const accountAddress = process.env.PAYO_DEVNET_ACCOUNT_ADDRESS
  ?? "0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691";
const accountPrivateKey = process.env.PAYO_DEVNET_ACCOUNT_PRIVATE_KEY
  ?? "0x0000000000000000000000000000000071d7bb07b9a64f6f78ac4c816aff4da9";
const poolCallerAddress = process.env.PAYO_DEVNET_POOL_ADDRESS ?? accountAddress;
const devnetVersion = process.env.PAYO_DEVNET_VERSION;
const expectedChainId = "0x534e5f5345504f4c4941";
const action = process.argv[2];

const artifacts = Object.freeze({
  baseVerifier: {
    sierra: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.contract_class.json",
    casm: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.compiled_contract_class.json",
    sources: "contracts/integrity_verifier",
  },
  advancedVerifier: {
    sierra: "contracts/advanced_verifier/target/dev/advanced_verifier_PayoAdvancedObligationVerifier.contract_class.json",
    casm: "contracts/advanced_verifier/target/dev/advanced_verifier_PayoAdvancedObligationVerifier.compiled_contract_class.json",
    sources: "contracts/advanced_verifier",
  },
  claimVerifier: {
    sierra: "contracts/claim_verifier/target/dev/claim_verifier_PayoWageClaimVerifier.contract_class.json",
    casm: "contracts/claim_verifier/target/dev/claim_verifier_PayoWageClaimVerifier.compiled_contract_class.json",
    sources: "contracts/claim_verifier",
  },
  remediationVerifier: {
    sierra: "contracts/remediation_verifier/target/dev/remediation_verifier_PayoWageRemediationVerifier.contract_class.json",
    casm: "contracts/remediation_verifier/target/dev/remediation_verifier_PayoWageRemediationVerifier.compiled_contract_class.json",
    sources: "contracts/remediation_verifier",
  },
  advancedBundle: {
    sierra: "contracts/target/dev/payo_contracts_PayoAdvancedBundleVerifier.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoAdvancedBundleVerifier.compiled_contract_class.json",
    sources: "contracts",
  },
  integrityBundle: {
    sierra: "contracts/target/dev/payo_contracts_PayoIntegrityBundleVerifier.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoIntegrityBundleVerifier.compiled_contract_class.json",
    sources: "contracts",
  },
  policyRegistry: {
    sierra: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.compiled_contract_class.json",
    sources: "contracts",
  },
  obligationRegistry: {
    sierra: "contracts/target/dev/payo_contracts_PayoObligationRootRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoObligationRootRegistry.compiled_contract_class.json",
    sources: "contracts",
  },
  payrollSeal: {
    sierra: "contracts/target/dev/payo_contracts_PayoPayrollSeal.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPayrollSeal.compiled_contract_class.json",
    sources: "contracts",
  },
});

if (!["check-artifacts", "deploy", "prove", "prove-matrix", "verify", "verify-matrix"].includes(action)) {
  throw new Error("Usage: node scripts/test-phase3-devnet.mjs <check-artifacts|deploy|prove|prove-matrix|verify|verify-matrix>");
}

async function readJson(path) {
  return JSON.parse(await readFile(resolve(root, path), "utf8"));
}

async function filesRecursively(directory, includeTarget = false) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.flatMap((entry) => {
    if (!includeTarget && entry.isDirectory() && entry.name === "target") return [];
    const path = resolve(directory, entry.name);
    return entry.isDirectory() ? [filesRecursively(path, includeTarget)] : [[path]];
  }));
  return nested.flat();
}

async function assertFreshArtifacts() {
  const sourceTimes = new Map();
  for (const definition of Object.values(artifacts)) {
    if (sourceTimes.has(definition.sources)) continue;
    const paths = [
      resolve(root, definition.sources, "Scarb.toml"),
      ...await filesRecursively(resolve(root, definition.sources, "src")),
    ];
    sourceTimes.set(definition.sources, Math.max(...await Promise.all(paths.map(async (path) => (await stat(path)).mtimeMs))));
  }
  for (const [name, definition] of Object.entries(artifacts)) {
    for (const path of [definition.sierra, definition.casm]) {
      let modifiedAt;
      try {
        modifiedAt = (await stat(resolve(root, path))).mtimeMs;
      } catch {
        throw new Error(`Missing ${name} artifact ${path}. Rebuild its pinned Scarb package.`);
      }
      if (modifiedAt < sourceTimes.get(definition.sources)) {
        throw new Error(`Refusing stale ${name} artifact ${path}. Rebuild its pinned Scarb package.`);
      }
    }
  }
}

if (action === "check-artifacts") {
  await assertFreshArtifacts();
  process.stdout.write("All Phase 3 deploy artifacts exist and are newer than their Cairo package sources.\n");
  process.exit(0);
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

const toolchains = await readJson("toolchains.lock.json");
const rpcVersion = await devnetRpc("starknet_specVersion", []);
if (rpcVersion !== toolchains.starknet.starknetDevnetRpc) {
  throw new Error(`Devnet RPC ${rpcVersion} does not match pinned ${toolchains.starknet.starknetDevnetRpc}.`);
}
const provider = new RpcProvider({ nodeUrl: rpcUrl });
const chainId = await provider.getChainId();
if (chainId !== expectedChainId) throw new Error(`Refusing Devnet mutation on chain ${chainId}.`);
const account = new Account({
  provider,
  address: accountAddress,
  signer: accountPrivateKey,
  cairoVersion: "1",
});

async function waitFor(transactionHash) {
  return provider.waitForTransaction(transactionHash, { retries: 1_200, retryInterval: 250 });
}

async function declareContract(definition) {
  const [contract, casm] = await Promise.all([readJson(definition.sierra), readJson(definition.casm)]);
  const declaration = await account.declareIfNot({ contract, casm }, { tip: 0 });
  if (declaration.transaction_hash) await waitFor(declaration.transaction_hash);
  return {
    abi: contract.abi,
    classHash: num.toHex(BigInt(declaration.class_hash)),
    declarationTransactionHash: declaration.transaction_hash || null,
    artifactSha256: createHash("sha256").update(JSON.stringify(contract)).digest("hex"),
  };
}

async function deployContract(declaration, constructorCalldata, salt) {
  const deployment = await account.deployContract({
    classHash: declaration.classHash,
    constructorCalldata,
    salt,
    unique: false,
  }, { tip: 0 });
  await waitFor(deployment.transaction_hash);
  const actualClassHash = num.toHex(BigInt(await provider.getClassHashAt(deployment.contract_address)));
  if (actualClassHash !== declaration.classHash) {
    throw new Error(`Deployed class ${actualClassHash} does not match ${declaration.classHash}.`);
  }
  return { address: num.toHex(BigInt(deployment.contract_address)), transactionHash: deployment.transaction_hash };
}

function contractFor(abi, address) {
  return new Contract({ abi, address, providerOrAccount: account });
}

function asScalar(value) {
  if (["bigint", "number", "string"].includes(typeof value)) return BigInt(value);
  if (Array.isArray(value) && value.length === 1) return asScalar(value[0]);
  if (value && typeof value === "object") {
    const values = Object.values(value);
    if (values.length === 1) return asScalar(values[0]);
  }
  throw new Error(`Expected scalar response, received ${JSON.stringify(value)}.`);
}

if (action === "deploy") {
  await assertFreshArtifacts();
  await devnetRpc("devnet_setTime", { time: 900 });
  const declarations = {};
  for (const [name, definition] of Object.entries(artifacts)) {
    declarations[name] = await declareContract(definition);
  }
  const contracts = {};
  contracts.baseVerifier = await deployContract(declarations.baseVerifier, [], "0x7061796f3301");
  contracts.advancedVerifier = await deployContract(declarations.advancedVerifier, [], "0x7061796f3302");
  contracts.claimVerifier = await deployContract(declarations.claimVerifier, [], "0x7061796f3303");
  contracts.remediationVerifier = await deployContract(declarations.remediationVerifier, [], "0x7061796f3304");
  contracts.advancedBundle = await deployContract(
    declarations.integrityBundle,
    [contracts.advancedVerifier.address],
    "0x7061796f3305",
  );
  contracts.claimBundle = await deployContract(
    declarations.integrityBundle,
    [contracts.claimVerifier.address],
    "0x7061796f3306",
  );
  contracts.remediationBundle = await deployContract(
    declarations.integrityBundle,
    [contracts.remediationVerifier.address],
    "0x7061796f3307",
  );
  contracts.policyRegistry = await deployContract(declarations.policyRegistry, [accountAddress], "0x7061796f3308");
  contracts.obligationRegistry = await deployContract(declarations.obligationRegistry, [accountAddress], "0x7061796f3309");
  contracts.payrollSeal = await deployContract(
    declarations.payrollSeal,
    [poolCallerAddress, contracts.policyRegistry.address, contracts.obligationRegistry.address, chainId],
    "0x7061796f3310",
  );
  const deployment = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    devnetVersion: devnetVersion ?? toolchains.starknet.starknetDevnet,
    rpcVersion,
    rpcUrl,
    chainId,
    accountAddress: num.toHex(BigInt(accountAddress)),
    proofWindow: { validityStart: 1_000, validityExpiry: 2_000 },
    classes: Object.fromEntries(Object.entries(declarations).map(([name, value]) => [name, {
      classHash: value.classHash,
      declarationTransactionHash: value.declarationTransactionHash,
      artifactSha256: value.artifactSha256,
    }])),
    contracts,
  };
  await writeFile(deploymentPath, `${JSON.stringify(deployment, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify(deployment, null, 2)}\n`);
}

async function run(command, args, env) {
  await new Promise((accept, reject) => {
    const child = spawn(command, args, { cwd: root, env: { ...process.env, ...env }, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => code === 0 ? accept() : reject(new Error(`${command} exited ${code ?? signal}.`)));
  });
}

if (action === "prove") {
  const deployment = await readJson("evidence/phase3-devnet-deployment.json");
  const binding = {
    PAYO_PHASE3_CHAIN_ID: deployment.chainId,
    PAYO_PHASE3_SEAL_ADDRESS: deployment.contracts.payrollSeal.address,
    NODE_OPTIONS: [process.env.NODE_OPTIONS, "--conditions=react-server"].filter(Boolean).join(" "),
  };
  await run(resolve(root, "node_modules/.bin/tsx"), ["scripts/generate-phase3-proof-fixtures.ts"], binding);
  await run(resolve(root, "node_modules/.bin/tsx"), ["scripts/generate-phase3-claim-fixtures.ts"], binding);
}

if (action === "prove-matrix") {
  const deployment = await readJson("evidence/phase3-devnet-deployment.json");
  await run(resolve(root, "node_modules/.bin/tsx"), ["scripts/generate-phase3-matrix-fixture.ts"], {
    PAYO_PHASE3_CHAIN_ID: deployment.chainId,
    PAYO_PHASE3_SEAL_ADDRESS: deployment.contracts.payrollSeal.address,
    NODE_OPTIONS: [process.env.NODE_OPTIONS, "--conditions=react-server"].filter(Boolean).join(" "),
  });
}

function normalizeHex(value) {
  return num.toHex(BigInt(value));
}

function proofFields(summary) {
  const first = summary.shards[0].publicInputs;
  const second = summary.shards[1].publicInputs;
  for (const key of Object.keys(first)) {
    if (key !== "shardIndex" && normalizeHex(first[key]) !== normalizeHex(second[key])) {
      throw new Error(`Proof shards disagree on ${key}.`);
    }
  }
  return {
    chainId: normalizeHex(first.chainId),
    sealAddress: normalizeHex(first.sealAddress),
    proofVersion: Number(BigInt(first.proofVersion)),
    schemaVersion: Number(BigInt(first.schemaVersion)),
    agreement: [first.agreementRootHigh, first.agreementRootLow],
    manifest: [first.manifestRootHigh, first.manifestRootLow],
    policy: [first.policyRootHigh, first.policyRootLow],
    fx: [first.fxRootHigh, first.fxRootLow],
    nullifier: [first.runNullifierHigh, first.runNullifierLow],
    validityStart: Number(BigInt(first.validityStart)),
    validityExpiry: Number(BigInt(first.validityExpiry)),
  };
}

async function readProof(profile) {
  const [summary, shard0Source, shard1Source] = await Promise.all([
    readJson(`evidence/phase3-devnet-fixtures/${profile}-proof.json`),
    readFile(resolve(fixtures, `${profile === "advanced" ? "advanced" : profile}-shard-0.txt`), "utf8"),
    readFile(resolve(fixtures, `${profile === "advanced" ? "advanced" : profile}-shard-1.txt`), "utf8"),
  ]);
  const calldata = [shard0Source, shard1Source].map((source) => source.trim().split(/\s+/).filter(Boolean));
  for (const [index, shard] of calldata.entries()) {
    if (shard.length < 1_000 || shard.some((felt) => !/^0x[0-9a-f]+$/i.test(felt))) {
      throw new Error(`${profile} shard ${index} calldata is malformed.`);
    }
    const actualHash = normalizeHex(hash.computePoseidonHashOnElements(shard));
    if (actualHash !== normalizeHex(summary.shards[index].calldataHash)) {
      throw new Error(`${profile} shard ${index} hash is not bound to its proof manifest.`);
    }
  }
  return { profile, summary, fields: proofFields(summary), calldata };
}

async function expectRejected(operation, message) {
  try {
    await operation();
  } catch {
    return true;
  }
  throw new Error(message);
}

if (action === "verify") {
  const deployment = await readJson("evidence/phase3-devnet-deployment.json");
  const [advanced, claim, remediation, policyArtifact, obligationArtifact, sealArtifact,
    advancedBundleArtifact, integrityBundleArtifact] = await Promise.all([
    readProof("advanced"), readProof("claim"), readProof("remediation"),
    readJson(artifacts.policyRegistry.sierra), readJson(artifacts.obligationRegistry.sierra),
    readJson(artifacts.payrollSeal.sierra), readJson(artifacts.integrityBundle.sierra),
    readJson(artifacts.integrityBundle.sierra),
  ]);
  const profiles = [advanced, claim, remediation];
  for (const proof of profiles) {
    if (proof.fields.chainId !== chainId) throw new Error(`${proof.profile} proof is bound to ${proof.fields.chainId}, not ${chainId}.`);
    if (proof.fields.sealAddress !== normalizeHex(deployment.contracts.payrollSeal.address)) {
      throw new Error(`${proof.profile} proof is not bound to the deployed payroll seal.`);
    }
    if (proof.fields.validityStart !== deployment.proofWindow.validityStart
      || proof.fields.validityExpiry !== deployment.proofWindow.validityExpiry) {
      throw new Error(`${proof.profile} proof uses an unexpected validity window.`);
    }
  }
  if (normalizeHex(claim.fields.nullifier[0]) !== normalizeHex(remediation.fields.nullifier[0])
    || normalizeHex(claim.fields.nullifier[1]) !== normalizeHex(remediation.fields.nullifier[1])) {
    throw new Error("Remediation is not linked to the wage-claim nullifier.");
  }
  const policy = contractFor(policyArtifact.abi, deployment.contracts.policyRegistry.address);
  const obligations = contractFor(obligationArtifact.abi, deployment.contracts.obligationRegistry.address);
  const seal = contractFor(sealArtifact.abi, deployment.contracts.payrollSeal.address);
  const advancedBundle = contractFor(advancedBundleArtifact.abi, deployment.contracts.advancedBundle.address);
  const claimBundle = contractFor(integrityBundleArtifact.abi, deployment.contracts.claimBundle.address);
  const remediationBundle = contractFor(integrityBundleArtifact.abi, deployment.contracts.remediationBundle.address);
  const topology = {
    pool: normalizeHex(await seal.call("get_pool")),
    policyRegistry: normalizeHex(await seal.call("get_catalog_registry")),
    obligationRegistry: normalizeHex(await seal.call("get_obligation_registry")),
    advancedVerifier: normalizeHex(await advancedBundle.call("get_underlying_verifier")),
    claimVerifier: normalizeHex(await claimBundle.call("get_underlying_verifier")),
    remediationVerifier: normalizeHex(await remediationBundle.call("get_underlying_verifier")),
  };
  const expectedTopology = {
    pool: normalizeHex(poolCallerAddress),
    policyRegistry: normalizeHex(deployment.contracts.policyRegistry.address),
    obligationRegistry: normalizeHex(deployment.contracts.obligationRegistry.address),
    advancedVerifier: normalizeHex(deployment.contracts.advancedVerifier.address),
    claimVerifier: normalizeHex(deployment.contracts.claimVerifier.address),
    remediationVerifier: normalizeHex(deployment.contracts.remediationVerifier.address),
  };
  if (JSON.stringify(topology) !== JSON.stringify(expectedTopology)) throw new Error("Deployed Phase 3 topology is miswired.");

  await devnetRpc("devnet_setTime", { time: 900 });
  const scheduleCalls = [
    policy.populate("schedule_policy_root", [...advanced.fields.policy, 900, 2_000]),
    policy.populate("schedule_fx_root", [...advanced.fields.fx, 900, 2_000]),
    policy.populate("schedule_verifier", [0, 2, deployment.contracts.advancedBundle.address, 900, 2_000]),
    policy.populate("schedule_verifier", [2, 3, deployment.contracts.claimBundle.address, 900, 2_000]),
    policy.populate("schedule_verifier", [3, 4, deployment.contracts.remediationBundle.address, 900, 2_000]),
    obligations.populate("schedule_obligation_root", [...advanced.fields.agreement, 900, 2_000]),
    obligations.populate("schedule_obligation_root", [...claim.fields.agreement, 900, 2_000]),
  ];
  const scheduled = await account.execute(scheduleCalls, { tip: 0 });
  await waitFor(scheduled.transaction_hash);
  await devnetRpc("devnet_setTime", { time: 1_500 });
  const activeChecks = await Promise.all([
    policy.call("is_policy_root_valid", advanced.fields.policy),
    policy.call("is_fx_root_valid", advanced.fields.fx),
    policy.call("is_verifier_valid", [0, 2]),
    policy.call("is_verifier_valid", [2, 3]),
    policy.call("is_verifier_valid", [3, 4]),
    obligations.call("is_obligation_root_valid", advanced.fields.agreement),
    obligations.call("is_obligation_root_valid", claim.fields.agreement),
  ]);
  if (!activeChecks.every(Boolean)) throw new Error("A Phase 3 registry binding is inactive.");

  const specifications = [
    { proof: advanced, mode: 0, terminalStatus: 2 },
    { proof: claim, mode: 2, terminalStatus: 4 },
    { proof: remediation, mode: 3, terminalStatus: 5 },
  ];
  const workflows = [];
  for (const specification of specifications) {
    const { proof, mode, terminalStatus } = specification;
    const hashes = proof.calldata.map((shard) => normalizeHex(hash.computePoseidonHashOnElements(shard)));
    const sealCall = seal.populate("privacy_invoke", [
      mode, proof.fields.proofVersion, proof.fields.schemaVersion,
      ...proof.fields.agreement, ...proof.fields.manifest, ...proof.fields.policy, ...proof.fields.fx,
      ...proof.fields.nullifier, proof.fields.validityStart, proof.fields.validityExpiry,
      ...hashes, [], [],
    ]);
    const sealed = await account.execute(sealCall, { tip: 0 });
    await waitFor(sealed.transaction_hash);
    if (asScalar(await seal.call("get_run_status", proof.fields.nullifier)) !== 1n) {
      throw new Error(`${proof.profile} did not enter sealed status.`);
    }
    const tampered = [...proof.calldata[0]];
    tampered[tampered.length - 1] = normalizeHex(BigInt(tampered[tampered.length - 1]) ^ 1n);
    const tamperedRejected = await expectRejected(
      () => account.estimateInvokeFee(
        seal.populate("verify_sealed_shard", [...proof.fields.nullifier, 0, tampered]),
        { tip: 0 },
      ),
      `${proof.profile} accepted tampered proof calldata.`,
    );
    const shardTransactions = [];
    for (const [shardIndex, calldata] of proof.calldata.entries()) {
      const transaction = await account.execute(
        seal.populate("verify_sealed_shard", [...proof.fields.nullifier, shardIndex, calldata]),
        { tip: 0 },
      );
      const receipt = await waitFor(transaction.transaction_hash);
      shardTransactions.push({ transactionHash: transaction.transaction_hash, blockNumber: receipt.block_number });
      const expected = shardIndex === 0 ? 1n : BigInt(terminalStatus);
      const actual = asScalar(await seal.call("get_run_status", proof.fields.nullifier));
      if (actual !== expected) throw new Error(`${proof.profile} status ${actual} after shard ${shardIndex}; expected ${expected}.`);
    }
    const replayRejected = await expectRejected(
      () => account.estimateInvokeFee(sealCall, { tip: 0 }),
      `${proof.profile} nullifier replay was accepted.`,
    );
    workflows.push({
      profile: proof.profile,
      mode,
      proofVersion: proof.fields.proofVersion,
      sealTransactionHash: sealed.transaction_hash,
      shardTransactions,
      proofHashes: hashes,
      nullifier: proof.fields.nullifier.map(normalizeHex),
      finalStatus: terminalStatus,
      tamperedProofRejected: tamperedRejected,
      replayRejected,
    });
  }
  const evidence = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    passed: true,
    standaloneRpc: rpcUrl,
    devnetVersion: devnetVersion ?? toolchains.starknet.starknetDevnet,
    rpcVersion,
    chainId,
    proofSealAddress: deployment.contracts.payrollSeal.address,
    topology,
    classes: deployment.classes,
    contracts: deployment.contracts,
    scheduleTransactionHash: scheduled.transaction_hash,
    registryChecks: { allActiveAt: 1_500, count: activeChecks.length },
    workflows,
  };
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}

if (action === "verify-matrix") {
  const deployment = await readJson("evidence/phase3-devnet-deployment.json");
  const [proof, policyArtifact, obligationArtifact, sealArtifact] = await Promise.all([
    readProof("advanced-matrix"),
    readJson(artifacts.policyRegistry.sierra),
    readJson(artifacts.obligationRegistry.sierra),
    readJson(artifacts.payrollSeal.sierra),
  ]);
  if (proof.fields.chainId !== chainId) throw new Error("The workflow-matrix proof is bound to another chain.");
  if (proof.fields.sealAddress !== normalizeHex(deployment.contracts.payrollSeal.address)) {
    throw new Error("The workflow-matrix proof is not bound to the deployed payroll seal.");
  }
  const policy = contractFor(policyArtifact.abi, deployment.contracts.policyRegistry.address);
  const obligations = contractFor(obligationArtifact.abi, deployment.contracts.obligationRegistry.address);
  const seal = contractFor(sealArtifact.abi, deployment.contracts.payrollSeal.address);
  await devnetRpc("devnet_setTime", { time: proof.fields.validityStart - 100 });
  const scheduled = await account.execute([
    policy.populate("schedule_policy_root", [...proof.fields.policy, proof.fields.validityStart - 100, proof.fields.validityExpiry]),
    policy.populate("schedule_fx_root", [...proof.fields.fx, proof.fields.validityStart - 100, proof.fields.validityExpiry]),
    policy.populate("schedule_verifier", [0, 2, deployment.contracts.advancedBundle.address, proof.fields.validityStart - 100, proof.fields.validityExpiry]),
    obligations.populate("schedule_obligation_root", [...proof.fields.agreement, proof.fields.validityStart - 100, proof.fields.validityExpiry]),
  ], { tip: 0 });
  await waitFor(scheduled.transaction_hash);
  await devnetRpc("devnet_setTime", { time: proof.fields.validityStart });
  const activeChecks = await Promise.all([
    policy.call("is_policy_root_valid", proof.fields.policy),
    policy.call("is_fx_root_valid", proof.fields.fx),
    policy.call("is_verifier_valid", [0, 2]),
    obligations.call("is_obligation_root_valid", proof.fields.agreement),
  ]);
  if (!activeChecks.every(Boolean)) throw new Error("A workflow-matrix registry binding is inactive.");
  const hashes = proof.calldata.map((shard) => normalizeHex(hash.computePoseidonHashOnElements(shard)));
  const sealCall = seal.populate("privacy_invoke", [
    0, 2, proof.fields.schemaVersion,
    ...proof.fields.agreement, ...proof.fields.manifest, ...proof.fields.policy, ...proof.fields.fx,
    ...proof.fields.nullifier, proof.fields.validityStart, proof.fields.validityExpiry,
    ...hashes, [], [],
  ]);
  const sealed = await account.execute(sealCall, { tip: 0 });
  await waitFor(sealed.transaction_hash);
  if (asScalar(await seal.call("get_run_status", proof.fields.nullifier)) !== 1n) {
    throw new Error("The workflow matrix did not enter sealed status.");
  }
  const tampered = [...proof.calldata[0]];
  tampered[tampered.length - 1] = normalizeHex(BigInt(tampered[tampered.length - 1]) ^ 1n);
  const tamperedProofRejected = await expectRejected(
    () => account.estimateInvokeFee(
      seal.populate("verify_sealed_shard", [...proof.fields.nullifier, 0, tampered]),
      { tip: 0 },
    ),
    "The workflow matrix accepted tampered proof calldata.",
  );
  const shardTransactions = [];
  for (const [shardIndex, calldata] of proof.calldata.entries()) {
    const transaction = await account.execute(
      seal.populate("verify_sealed_shard", [...proof.fields.nullifier, shardIndex, calldata]),
      { tip: 0 },
    );
    const receipt = await waitFor(transaction.transaction_hash);
    shardTransactions.push({ transactionHash: transaction.transaction_hash, blockNumber: receipt.block_number });
    const expected = shardIndex === 0 ? 1n : 2n;
    const actual = asScalar(await seal.call("get_run_status", proof.fields.nullifier));
    if (actual !== expected) throw new Error(`Workflow-matrix status ${actual}; expected ${expected}.`);
  }
  const replayRejected = await expectRejected(
    () => account.estimateInvokeFee(sealCall, { tip: 0 }),
    "The workflow-matrix nullifier replay was accepted.",
  );
  const evidence = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    passed: true,
    standaloneRpc: rpcUrl,
    devnetVersion: devnetVersion ?? toolchains.starknet.starknetDevnet,
    rpcVersion,
    chainId,
    proofSealAddress: deployment.contracts.payrollSeal.address,
    coverage: proof.summary.coverage,
    publicBindings: {
      agreementRoot: proof.fields.agreement.map(normalizeHex),
      manifestRoot: proof.fields.manifest.map(normalizeHex),
      policyRoot: proof.fields.policy.map(normalizeHex),
      fxRoot: proof.fields.fx.map(normalizeHex),
      nullifier: proof.fields.nullifier.map(normalizeHex),
      validityStart: proof.fields.validityStart,
      validityExpiry: proof.fields.validityExpiry,
    },
    transactions: {
      schedule: scheduled.transaction_hash,
      seal: sealed.transaction_hash,
      verifyShards: shardTransactions,
    },
    proofHashes: hashes,
    finalStatus: 2,
    tamperedProofRejected,
    replayRejected,
  };
  await writeFile(resolve(root, "evidence/phase3-matrix-devnet.json"), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}
