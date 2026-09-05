import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Account, Contract, RpcProvider, hash, num, shortString } from "starknet";

const root = resolve(import.meta.dirname, "..");
const rpcUrl = process.env.PAYO_DEVNET_RPC_URL ?? "http://127.0.0.1:5052";
const accountAddress = process.env.PAYO_DEVNET_ACCOUNT_ADDRESS
  ?? "0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691";
const accountPrivateKey = process.env.PAYO_DEVNET_ACCOUNT_PRIVATE_KEY
  ?? "0x0000000000000000000000000000000071d7bb07b9a64f6f78ac4c816aff4da9";
const evidencePath = resolve(root, "evidence/vesting-tax-devnet.json");
const proofFixtureManifest = JSON.parse(await readFile(resolve(
  root,
  "contracts/vesting_verifier_v3/tests/proof_fixture_manifest.json",
), "utf8"));

function splitCommitment(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} is not a canonical 32-byte fixture commitment.`);
  }
  return [`0x${value.slice(2, 34)}`, `0x${value.slice(34)}`];
}

const artifacts = Object.freeze({
  policyRegistry: {
    sierra: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.compiled_contract_class.json",
    source: "contracts/src/policy_registry.cairo",
  },
  obligationRegistry: {
    sierra: "contracts/target/dev/payo_contracts_PayoTenantObligationRootRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoTenantObligationRootRegistry.compiled_contract_class.json",
    source: "contracts/src/tenant_obligation_registry.cairo",
  },
  vestingBookSeal: {
    sierra: "contracts/target/dev/payo_contracts_PayoVestingBookSeal.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoVestingBookSeal.compiled_contract_class.json",
    source: "contracts/src/vesting_book_seal.cairo",
  },
  realVerifier: {
    sierra: "contracts/vesting_verifier_v3/target/dev/vesting_verifier_v3_PayoVestingBookV3Verifier.contract_class.json",
    casm: "contracts/vesting_verifier_v3/target/dev/vesting_verifier_v3_PayoVestingBookV3Verifier.compiled_contract_class.json",
    source: "contracts/vesting_verifier_v3/src/honk_verifier.cairo",
  },
  realBundle: {
    sierra: "contracts/vesting_verifier_v3/target/dev/vesting_verifier_v3_PayoVestingBookV3BundleVerifier.contract_class.json",
    casm: "contracts/vesting_verifier_v3/target/dev/vesting_verifier_v3_PayoVestingBookV3BundleVerifier.compiled_contract_class.json",
    source: "contracts/vesting_verifier_v3/src/vesting_bundle_verifier.cairo",
  },
  lifecycleHarness: {
    sierra: "contracts/vesting_devnet_harness/target/dev/vesting_devnet_harness_PayoVestingDevnetPublicInputHarness.contract_class.json",
    casm: "contracts/vesting_devnet_harness/target/dev/vesting_devnet_harness_PayoVestingDevnetPublicInputHarness.compiled_contract_class.json",
    source: "contracts/vesting_devnet_harness/src/lib.cairo",
  },
});

const AGREEMENT = [
  "0x0529212320c6132cf304d3d238216e29",
  "0xe2377075c1b7a41f092917f393612e3f",
];
const MANIFEST = [
  "0x2db5a4e9e7f2b20f4dbe170c3a2e5c41",
  "0x9f4cbf611978b46238d621ee04e2dc85",
];
const RUN = [
  "0x24f264a5e04c12c05b0a5c219c1162e3",
  "0x8d8d5e95c8d710aa3067c6ad9123392e",
];
const SCHEDULE = splitCommitment(proofFixtureManifest.scheduleId, "Schedule ID");
const NEXT = splitCommitment(proofFixtureManifest.nextStateCommitment, "Next vesting state");
const RELEASE = splitCommitment(proofFixtureManifest.releaseNullifier, "Release nullifier");
const BOOK = splitCommitment(proofFixtureManifest.bookEntryCommitment, "Payroll-book entry");
const ATTESTATION = splitCommitment(proofFixtureManifest.attestationRoot, "Attestation root");
const TOTALS = ["0x31", "0x32"];
const POLICY = ["0x11", "0x12"];
const FX = ["0x21", "0x22"];
const START = 600;
const EXPIRY = 900;
const PERIOD = [1, 1_000];

function felt(value) {
  return num.toHex(BigInt(value));
}

function scalar(value) {
  if (typeof value === "boolean") return value ? 1n : 0n;
  if (["bigint", "number", "string"].includes(typeof value)) return BigInt(value);
  if (Array.isArray(value) && value.length === 1) return scalar(value[0]);
  if (value && typeof value === "object") {
    const values = Object.values(value);
    if (values.length === 1) return scalar(values[0]);
  }
  throw new Error(`Expected scalar, received ${JSON.stringify(value)}.`);
}


async function readJson(path) {
  return JSON.parse(await readFile(resolve(root, path), "utf8"));
}

async function assertFreshArtifacts() {
  for (const [name, artifact] of Object.entries(artifacts)) {
    const sourceTime = (await stat(resolve(root, artifact.source))).mtimeMs;
    for (const path of [artifact.sierra, artifact.casm]) {
      const artifactTime = (await stat(resolve(root, path))).mtimeMs;
      if (artifactTime < sourceTime) {
        throw new Error(`Refusing stale ${name} artifact ${path}.`);
      }
    }
  }
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

await assertFreshArtifacts();
const toolchains = await readJson("toolchains.lock.json");
const rpcVersion = await rpc("starknet_specVersion");
if (rpcVersion !== toolchains.starknet.starknetDevnetRpc) {
  throw new Error(`Devnet RPC ${rpcVersion} does not match pinned ${toolchains.starknet.starknetDevnetRpc}.`);
}
const provider = new RpcProvider({ nodeUrl: rpcUrl });
const chainId = felt(await provider.getChainId());
const expectedChainId = felt(shortString.encodeShortString("SN_SEPOLIA"));
if (chainId !== expectedChainId) throw new Error(`Refusing lifecycle mutation on ${chainId}.`);
const account = new Account({
  provider,
  address: accountAddress,
  signer: accountPrivateKey,
  cairoVersion: "1",
});

async function waitFor(transactionHash) {
  const receipt = await provider.waitForTransaction(transactionHash, {
    retries: 1_200,
    retryInterval: 250,
  });
  if (receipt.isReverted()) {
    throw new Error(`Transaction ${transactionHash} reverted: ${receipt.revert_reason}.`);
  }
  return receipt;
}

async function declare(definition) {
  const [contract, casm] = await Promise.all([
    readJson(definition.sierra),
    readJson(definition.casm),
  ]);
  const result = await account.declareIfNot({ contract, casm }, { tip: 0 });
  if (result.transaction_hash) await waitFor(result.transaction_hash);
  return {
    abi: contract.abi,
    classHash: felt(result.class_hash),
    declarationTransactionHash: result.transaction_hash || null,
    artifactSha256: createHash("sha256").update(JSON.stringify(contract)).digest("hex"),
  };
}

async function deploy(declaration, constructorCalldata, salt) {
  const result = await account.deployContract({
    classHash: declaration.classHash,
    constructorCalldata,
    salt,
    unique: false,
  }, { tip: 0 });
  const receipt = await waitFor(result.transaction_hash);
  const address = felt(result.contract_address);
  if (felt(await provider.getClassHashAt(address)) !== declaration.classHash) {
    throw new Error(`Deployment ${address} has a substituted class hash.`);
  }
  return { address, transactionHash: result.transaction_hash, blockNumber: receipt.block_number };
}

async function invoke(call) {
  const result = await account.execute(call, { tip: 0 });
  const receipt = await waitFor(result.transaction_hash);
  return { transactionHash: result.transaction_hash, blockNumber: receipt.block_number };
}

async function expectRejected(operation, label) {
  try {
    await operation();
  } catch (error) {
    return error instanceof Error ? error.message.slice(0, 500) : label;
  }
  throw new Error(`${label} was accepted.`);
}

await rpc("devnet_setTime", { time: 500, generate_block: true });
const declarations = {};
for (const [name, definition] of Object.entries(artifacts)) {
  declarations[name] = await declare(definition);
}
const deployed = {};
deployed.realVerifier = await deploy(declarations.realVerifier, [], "0x7061796f7601");
deployed.realBundle = await deploy(
  declarations.realBundle,
  [deployed.realVerifier.address],
  "0x7061796f7602",
);
deployed.lifecycleHarness = await deploy(declarations.lifecycleHarness, [], "0x7061796f7603");
deployed.policyRegistry = await deploy(
  declarations.policyRegistry,
  [accountAddress],
  "0x7061796f7604",
);
deployed.obligationRegistry = await deploy(
  declarations.obligationRegistry,
  [accountAddress],
  "0x7061796f7605",
);
deployed.vestingBookSeal = await deploy(
  declarations.vestingBookSeal,
  [
    accountAddress,
    deployed.policyRegistry.address,
    deployed.obligationRegistry.address,
    accountAddress,
    chainId,
  ],
  "0x7061796f7606",
);

const realCalldata = await Promise.all([0, 1].map(async (shard) =>
  (await readFile(resolve(root, `contracts/vesting_verifier_v3/tests/proof_calldata_${shard}.txt`), "utf8"))
    .trim().split(/\s+/).filter(Boolean),
));
const callRealBundle = (left, right) => provider.callContract({
  contractAddress: deployed.realBundle.address,
  entrypoint: "verify_payroll_integrity_bundle",
  calldata: [left.length, ...left, right.length, ...right],
}, "latest");
const realVerification = await callRealBundle(realCalldata[0], realCalldata[1]);
if (
  BigInt(realVerification[0] ?? 1) !== 0n
  || BigInt(realVerification[1] ?? 0) !== 116n
  || realVerification.length !== 234
) throw new Error("The real v3 Devnet verifier did not return Result::Ok with 116 bound inputs.");
const verifiedInputs = Array.from({ length: 116 }, (_, index) =>
  BigInt(realVerification[2 + index * 2])
    + (BigInt(realVerification[3 + index * 2]) << 128n));
if (verifiedInputs[24] !== BigInt(ATTESTATION[0])
  || verifiedInputs[25] !== BigInt(ATTESTATION[1])) {
  throw new Error("The real v3 proof did not expose the expected attestation catalog root.");
}
const changedRealCalldata = [...realCalldata[0]];
// Calldata starts with the public-input count followed by low/high u256 limbs.
// Input 24 is the attestation-root high limb, so this changes the proved
// statement itself instead of mutating an unused hint/padding position.
const changedRealIndex = 1 + 24 * 2;
changedRealCalldata[changedRealIndex] = felt(BigInt(changedRealCalldata[changedRealIndex]) ^ 1n);
const changedAttestationProofRejected = await expectRejected(
  async () => {
    const result = await callRealBundle(changedRealCalldata, realCalldata[1]);
    if (BigInt(result[0] ?? 0) !== 0n) throw new Error("Verifier returned Result::Err.");
  },
  "A changed attestation-bound real proof",
);

const registry = new Contract({
  abi: declarations.policyRegistry.abi,
  address: deployed.policyRegistry.address,
  providerOrAccount: account,
});
const obligations = new Contract({
  abi: declarations.obligationRegistry.abi,
  address: deployed.obligationRegistry.address,
  providerOrAccount: account,
});
const schedule = await account.execute([
  registry.populate("schedule_policy_root", [...POLICY, 500, EXPIRY]),
  registry.populate("schedule_policy_root", [...ATTESTATION, 500, EXPIRY]),
  registry.populate("schedule_fx_root", [...FX, 500, EXPIRY]),
  registry.populate("schedule_verifier", [0, 2, deployed.lifecycleHarness.address, 500, EXPIRY]),
  registry.populate("schedule_verifier", [0, 3, deployed.lifecycleHarness.address, 500, EXPIRY]),
  obligations.populate("schedule_obligation_root", [...AGREEMENT, 500, EXPIRY]),
], { tip: 0 });
const scheduleReceipt = await waitFor(schedule.transaction_hash);
await rpc("devnet_setTime", { time: 700, generate_block: true });

const sealAddress = deployed.vestingBookSeal.address;
const payrollState = [
  2, 1, ...AGREEMENT, ...MANIFEST, ...POLICY, ...FX, ...RUN, START, EXPIRY,
].map(felt);
const transitionState = [
  3, 1, 1,
  ...AGREEMENT, ...MANIFEST, ...POLICY, ...FX, ...RUN,
  ...RUN, 0, 0, 0, 0,
  accountAddress, sealAddress, 2,
  ...ATTESTATION,
  1, 0,
  1, ...TOTALS,
  500, 0, 500, 0, 0, 0,
  0, 0, 0, 0, 0, 0,
  ...SCHEDULE, 0, 0, ...NEXT, ...RELEASE, ...BOOK,
  ...PERIOD, START, EXPIRY,
].map(felt);
const payrollProofs = [0, 1].map((shard) => [
  chainId, sealAddress, 2, 1, ...AGREEMENT, ...MANIFEST, ...POLICY, ...FX,
  ...RUN, START, EXPIRY, shard,
].map(felt));
const transitionProofs = [0, 1].map((shard) => [
  chainId, sealAddress, ...transitionState, shard,
].map(felt));
const proofHashes = [...payrollProofs, ...transitionProofs]
  .map((proof) => felt(hash.computePoseidonHashOnElements(proof)));
const beginCall = {
  contractAddress: sealAddress,
  entrypoint: "begin_vesting_authorization",
  calldata: [...payrollState, ...transitionState, ...proofHashes],
};
const begun = await invoke(beginCall);

const tamperedPayroll = [...payrollProofs[0]];
tamperedPayroll[tamperedPayroll.length - 1] = "0x1";
const tamperedProofRejected = await expectRejected(
  () => account.estimateInvokeFee({
    contractAddress: sealAddress,
    entrypoint: "verify_vesting_authorization_proof",
    calldata: [...RUN, 0, tamperedPayroll.length, ...tamperedPayroll],
  }, { tip: 0 }),
  "A changed payroll proof",
);

const proofTransactions = [];
for (const [proofKind, proof] of [...payrollProofs, ...transitionProofs].entries()) {
  proofTransactions.push(await invoke({
    contractAddress: sealAddress,
    entrypoint: "verify_vesting_authorization_proof",
    calldata: [...RUN, proofKind, proof.length, ...proof],
  }));
}
const seal = new Contract({
  abi: declarations.vestingBookSeal.abi,
  address: sealAddress,
  providerOrAccount: provider,
});
const pending = await seal.call("get_pending_authorization", RUN);
if (scalar(pending.exists) !== 1n
  || scalar(pending.status) !== 2n || scalar(pending.verified_mask) !== 15n) {
  throw new Error("The four-shard authorization did not reach the exact authorized state.");
}

const invoked = await invoke({
  contractAddress: sealAddress,
  entrypoint: "privacy_invoke",
  calldata: [...RUN, ...RELEASE, ...BOOK],
});
const state = await seal.call("get_vesting_state", SCHEDULE);
if (scalar(state.exists) !== 1n
  || scalar(state.owner) !== BigInt(accountAddress)
  || scalar(state.state_high) !== BigInt(NEXT[0])
  || scalar(state.state_low) !== BigInt(NEXT[1])) {
  throw new Error("Devnet vesting state did not persist the proved next commitment.");
}
const consumed = await seal.call("is_release_consumed", RELEASE);
if (scalar(consumed) !== 1n) {
  throw new Error("Devnet did not persist the release nullifier.");
}
const book = await seal.call("get_payroll_book", [accountAddress, ...PERIOD]);
const entry = await seal.call("get_payroll_book_entry", [accountAddress, ...PERIOD, 0]);
const initialBookRoot = felt(hash.computePoseidonHashOnElements([
  shortString.encodeShortString("PAYO_BOOK_V1"), chainId, sealAddress, accountAddress, ...PERIOD,
]));
const expectedBookRoot = felt(hash.computePoseidonHashOnElements([
  shortString.encodeShortString("PAYO_BOOK_ADD_V1"), initialBookRoot, ...BOOK, 0,
]));
if (scalar(book.exists) !== 1n || scalar(book.entry_count) !== 1n
  || scalar(book.contributor_count) !== 1n
  || scalar(book.disclosed_entry_count) !== 1n
  || scalar(book.vesting_entry_count) !== 1n
  || scalar(book.strk_gross) !== 500n
  || scalar(book.strk_deductions) !== 0n
  || scalar(book.strk_net) !== 500n
  || scalar(book.accumulator_root) !== BigInt(expectedBookRoot)) {
  throw new Error("The on-chain period book is incomplete or has the wrong accumulator root.");
}
if (scalar(entry) !== (BigInt(BOOK[0]) << 128n | BigInt(BOOK[1]))) {
  throw new Error("The on-chain period book returned a substituted entry commitment.");
}

const replayRejected = await expectRejected(
  () => account.estimateInvokeFee({
    contractAddress: sealAddress,
    entrypoint: "privacy_invoke",
    calldata: [...RUN, ...RELEASE, ...BOOK],
  }, { tip: 0 }),
  "A consumed vesting release",
);
const staleRun = [RUN[0], felt(BigInt(RUN[1]) + 1n)];
const staleTransition = [...transitionState];
staleTransition[11] = staleRun[0];
staleTransition[12] = staleRun[1];
staleTransition[13] = staleRun[0];
staleTransition[14] = staleRun[1];
staleTransition[48] = felt(BigInt(RELEASE[1]) + 1n);
staleTransition[50] = felt(BigInt(BOOK[1]) + 1n);
const stalePayroll = [...payrollState];
stalePayroll[10] = staleRun[0];
stalePayroll[11] = staleRun[1];
const staleStateRejected = await expectRejected(
  () => account.estimateInvokeFee({
    contractAddress: sealAddress,
    entrypoint: "begin_vesting_authorization",
    calldata: [...stalePayroll, ...staleTransition, 1, 2, 3, 4],
  }, { tip: 0 }),
  "A second genesis state for an advanced schedule",
);
const revokedCatalog = await invoke(registry.populate("revoke_policy_root", ATTESTATION));
const revokedRun = [RUN[0], felt(BigInt(RUN[1]) + 2n)];
const revokedPayroll = [...payrollState];
revokedPayroll[10] = revokedRun[0];
revokedPayroll[11] = revokedRun[1];
const revokedTransition = [...transitionState];
revokedTransition[11] = revokedRun[0];
revokedTransition[12] = revokedRun[1];
revokedTransition[13] = revokedRun[0];
revokedTransition[14] = revokedRun[1];
const revokedCatalogRejected = await expectRejected(
  () => account.estimateInvokeFee({
    contractAddress: sealAddress,
    entrypoint: "begin_vesting_authorization",
    calldata: [...revokedPayroll, ...revokedTransition, 1, 2, 3, 4],
  }, { tip: 0 }),
  "A payroll bound to a revoked external-attestation catalog",
);

const evidence = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  passed: true,
  scope: "vesting-v3-complete-payroll-book-and-external-attestation-devnet",
  chainId,
  rpcVersion,
  devnetVersion: toolchains.starknet.starknetDevnet,
  realProofVerification: {
    passed: true,
    verifier: deployed.realVerifier.address,
    bundle: deployed.realBundle.address,
    proofCalldataFelts: realCalldata.map((values) => values.length),
  },
  topology: {
    pool: felt(accountAddress),
    policyRegistry: deployed.policyRegistry.address,
    obligationRegistry: deployed.obligationRegistry.address,
    vestingBookSeal: sealAddress,
    lifecycleHarness: deployed.lifecycleHarness.address,
  },
  classes: Object.fromEntries(Object.entries(declarations).map(([name, value]) => [name, {
    classHash: value.classHash,
    declarationTransactionHash: value.declarationTransactionHash,
    artifactSha256: value.artifactSha256,
  }])),
  deployments: deployed,
  transactions: {
    registryActivation: schedule.transaction_hash,
    registryActivationBlock: scheduleReceipt.block_number,
    beginAuthorization: begun,
    verifyProofs: proofTransactions,
    invokeTransition: invoked,
    revokeAttestationCatalog: revokedCatalog,
  },
  externalAttestation: {
    root: `0x${BigInt(ATTESTATION[0]).toString(16).padStart(32, "0")}${BigInt(ATTESTATION[1]).toString(16).padStart(32, "0")}`,
    factMask: 7,
    requiredFacts: ["residency", "employment_status", "tax_status"],
    exactPolicyRootBound: true,
    exactRecipientCommitmentBound: true,
    credentialContentsPublic: false,
    activeCatalogAccepted: true,
    revokedCatalogRejected: Boolean(revokedCatalogRejected),
  },
  publicState: {
    scheduleId: SCHEDULE.map(felt),
    nextStateCommitment: NEXT.map(felt),
    releaseNullifier: RELEASE.map(felt),
    releaseConsumed: true,
    period: PERIOD,
    bookEntryCount: Number(scalar(book.entry_count)),
    bookEntryCommitment: `0x${BigInt(BOOK[0]).toString(16).padStart(32, "0")}${BigInt(BOOK[1]).toString(16).padStart(32, "0")}`,
    bookAccumulatorRoot: felt(scalar(book.accumulator_root)),
  },
  negativeTests: {
    changedAttestationBoundRealProofRejected: Boolean(changedAttestationProofRejected),
    changedProofRejected: Boolean(tamperedProofRejected),
    replayRejected: Boolean(replayRejected),
    staleGenesisRejected: Boolean(staleStateRejected),
  },
  limitations: [
    "The attestation-bound real proof pair is verified by the real generated v3 verifier on this Devnet.",
    "The state/book/catalog lifecycle uses a test-only public-input harness because the committed real proof is intentionally bound to seal 0x456; production never deploys this harness.",
    "The same real proof, active catalog root and production seal are composed in contracts/vesting_integration and must pass in CI.",
  ],
};
await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
