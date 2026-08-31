/* eslint-disable @typescript-eslint/no-explicit-any -- The evidence harness loads the digest-pinned SDK from an operator-selected absolute path, so TypeScript cannot statically resolve those runtime-only modules. Every security-sensitive result is schema- and commitment-checked below. */

import "server-only";

import { createHash } from "node:crypto";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  Account,
  Contract,
  EDataAvailabilityMode,
  ETransactionVersion,
  OutsideExecutionVersion,
  RpcProvider,
  Signer,
  ec,
  hash,
  num,
  outsideExecution,
} from "starknet";
import {
  loadPinnedPrivacySdk,
  PAYO_PRIVACY_SDK_REVISION,
  PAYO_PRIVACY_SDK_VERSION,
} from "@/lib/server/privacy-sdk-loader";
import {
  assertDirectPrivacySdkResult,
  assertDirectPrivacySdkResultBindings,
  buildDirectPrivacyPlan,
  buildDirectPrivacyPolicyCall,
  splitDirectPrivacyRoot,
} from "@/lib/starknet/direct-privacy-plan";
import { extractDirectPrivacySettlementEvidence } from "@/lib/starknet/privacy-invocation";
import {
  buildDirectPayrollPrecommitCall,
  buildPayoSealedPayroll,
  buildVerifySealedShardCall,
} from "@/lib/starknet/payo-seal";
import { buildAuthorizedPolicyRunTree, commitPolicyCapability } from "@/lib/starknet/policy-account";
import { buildConfigurePolicyCall } from "@/lib/starknet/policy-account-configuration";
import { buildPayrollIntegrityInputsFromSerialized } from "@/lib/proof/input-builder";
import {
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { settlementMatchWitnessSchema } from "@/lib/proof/settlement-request";
import { proveSettlementMatchOnSelfHostedNode } from "@/lib/proof/server-prover";
import { buildSettlementRoot } from "@/lib/proof/settlement-match";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  agentCapabilitySchema,
  agentExecutionRequestSchema,
  type AgentCapability,
} from "@/lib/domain/capability";
import { commitAgentExecutionRequest } from "@/lib/domain/agent-execution";
import {
  directPrivacyRunMaterialSchema,
  type DirectPrivacyAccountConfig,
} from "@/lib/domain/direct-privacy";
import { PAYROLL_TOKENS } from "@/lib/starknet/tokens";

const root = resolve(import.meta.dirname, "..");
const rpcUrl = process.env.PAYO_DEVNET_RPC_URL ?? "http://127.0.0.1:5050";
const action = process.argv[2];
const deploymentPath = resolve(
  root,
  "circuits/payroll_integrity/target/phase4-devnet-deployment.json",
);
const evidencePath = resolve(root, "evidence/phase4-private-payroll-devnet.json");
const expectedPoolClassHash =
  "0x52107fadffab71bdcbb6b2ccb68ba3e1b5558d94036538053e159d3076ad633";
const expectedChainId = "0x534e5f5345504f4c4941";
const strkAddress =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const devnetVersion = process.env.PAYO_PHASE4_DEVNET_VERSION ?? "0.8.0-rc.3";
const transactionProofMode = process.env.PAYO_PHASE4_TRANSACTION_PROOF_MODE ?? "none";
if (!new Set(["none", "devnet"]).has(transactionProofMode)) {
  throw new Error("PAYO_PHASE4_TRANSACTION_PROOF_MODE must be none or devnet.");
}
const ownerPrivateKey =
  "0x314159265358979323846264338327950288419716939937510";
const sessionPrivateKey =
  "0x161803398874989484820458683436563811772030917980576";

if (!new Set(["check-artifacts", "deploy", "settle"]).has(action)) {
  throw new Error(
    "Usage: tsx scripts/test-phase4-private-payroll-devnet.ts <check-artifacts|deploy|settle>",
  );
}

type Artifact = {
  sierra: string;
  casm: string;
  sources: string;
};

const artifacts = Object.freeze({
  integrityVerifier: {
    sierra: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.contract_class.json",
    casm: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.compiled_contract_class.json",
    sources: "contracts/integrity_verifier",
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
  policyAccount: {
    sierra: "contracts/target/dev/payo_contracts_PayoPolicyAccount.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPolicyAccount.compiled_contract_class.json",
    sources: "contracts",
  },
  settlementVerifier: {
    sierra: "contracts/settlement_verifier_v8/target/dev/settlement_verifier_v8_PayoSettlementMatchV8Verifier.contract_class.json",
    casm: "contracts/settlement_verifier_v8/target/dev/settlement_verifier_v8_PayoSettlementMatchV8Verifier.compiled_contract_class.json",
    sources: "contracts/settlement_verifier_v8",
  },
} satisfies Record<string, Artifact>);

async function readJson(path: string): Promise<any> {
  return JSON.parse(await readFile(resolve(root, path), "utf8"));
}

async function rpc(method: string, params: unknown = {}): Promise<any> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: method, method, params }),
  });
  if (!response.ok) throw new Error(`${method} returned HTTP ${response.status}.`);
  const payload = await response.json() as { result?: unknown; error?: unknown };
  if (payload.error) throw new Error(`${method} failed: ${JSON.stringify(payload.error)}`);
  return payload.result;
}

async function filesRecursively(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory() && entry.name === "target") continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) paths.push(...await filesRecursively(path));
    else if (entry.isFile()) paths.push(path);
  }
  return paths;
}

async function assertFreshArtifacts(): Promise<void> {
  const sourceTimes = new Map<string, number>();
  for (const definition of Object.values(artifacts)) {
    if (!sourceTimes.has(definition.sources)) {
      const sourceRoot = resolve(root, definition.sources);
      const paths = [
        resolve(sourceRoot, "Scarb.toml"),
        ...await filesRecursively(resolve(sourceRoot, "src")),
      ];
      sourceTimes.set(
        definition.sources,
        Math.max(...await Promise.all(paths.map(async (path) => (await stat(path)).mtimeMs))),
      );
    }
    for (const path of [definition.sierra, definition.casm]) {
      const artifact = await stat(resolve(root, path));
      if (artifact.mtimeMs < sourceTimes.get(definition.sources)!) {
        throw new Error(`Refusing stale Phase 4 artifact ${path}.`);
      }
    }
  }
  const sdk = await loadPinnedPrivacySdk();
  const poolSierra = await readJson(
    resolve(sdk.root, "../target/release/privacy_Privacy.contract_class.json"),
  );
  const actualPoolClassHash = num.toHex(BigInt(hash.computeContractClassHash(poolSierra)));
  if (actualPoolClassHash !== expectedPoolClassHash) {
    throw new Error(`Pinned Privacy Pool class is ${actualPoolClassHash}, expected ${expectedPoolClassHash}.`);
  }
}

async function main(): Promise<void> {
if (action === "check-artifacts") {
  await assertFreshArtifacts();
  process.stdout.write("Phase 4 policy, PAYO verifier/seal, SettlementMatch and Privacy Pool artifacts are fresh and pinned.\n");
  process.exit(0);
}

await assertFreshArtifacts();
const toolchains = await readJson("toolchains.lock.json");
const rpcVersion = await rpc("starknet_specVersion", []);
if (rpcVersion !== toolchains.starknet.starknetDevnetRpc) {
  throw new Error(`Devnet RPC ${rpcVersion} does not match pinned ${toolchains.starknet.starknetDevnetRpc}.`);
}
const provider = new RpcProvider({ nodeUrl: rpcUrl, batch: 0 });
const chainId = await provider.getChainId();
if (BigInt(chainId) !== BigInt(expectedChainId)) {
  throw new Error(`Refusing Phase 4 mutation on chain ${chainId}.`);
}
const predeployed = await rpc("devnet_getPredeployedAccounts", []);
if (!Array.isArray(predeployed) || predeployed.length < 3) {
  throw new Error("Phase 4 Devnet requires at least three deterministic accounts.");
}
function accountFor(raw: { address: string; private_key: string }): Account {
  return new Account({
    provider,
    address: raw.address,
    signer: raw.private_key,
    cairoVersion: "1",
  });
}
const alice = accountFor(predeployed[0]);
const bob = accountFor(predeployed[1]);
const admin = accountFor(predeployed.at(-1));

const resourceBounds = {
  // Devnet 0.9.2 prices all three resources at 1e9 FRI by default. The 2x
  // price ceiling tolerates a deterministic local bump while the amount
  // ceiling keeps every synthetic test transaction bounded.
  l1_gas: { max_amount: 10_000_000_000n, max_price_per_unit: 2_000_000_000n },
  l2_gas: { max_amount: 10_000_000_000n, max_price_per_unit: 2_000_000_000n },
  l1_data_gas: { max_amount: 10_000_000_000n, max_price_per_unit: 2_000_000_000n },
};
function transactionDetails(overrides: Record<string, unknown> = {}) {
  return {
    resourceBounds,
    tip: 0n,
    feeDataAvailabilityMode: EDataAvailabilityMode.L2,
    nonceDataAvailabilityMode: EDataAvailabilityMode.L2,
    version: ETransactionVersion.V3,
    ...overrides,
  };
}
async function waitFor(transactionHash: string) {
  const receipt = await provider.waitForTransaction(transactionHash, {
    retries: 1_200,
    retryInterval: 100,
  });
  if (receipt.isReverted()) {
    throw new Error(`Transaction ${transactionHash} reverted: ${receipt.revert_reason}.`);
  }
  return receipt;
}

function asScalar(value: unknown): bigint {
  if (typeof value === "boolean") return value ? 1n : 0n;
  if (["bigint", "number", "string"].includes(typeof value)) {
    return BigInt(value as string | number | bigint);
  }
  if (Array.isArray(value) && value.length === 1) return asScalar(value[0]);
  if (value && typeof value === "object") {
    const values = Object.values(value as Record<string, unknown>);
    if (values.length === 1) return asScalar(values[0]);
  }
  throw new Error(`Expected one scalar value, received ${JSON.stringify(value)}.`);
}

async function createBlocks(count: number): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    await rpc("devnet_createBlock");
  }
}

async function declare(definition: Artifact) {
  const [contract, casm] = await Promise.all([
    readJson(definition.sierra),
    readJson(definition.casm),
  ]);
  const response = await admin.declareIfNot(
    { contract, casm, compiledClassHash: hash.computeCompiledClassHash(casm) },
    transactionDetails(),
  );
  if (response.transaction_hash) await waitFor(response.transaction_hash);
  return {
    abi: contract.abi,
    classHash: num.toHex(BigInt(response.class_hash)),
    declarationTransactionHash: response.transaction_hash || null,
    sierraSha256: createHash("sha256").update(JSON.stringify(contract)).digest("hex"),
    casmSha256: createHash("sha256").update(JSON.stringify(casm)).digest("hex"),
  };
}

async function deploy(
  declaration: Awaited<ReturnType<typeof declare>>,
  constructorCalldata: readonly (string | number | bigint)[],
  salt: string,
) {
  const response = await admin.deployContract({
    classHash: declaration.classHash,
    constructorCalldata: [...constructorCalldata],
    salt,
    unique: false,
  }, transactionDetails());
  await waitFor(response.transaction_hash);
  const address = num.toHex(BigInt(response.contract_address));
  const actualClassHash = num.toHex(BigInt(await provider.getClassHashAt(address)));
  if (actualClassHash !== declaration.classHash) {
    throw new Error(`Deployed class ${actualClassHash} does not match ${declaration.classHash}.`);
  }
  return { address, transactionHash: response.transaction_hash };
}

if (action === "deploy") {
  await rpc("devnet_setTime", { time: 9_000 });
  const sdk = await loadPinnedPrivacySdk();
  const poolDefinition: Artifact = {
    sierra: resolve(sdk.root, "../target/release/privacy_Privacy.contract_class.json"),
    casm: resolve(sdk.root, "../target/release/privacy_Privacy.compiled_contract_class.json"),
    sources: resolve(sdk.root, "../packages/privacy"),
  };
  const screeningModule = await import(
    pathToFileURL(resolve(sdk.root, "dist/testing/screening-signer.js")).href
  ) as { SCREENING_SIGNER_PUBLIC_KEY: bigint };
  const declarations: Record<string, Awaited<ReturnType<typeof declare>>> = {};
  declarations.pool = await declare(poolDefinition);
  for (const [name, definition] of Object.entries(artifacts)) {
    declarations[name] = await declare(definition);
  }
  const contracts: Record<string, { address: string; transactionHash: string }> = {};
  contracts.pool = await deploy(declarations.pool, [
    admin.address,
    1,
    num.toHex(screeningModule.SCREENING_SIGNER_PUBLIC_KEY),
    450,
  ], "0x7061796f340100");
  contracts.integrityVerifier = await deploy(
    declarations.integrityVerifier,
    [],
    "0x7061796f340101",
  );
  contracts.integrityBundle = await deploy(
    declarations.integrityBundle,
    [contracts.integrityVerifier.address],
    "0x7061796f340102",
  );
  contracts.policyRegistry = await deploy(
    declarations.policyRegistry,
    [admin.address],
    "0x7061796f340103",
  );
  contracts.obligationRegistry = await deploy(
    declarations.obligationRegistry,
    [admin.address],
    "0x7061796f340104",
  );
  contracts.settlementVerifier = await deploy(
    declarations.settlementVerifier,
    [],
    "0x7061796f340105",
  );
  contracts.payrollSeal = await deploy(declarations.payrollSeal, [
    contracts.pool.address,
    contracts.policyRegistry.address,
    contracts.obligationRegistry.address,
    chainId,
  ], "0x7061796f340106");
  contracts.policyAccount = await deploy(declarations.policyAccount, [
    num.toHex(ec.starkCurve.getStarkKey(ownerPrivateKey)),
  ], "0x7061796f340107");
  const policyFeeFunding = await admin.execute({
    contractAddress: strkAddress,
    entrypoint: "transfer",
    calldata: [contracts.policyAccount.address, num.toHex(100n * 10n ** 18n), "0x0"],
  }, transactionDetails());
  await waitFor(policyFeeFunding.transaction_hash);
  const deployment = {
    schemaVersion: "payo.phase4.private-devnet-deployment.v1",
    generatedAt: new Date().toISOString(),
    devnetVersion,
    transactionProofMode,
    rpcVersion,
    rpcUrl,
    chainId: num.toHex(BigInt(chainId)),
    proofWindow: { validityStart: 10_000, validityExpiry: 13_600 },
    accounts: {
      alice: num.toHex(BigInt(alice.address)),
      recipient: num.toHex(BigInt(bob.address)),
      admin: num.toHex(BigInt(admin.address)),
    },
    classes: Object.fromEntries(Object.entries(declarations).map(([name, value]) => [name, {
      classHash: value.classHash,
      declarationTransactionHash: value.declarationTransactionHash,
      sierraSha256: value.sierraSha256,
      casmSha256: value.casmSha256,
    }])),
    contracts,
    policyFeeFundingTransactionHash: policyFeeFunding.transaction_hash,
  };
  await writeFile(deploymentPath, `${JSON.stringify(deployment, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    deployed: true,
    chainId: deployment.chainId,
    recipientAddress: deployment.accounts.recipient,
    sealAddress: contracts.payrollSeal.address,
    policyAccountAddress: contracts.policyAccount.address,
    validityStart: deployment.proofWindow.validityStart,
    validityExpiry: deployment.proofWindow.validityExpiry,
    deploymentPath,
  }, null, 2)}\n`);
  process.exit(0);
}

if (action === "settle") {
  const [deployment, privateBuild, shardZeroText, shardOneText, sdk] = await Promise.all([
    readJson(deploymentPath),
    readJson("circuits/payroll_integrity/target/phase4-devnet-payroll-build.json"),
    readFile(resolve(root, "circuits/payroll_integrity/target/proof_calldata-phase4-devnet-shard-0.txt"), "utf8"),
    readFile(resolve(root, "circuits/payroll_integrity/target/proof_calldata-phase4-devnet-shard-1.txt"), "utf8"),
    loadPinnedPrivacySdk(),
  ]);
  if (deployment.schemaVersion !== "payo.phase4.private-devnet-deployment.v1") {
    throw new Error("The Phase 4 Devnet deployment manifest is missing or incompatible.");
  }
  if (privateBuild.version !== "payo-phase4-devnet-payroll-build-v1") {
    throw new Error("The Phase 4 private PayrollIntegrity build is missing or incompatible.");
  }
  if (
    BigInt(deployment.chainId) !== BigInt(chainId)
    || BigInt(deployment.accounts.recipient) !== BigInt(bob.address)
    || BigInt(privateBuild.serializedBuild.chainId) !== BigInt(chainId)
    || BigInt(privateBuild.serializedBuild.sealAddress)
      !== BigInt(deployment.contracts.payrollSeal.address)
    || BigInt(privateBuild.serializedBuild.lines[0].recipientAddress) !== BigInt(bob.address)
  ) {
    throw new Error("The payroll witness crosses the deployed chain, seal, or recipient boundary.");
  }
  const parseProofCalldata = (source: string): `0x${string}`[] => {
    const values = source.trim().split(/\s+/).filter(Boolean);
    if (values.length < 100 || values.length > 4_992) {
      throw new Error(`Payroll proof calldata has ${values.length} felts.`);
    }
    return values.map((value) => {
      if (!/^0x[0-9a-fA-F]+$/.test(value)) throw new Error("Payroll proof calldata is malformed.");
      return num.toHex(BigInt(value)) as `0x${string}`;
    });
  };
  const proofCalldata = [parseProofCalldata(shardZeroText), parseProofCalldata(shardOneText)] as const;
  const payroll = await buildPayrollIntegrityInputsFromSerialized(privateBuild.serializedBuild);
  payroll.witness.circuitInputs = [{}, {}];
  const payrollProof: ProofWorkerSuccess = {
    version: 1,
    type: "proof-complete",
    requestId: "phase4-devnet-execution",
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    provingTimeMs: 0,
    shards: [0, 1].map((shardIndex) => ({
      shardIndex: shardIndex as 0 | 1,
      proofCalldata: proofCalldata[shardIndex as 0 | 1],
      calldataHash: hashProofCalldata(proofCalldata[shardIndex as 0 | 1]),
      publicInputs: payroll.publicInputs[shardIndex as 0 | 1],
    })) as ProofWorkerSuccess["shards"],
  };
  const sealedPayroll = buildPayoSealedPayroll({
    sealAddress: deployment.contracts.payrollSeal.address,
    chainId,
    shards: payrollProof.shards,
    nowUnixSeconds: BigInt(deployment.proofWindow.validityStart),
  });
  const [agreementHigh, agreementLow] = splitDirectPrivacyRoot(payroll.agreementRoot);
  const [policyHigh, policyLow] = splitDirectPrivacyRoot(payroll.policyRoot);
  const [fxHigh, fxLow] = splitDirectPrivacyRoot(payroll.fxRoot);
  const [nullifierHigh, nullifierLow] = splitDirectPrivacyRoot(payroll.runNullifier);

  const [policyArtifact, obligationArtifact, sealArtifact, policyAccountArtifact] = await Promise.all([
    readJson(artifacts.policyRegistry.sierra),
    readJson(artifacts.obligationRegistry.sierra),
    readJson(artifacts.payrollSeal.sierra),
    readJson(artifacts.policyAccount.sierra),
  ]);
  const policyRegistry = new Contract({
    abi: policyArtifact.abi,
    address: deployment.contracts.policyRegistry.address,
    providerOrAccount: admin,
  });
  const obligationRegistry = new Contract({
    abi: obligationArtifact.abi,
    address: deployment.contracts.obligationRegistry.address,
    providerOrAccount: admin,
  });
  const payrollSeal = new Contract({
    abi: sealArtifact.abi,
    address: deployment.contracts.payrollSeal.address,
    providerOrAccount: admin,
  });
  const registryResponse = await admin.execute([
    policyRegistry.populate("schedule_policy_root", [
      policyHigh,
      policyLow,
      deployment.proofWindow.validityStart - 1,
      deployment.proofWindow.validityExpiry,
    ]),
    policyRegistry.populate("schedule_verifier", [
      0,
      1,
      deployment.contracts.integrityBundle.address,
      deployment.proofWindow.validityStart - 1,
      deployment.proofWindow.validityExpiry,
    ]),
    policyRegistry.populate("schedule_verifier", [
      1,
      8,
      deployment.contracts.settlementVerifier.address,
      deployment.proofWindow.validityStart - 1,
      deployment.proofWindow.validityExpiry,
    ]),
    obligationRegistry.populate("schedule_obligation_root", [
      agreementHigh,
      agreementLow,
      deployment.proofWindow.validityStart - 1,
      deployment.proofWindow.validityExpiry,
    ]),
  ], transactionDetails());
  await waitFor(registryResponse.transaction_hash);
  await rpc("devnet_setTime", { time: deployment.proofWindow.validityStart });
  const snapshot = privateBuild.serializedBuild.fxSnapshots[0];
  const observedAt = Math.floor(new Date(snapshot.observedAt).getTime() / 1_000);
  const fxResponse = await admin.execute(
    policyRegistry.populate("publish_fx_root", [
      fxHigh,
      fxLow,
      observedAt,
      snapshot.maximumAgeSeconds,
    ]),
    transactionDetails(),
  );
  await waitFor(fxResponse.transaction_hash);
  const configurationChecks = await Promise.all([
    policyRegistry.call("is_policy_root_valid", [policyHigh, policyLow]),
    policyRegistry.call("is_fx_root_valid", [fxHigh, fxLow]),
    policyRegistry.call("is_verifier_valid", [0, 1]),
    policyRegistry.call("is_verifier_valid", [1, 8]),
    obligationRegistry.call("is_obligation_root_valid", [agreementHigh, agreementLow]),
  ]);
  if (configurationChecks.some((value) => asScalar(value) !== 1n)) {
    throw new Error("A proof-bound Phase 4 registry entry is inactive.");
  }
  const precommit = buildDirectPayrollPrecommitCall({
    sealAddress: deployment.contracts.payrollSeal.address,
    sealedPayroll,
  });
  const precommitResponse = await admin.execute(precommit, transactionDetails());
  await waitFor(precommitResponse.transaction_hash);
  const shardTransactions: string[] = [];
  for (const shard of payrollProof.shards) {
    const response = await admin.execute(buildVerifySealedShardCall({
      sealAddress: deployment.contracts.payrollSeal.address,
      runNullifierHigh: sealedPayroll.runNullifierHigh,
      runNullifierLow: sealedPayroll.runNullifierLow,
      shard,
    }), transactionDetails());
    await waitFor(response.transaction_hash);
    shardTransactions.push(response.transaction_hash);
  }
  const provenStatus = await payrollSeal.call("get_run_status", [nullifierHigh, nullifierLow]);
  if (BigInt(provenStatus as bigint) !== 2n) {
    throw new Error(`PayrollIntegrity status is ${String(provenStatus)}, expected PROVEN.`);
  }

  const sdkTesting = await import(pathToFileURL(resolve(sdk.root, "dist/testing/index.js")).href) as any;
  const sdkStarknet = await import(
    pathToFileURL(resolve(sdk.root, "node_modules/starknet/dist/index.mjs")).href
  ) as any;
  const poolAbiModule = await import(pathToFileURL(resolve(sdk.root, "dist/internal/abi.js")).href) as any;
  const invocationFactoryModule = await import(
    pathToFileURL(resolve(sdk.root, "dist/internal/proof-invocation-factory.js")).href
  ) as any;
  const proofFactsModule = await import(
    pathToFileURL(resolve(sdk.root, "dist/utils/proof-facts.js")).href
  ) as any;
  const screeningSignerModule = await import(
    pathToFileURL(resolve(sdk.root, "dist/testing/screening-signer.js")).href
  ) as any;
  const sdkProvider = new sdkStarknet.RpcProvider({
    nodeUrl: rpcUrl,
    batch: 0,
    chainId: sdkStarknet.constants.StarknetChainId.SN_SEPOLIA,
  });
  const sdkAdmin = new sdkStarknet.Account({
    provider: sdkProvider,
    address: predeployed.at(-1).address,
    signer: predeployed.at(-1).private_key,
    cairoVersion: "1",
  });
  const pool = new sdkStarknet.Contract({
    abi: poolAbiModule.PrivacyPoolABI,
    address: deployment.contracts.pool.address,
    providerOrAccount: sdkAdmin,
  }).typedv2(poolAbiModule.PrivacyPoolABI);
  const discovery = new sdkTesting.ContractDiscoveryProvider(pool);
  const upstreamProofProvider = new sdk.sdk.ProvingServiceProofProvider(
    rpcUrl,
    chainId,
    {
      requestTimeoutMs: 20 * 60_000,
      blockIdentifier: "latest",
      nodeUrl: rpcUrl,
      poolAddress: deployment.contracts.pool.address,
      retry: { maxRetries: 0 },
    },
  ) as any;
  const callProofProvider = new sdkTesting.CallMockProofProvider(
    sdkProvider,
    sdkStarknet.constants.StarknetChainId.SN_SEPOLIA,
  );
  const actionsDecoder = new sdkStarknet.CallData(poolAbiModule.PrivacyPoolABI);
  const clientActionsType = "core::array::Span::<privacy::actions::ClientAction>";
  const screeningDataFor = async (invocation: any, blockIdentifier: any) => {
    const innerCalldata = invocationFactoryModule.extractExecuteViewCalldata(invocation.calldata);
    if (innerCalldata.length < 3) return undefined;
    const decodedActions = actionsDecoder.decodeParameters(
      clientActionsType,
      innerCalldata.slice(2),
    );
    if (!decodedActions.some((entry: any) => entry.activeVariant() === "Deposit")) {
      return undefined;
    }
    const block = await sdkProvider.getBlock(blockIdentifier);
    return {
      signature: screeningSignerModule.signScreeningAttestation(
        screeningSignerModule.SCREENING_SIGNER_PRIVATE_KEY,
        BigInt(chainId),
        BigInt(innerCalldata[0]),
        Number(block.timestamp),
      ),
    };
  };
  const proofProvider = {
    getDefaultDetails: () => upstreamProofProvider.getDefaultDetails(),
    invalidateNonceCache: () => upstreamProofProvider.invalidateNonceCache?.(),
    async prove(invocation: any, blockIdentifier: any = "latest") {
      if (transactionProofMode === "none") {
        const compiled = await callProofProvider.prove(invocation, blockIdentifier);
        return {
          ...compiled,
          additionalData: await screeningDataFor(invocation, blockIdentifier),
        };
      }
      const blockId = typeof blockIdentifier === "number" || typeof blockIdentifier === "bigint"
        ? { block_number: Number(blockIdentifier) }
        : blockIdentifier;
      const result = await rpc("starknet_proveTransaction", {
        block_id: blockId,
        transaction: invocation,
      });
      if (
        !result
        || typeof result.proof !== "string"
        || result.proof.length === 0
        || !Array.isArray(result.proof_facts)
        || result.proof_facts.length === 0
        || !Array.isArray(result.l2_to_l1_messages)
      ) throw new Error("Devnet returned an invalid transaction proof.");
      const poolMessage = result.l2_to_l1_messages.find((message: any) =>
        typeof message?.from_address === "string"
        && BigInt(message.from_address) === BigInt(invocation.sender_address));
      if (!poolMessage || !Array.isArray(poolMessage.payload) || poolMessage.payload.length < 2) {
        throw new Error("Devnet omitted the Privacy Pool proof output.");
      }
      // Devnet 0.8 returns the blockifier's flat OS facts, while the official
      // Privacy Pool consumes the equivalent Cairo `ProofFacts` serialization.
      // Rebuild that ABI layout with the pinned SDK helper from the proven
      // block and the exact L2-to-L1 payload; the proof bytes remain untouched.
      const compatibleProofFacts = proofFactsModule.buildProofFacts(
        invocation.sender_address,
        poolMessage.payload[0],
        poolMessage.payload.slice(1),
        BigInt(result.proof_facts[4]),
        result.proof_facts[5],
        chainId,
      );
      if (process.env.PAYO_PHASE4_DEBUG_PROOF === "1") {
        console.error(JSON.stringify({
          proofPrefix: result.proof.slice(0, 18),
          rawProofFacts: result.proof_facts,
          compatibleProofFacts,
          l2ToL1Messages: result.l2_to_l1_messages,
        }, null, 2));
      }
      if (
        result.proof_facts.length !== compatibleProofFacts.length
        || result.proof_facts.some((value: string, index: number) =>
          BigInt(value) !== BigInt(compatibleProofFacts[index]))
      ) {
        throw new Error(
          "Devnet bound the transaction proof to proof facts that the pinned Privacy Pool cannot deserialize.",
        );
      }
      return {
        data: result.proof,
        output: poolMessage.payload,
        proofFacts: result.proof_facts,
        additionalData:
          await screeningDataFor(invocation, blockIdentifier) ?? result.additional_data,
      };
    },
  };
  const submitPrivate = async (callAndProof: any) => {
    if (
      (transactionProofMode !== "none" && (
        typeof callAndProof?.proof?.data !== "string"
        || callAndProof.proof.data.length === 0
      ))
      || !Array.isArray(callAndProof?.proof?.proofFacts)
      || callAndProof.proof.proofFacts.length === 0
    ) throw new Error("The SDK private transaction has no proof or proof facts.");
    await createBlocks(10);
    const block = await provider.getBlock("latest");
    const outside = await admin.getOutsideTransaction({
      caller: admin.address,
      execute_after: Math.max(0, Number(block.timestamp) - 3_600),
      execute_before: Number(block.timestamp) + 3_600,
    }, callAndProof.call, OutsideExecutionVersion.V2);
    const response = await admin.executeFromOutside(outside, {
      ...transactionDetails(),
      proofFacts: callAndProof.proof.proofFacts,
      proof: callAndProof.proof.data,
    });
    await waitFor(response.transaction_hash);
    return response.transaction_hash;
  };

  const policyOwner = new Account({
    provider,
    address: deployment.contracts.policyAccount.address,
    signer: ownerPrivateKey,
    cairoVersion: "1",
  });
  const policyOwnerSdk = {
    address: deployment.contracts.policyAccount.address,
    signer: new sdkStarknet.Signer(ownerPrivateKey),
  };
  const sdkBob = new sdkStarknet.Account({
    provider: sdkProvider,
    address: predeployed[1].address,
    signer: predeployed[1].private_key,
    cairoVersion: "1",
  });
  const policyViewingKey = "0x5041594f504f4c494359";
  const bobViewingKey = "0xb0b";
  const privateTransfersFor = (account: any, viewingKey: string) =>
    sdk.sdk.createPrivateTransfers({
      account,
      viewingKeyProvider: { getViewingKey: async () => BigInt(viewingKey) },
      provingProvider: proofProvider,
      discoveryProvider: discovery,
      poolContractAddress: deployment.contracts.pool.address,
    }) as any;
  const policyTransfers = privateTransfersFor(policyOwnerSdk, policyViewingKey);
  const bobTransfers = privateTransfersFor(sdkBob, bobViewingKey);

  const bobRegistration = await bobTransfers.build().register().execute();
  const bobRegistrationTransactionHash = await submitPrivate(bobRegistration.callAndProof);
  const provisionAmount = 10n * 10n ** 15n;
  const approvalResponse = await policyOwner.execute({
    contractAddress: strkAddress,
    entrypoint: "approve",
    calldata: [deployment.contracts.pool.address, num.toHex(provisionAmount), "0x0"],
  }, transactionDetails());
  await waitFor(approvalResponse.transaction_hash);
  const provisioning = await policyTransfers
    .build({
      autoRegister: true,
      autoSetup: true,
      autoDiscover: { notes: "refresh", channels: "refresh" },
    })
    .with(strkAddress)
    .deposit({ amount: provisionAmount })
    .transfer({ recipient: bob.address, amount: 1n })
    .surplusTo(deployment.contracts.policyAccount.address)
    .execute();
  const provisioningTransactionHash = await submitPrivate(provisioning.callAndProof);
  await createBlocks(1);
  const privateBalance = async (transfers: any): Promise<bigint> => {
    const discovered = await transfers.discoverNotes();
    return (discovered.notes.get(BigInt(strkAddress)) ?? [])
      .reduce((total: bigint, note: any) => total + BigInt(note.amount), 0n);
  };
  const recipientBefore = await privateBalance(bobTransfers);
  if (recipientBefore !== 1n) {
    throw new Error(`Recipient setup balance is ${recipientBefore}, expected one atomic STRK.`);
  }

  const runId = "phase4-private-payroll-run-0001";
  const organizationId = "phase4-private-payroll-organization";
  const capabilityId = "phase4-private-payroll-capability";
  const amountAtomic = payroll.calculatedLines[0].netAtomic.toString();
  const validAfter = deployment.proofWindow.validityStart - 1;
  const validBefore = deployment.proofWindow.validityExpiry;
  const iso = (seconds: number) => new Date(seconds * 1_000).toISOString();
  const capability: AgentCapability = agentCapabilitySchema.parse({
    capabilityVersion: "payo-agent-capability-v1",
    id: capabilityId,
    organizationId,
    principalId: "phase4-agent-principal",
    allowedActions: ["request_execution"],
    allowedTokens: ["STRK"],
    recipientScope: { mode: "allowlist", addresses: [bob.address] },
    purposeCodes: ["private_payroll"],
    limits: [{
      token: "STRK",
      maxPerPaymentAtomic: (BigInt(amountAtomic) * 2n).toString(),
      maxPerPeriodAtomic: (BigInt(amountAtomic) * 2n).toString(),
      spentThisPeriodAtomic: "0",
      periodStartsAt: iso(validAfter),
      periodEndsAt: iso(validBefore),
      approvalThresholdAtomic: (BigInt(amountAtomic) * 2n).toString(),
    }],
    executionMode: "autonomous_bounded",
    maxCallCount: 1,
    usedCallCount: 0,
    validAfter: iso(validAfter),
    expiresAt: iso(validBefore),
    nonce: "phase4-private-capability-nonce-0001",
  });
  const authoritativeRequest = agentExecutionRequestSchema.parse({
    requestVersion: "payo-agent-execution-v1",
    runId,
    intents: [{
      intentVersion: "payo-payment-intent-v1",
      intentId: "phase4-private-payment-intent-0001",
      organizationId,
      runId,
      action: "request_execution",
      token: "STRK",
      recipientAddress: bob.address,
      amountAtomic,
      purposeCode: "private_payroll",
      capabilityNonce: capability.nonce,
      createdAt: iso(deployment.proofWindow.validityStart),
      validUntil: iso(deployment.proofWindow.validityStart + 299),
    }],
  });
  const scope = commitPolicyCapability(capability);
  const policyId = "0x5041594f34";
  const policyContext = {
    policyId,
    sealMode: 0 as const,
    proofVersion: 1,
    schemaVersion: 1,
    payrollPolicyRoot: payroll.policyRoot,
    ...scope,
  };
  const authorizedTree = buildAuthorizedPolicyRunTree(policyContext, [{
    agreementRoot: payroll.agreementRoot,
    manifestRoot: payroll.manifestRoot,
    runNullifier: payroll.runNullifier,
  }]);
  const policyRun = authorizedTree.proofs[0];
  const config: DirectPrivacyAccountConfig = {
    version: "payo-direct-privacy-account-v1",
    chainId,
    policyAccountAddress: deployment.contracts.policyAccount.address,
    policyId,
    sessionPublicKey: num.toHex(ec.starkCurve.getStarkKey(sessionPrivateKey)) as `0x${string}`,
    sealMode: 0,
    proofVersion: 1,
    schemaVersion: 1,
    payrollPolicyRoot: payroll.policyRoot,
    ...scope,
    authorizedRunsRoot: authorizedTree.root,
    validAfterUnix: validAfter.toString(),
    validBeforeUnix: validBefore.toString(),
    periodSeconds: "3600",
    maxCallsPerPeriod: 1,
    maxCallCount: 1,
    poolAddress: deployment.contracts.pool.address,
    sealAddress: deployment.contracts.payrollSeal.address,
    tokenAddresses: {
      STRK: num.toHex(BigInt(PAYROLL_TOKENS.STRK.address)) as `0x${string}`,
      USDC: num.toHex(BigInt(PAYROLL_TOKENS.USDC.address)) as `0x${string}`,
    },
    sdkVersion: PAYO_PRIVACY_SDK_VERSION,
    sdkRevision: PAYO_PRIVACY_SDK_REVISION,
  };
  const configurationResponse = await policyOwner.execute(
    buildConfigurePolicyCall(config),
    transactionDetails(),
  );
  await waitFor(configurationResponse.transaction_hash);

  const proofPrincipal = generateVaultPrincipal("phase4-private-payroll-proof-principal");
  const encryptedPayrollWitness = encryptVaultRecord(
    { buildInput: privateBuild.serializedBuild },
    {
      schemaVersion: 1,
      organizationId,
      recordType: "agent_payroll_witness",
      recordId: runId,
      revision: 1,
    },
    [proofPrincipal],
  );
  const material = directPrivacyRunMaterialSchema.parse({
    version: "payo-direct-privacy-run-v1",
    organizationId,
    capabilityId,
    runId,
    runVersion: 1,
    requestCommitment: commitAgentExecutionRequest(authoritativeRequest),
    authoritativeRequest,
    encryptedWitness: encryptedPayrollWitness,
    policyRun: {
      agreementRoot: policyRun.agreementRoot,
      manifestRoot: policyRun.manifestRoot,
      runNullifier: policyRun.runNullifier,
      pathBits: policyRun.pathBits,
      siblings: policyRun.siblings,
    },
  });
  const directPlan = buildDirectPrivacyPlan({
    config,
    material,
    payrollProof,
    nowUnixSeconds: BigInt(deployment.proofWindow.validityStart),
  });
  const invocation = await policyTransfers.createProofInvocation(directPlan.actions, {
    autoRegister: false,
    autoSetup: false,
    autoDiscover: { notes: "all", channels: "refresh" },
    autoSelectNotes: "all",
  });
  const sdkResult = await policyTransfers.executeWithInvocation(invocation, "latest");
  const sdkAssertion = {
    result: sdkResult,
    poolAddress: deployment.contracts.pool.address,
  };
  if (transactionProofMode === "none") {
    assertDirectPrivacySdkResultBindings(sdkAssertion);
  } else {
    assertDirectPrivacySdkResult(sdkAssertion);
  }
  const poolCalldata = sdkResult.callAndProof.call.calldata;
  if (!poolCalldata) throw new Error("The SDK omitted private settlement calldata.");
  const settlementEvidence = extractDirectPrivacySettlementEvidence({
    invocation,
    poolAddress: deployment.contracts.pool.address,
    policyAccountAddress: deployment.contracts.policyAccount.address,
    viewingKey: policyViewingKey,
    chainId,
    poolCalldata,
    payrollLineCount: 1,
  });
  if (
    settlementEvidence.payrollNotes.length !== 1
    || BigInt(settlementEvidence.payrollNotes[0].recipientAddress) !== BigInt(bob.address)
    || BigInt(settlementEvidence.payrollNotes[0].tokenAddress) !== BigInt(strkAddress)
    || BigInt(settlementEvidence.payrollNotes[0].amountAtomic) !== BigInt(amountAtomic)
  ) throw new Error("The extracted private note does not match the approved payroll line.");
  const settlementWitness = settlementMatchWitnessSchema.parse({
    version: "payo-settlement-match-witness-v1",
    executionId: runId,
    chainId,
    policyAccountAddress: deployment.contracts.policyAccount.address,
    poolAddress: deployment.contracts.pool.address,
    poolCalldata: settlementEvidence.poolCalldata,
    viewingKey: settlementEvidence.viewingKey,
    payrollNotes: settlementEvidence.payrollNotes,
    emittedNotes: settlementEvidence.emittedNotes,
  });
  const encryptedSettlementWitness = encryptVaultRecord(
    settlementWitness,
    {
      schemaVersion: 1,
      organizationId,
      recordType: "settlement-match-proof-request",
      recordId: runId,
      revision: 1,
    },
    [proofPrincipal],
  );
  const settlementProof = await proveSettlementMatchOnSelfHostedNode({
    requestId: runId,
    encryptedPayrollWitness,
    encryptedSettlementWitness,
    principal: proofPrincipal,
  });
  const expectedSettlementRoot = buildSettlementRoot(settlementEvidence.emittedNotes);
  if (
    settlementProof.chunks.length !== 1
    || settlementProof.settlementRoot !== expectedSettlementRoot
    || settlementProof.transactionReference !== settlementEvidence.transactionReference
  ) throw new Error("SettlementMatch returned a substituted settlement binding.");
  const policyCall = buildDirectPrivacyPolicyCall({
    config,
    material,
    poolCalldata,
    settlementProofChunks: settlementProof.chunks,
  });
  await createBlocks(10);
  const submissionBlock = await provider.getBlock("latest");
  const executeBefore = Math.min(
    Number(submissionBlock.timestamp) + 600,
    deployment.proofWindow.validityExpiry,
  );
  if (executeBefore <= Number(submissionBlock.timestamp) + 1) {
    throw new Error("The session execution window expired before private settlement.");
  }
  const sessionAccount = new Account({
    provider,
    address: deployment.contracts.policyAccount.address,
    signer: new Signer(sessionPrivateKey),
    cairoVersion: "1",
  });
  const outsideTransaction = await sessionAccount.getOutsideTransaction({
    caller: admin.address,
    execute_after: Number(submissionBlock.timestamp) - 1,
    execute_before: executeBefore,
  }, policyCall, OutsideExecutionVersion.V2);
  const outsideCall = outsideExecution.buildExecuteFromOutsideCall(outsideTransaction);
  const settlementResponse = await admin.execute(outsideCall, transactionDetails({
    proofFacts: sdkResult.callAndProof.proof.proofFacts,
    proof: sdkResult.callAndProof.proof.data,
  }));
  const settlementReceipt = await waitFor(settlementResponse.transaction_hash);
  if (!("block_number" in settlementReceipt)) {
    throw new Error("The private settlement receipt has no accepted block number.");
  }
  await createBlocks(1);
  const recipientAfter = await privateBalance(bobTransfers);
  if (recipientAfter - recipientBefore !== BigInt(amountAtomic)) {
    throw new Error(
      `Recipient private STRK changed by ${recipientAfter - recipientBefore}, expected ${amountAtomic}.`,
    );
  }

  const policyAccount = new Contract({
    abi: policyAccountArtifact.abi,
    address: deployment.contracts.policyAccount.address,
    providerOrAccount: admin,
  });
  const [finalStatus, settlementSource, progress, chunkVerified, policyState, onchainReceipt] =
    await Promise.all([
      payrollSeal.call("get_run_status", [nullifierHigh, nullifierLow]),
      payrollSeal.call("get_settlement_source", [nullifierHigh, nullifierLow]),
      payrollSeal.call("get_settlement_progress", [nullifierHigh, nullifierLow]),
      payrollSeal.call("is_settlement_chunk_verified", [nullifierHigh, nullifierLow, 0]),
      policyAccount.call("get_policy", [policyId]),
      policyAccount.call("get_settlement_receipt", [nullifierHigh, nullifierLow]),
    ]);
  const progressValues = Array.isArray(progress)
    ? progress
    : Object.values(progress as Record<string, unknown>);
  if (
    asScalar(finalStatus) !== 3n
    || asScalar(settlementSource) !== BigInt(deployment.contracts.policyAccount.address)
    || progressValues.length !== 2
    || asScalar(progressValues[0]) !== 1n
    || asScalar(progressValues[1]) !== 1n
    || asScalar(chunkVerified) !== 1n
  ) throw new Error("The PAYO seal did not reach one-chunk FINALIZED state.");
  const state = policyState as Record<string, unknown>;
  const receipt = onchainReceipt as Record<string, unknown>;
  const [transactionReferenceHigh, transactionReferenceLow] = splitDirectPrivacyRoot(
    settlementEvidence.transactionReference,
  );
  const [settlementRootHigh, settlementRootLow] = splitDirectPrivacyRoot(
    expectedSettlementRoot,
  );
  if (
    asScalar(state.configured) !== 1n
    || asScalar(state.revoked) !== 0n
    || asScalar(state.used_call_count) !== 1n
    || asScalar(state.period_call_count) !== 1n
    || asScalar(receipt.exists) !== 1n
    || asScalar(receipt.policy_id) !== BigInt(policyId)
    || asScalar(receipt.manifest_root_high) !== BigInt(sealedPayroll.manifestRootHigh)
    || asScalar(receipt.manifest_root_low) !== BigInt(sealedPayroll.manifestRootLow)
    || asScalar(receipt.transaction_reference_high) !== BigInt(transactionReferenceHigh)
    || asScalar(receipt.transaction_reference_low) !== BigInt(transactionReferenceLow)
    || asScalar(receipt.settlement_root_high) !== BigInt(settlementRootHigh)
    || asScalar(receipt.settlement_root_low) !== BigInt(settlementRootLow)
    || asScalar(receipt.emitted_note_count) < 1n
  ) throw new Error("The policy-account receipt is not bound to the finalized settlement.");

  let replayRejected = false;
  try {
    const replayResponse = await admin.execute(outsideCall, transactionDetails({
      proofFacts: sdkResult.callAndProof.proof.proofFacts,
      proof: sdkResult.callAndProof.proof.data,
    }));
    await waitFor(replayResponse.transaction_hash);
  } catch {
    replayRejected = true;
  }
  if (!replayRejected) throw new Error("The policy account accepted a replayed session execution.");
  if (
    asScalar(await payrollSeal.call("get_run_status", [nullifierHigh, nullifierLow])) !== 3n
    || await privateBalance(bobTransfers) !== recipientAfter
  ) throw new Error("The rejected replay changed finalized state or recipient balance.");

  const evidence = {
    schemaVersion: "payo.phase4.private-payroll-devnet.v1",
    generatedAt: new Date().toISOString(),
    chainId,
    rpcVersion,
    devnetVersion,
    proofMode: transactionProofMode,
    privacySdk: {
      version: PAYO_PRIVACY_SDK_VERSION,
      revision: PAYO_PRIVACY_SDK_REVISION,
      poolClassHash: expectedPoolClassHash,
    },
    run: {
      runId,
      requestCommitment: material.requestCommitment,
      agreementRoot: payroll.agreementRoot,
      manifestRoot: payroll.manifestRoot,
      policyRoot: payroll.policyRoot,
      fxRoot: payroll.fxRoot,
      runNullifier: payroll.runNullifier,
      settlementRoot: expectedSettlementRoot,
      transactionReference: settlementEvidence.transactionReference,
      token: "STRK",
      amountAtomic,
      recipient: num.toHex(BigInt(bob.address)),
    },
    contracts: deployment.contracts,
    transactions: {
      registryConfiguration: registryResponse.transaction_hash,
      fxPublication: fxResponse.transaction_hash,
      payrollPrecommit: precommitResponse.transaction_hash,
      payrollProofShards: shardTransactions,
      recipientRegistration: bobRegistrationTransactionHash,
      tokenApproval: approvalResponse.transaction_hash,
      accountProvisioning: provisioningTransactionHash,
      policyConfiguration: configurationResponse.transaction_hash,
      atomicPrivatePayrollAndFinalization: settlementResponse.transaction_hash,
    },
    settlementBlockNumber: settlementReceipt.block_number,
    proofs: {
      payrollIntegrity: {
        circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
        shardCalldataHashes: payrollProof.shards.map((shard) => shard.calldataHash),
      },
      settlementMatch: {
        circuitSha256: settlementProof.circuitSha256,
        verificationKeySha256: settlementProof.verificationKeySha256,
        calldataHash: settlementProof.chunks[0].calldataHash,
        provingTimeMs: settlementProof.provingTimeMs,
      },
      sdkTransactionProofBytesPresent:
        typeof sdkResult.callAndProof.proof.data === "string"
        && sdkResult.callAndProof.proof.data.length > 0,
      sdkProofFactsPresent: sdkResult.callAndProof.proof.proofFacts.length > 0,
    },
    checks: {
      payrollIntegrityPrecommittedBeforePayment: true,
      bothPayrollIntegrityShardsVerifiedBeforePayment: true,
      payrollIntegrityProvenBeforePayment: true,
      exactSdkCiphertextExtractedBeforeSettlementProof: true,
      settlementMatchVerifiedOnchain: true,
      privatePaymentAndFinalizationAtomic: true,
      policyScopeAndAuthorizedRunEnforced: true,
      recipientPrivateNoteDiscovered: true,
      recipientBalanceDeltaExact: true,
      settlementReceiptMatchesProof: true,
      sealFinalized: true,
      replayRejected: true,
    },
    privateBalanceEvidenceAtomic: {
      recipientBefore: recipientBefore.toString(),
      recipientAfter: recipientAfter.toString(),
      delta: (recipientAfter - recipientBefore).toString(),
    },
    limitations: [
      "Devnet evidence uses one synthetic STRK payroll line and deterministic local accounts.",
      "The official Privacy Pool integration runs with Devnet transaction-proof verification disabled because Devnet's fake proof facts are wire-incompatible with the pinned pool; this is not full transaction-OS proof evidence.",
      "Mainnet declaration, deployment and public operator addresses remain a Phase 5 release gate.",
    ],
  };
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
