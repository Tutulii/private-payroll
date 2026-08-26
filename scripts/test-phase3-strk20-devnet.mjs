import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const rpcUrl = process.env.PAYO_DEVNET_RPC_URL ?? "http://127.0.0.1:5055";
const devnetProofMode = process.env.PAYO_DEVNET_PROOF_MODE ?? "none";
const sdkRoot = process.env.PAYO_PRIVACY_SDK_ROOT;
const poolSierraPath = process.env.PAYO_PRIVACY_POOL_SIERRA;
const poolCasmPath = process.env.PAYO_PRIVACY_POOL_CASM;
const expectedPoolClassHash =
  process.env.PAYO_PRIVACY_POOL_CLASS_HASH
  ?? "0x52107fadffab71bdcbb6b2ccb68ba3e1b5558d94036538053e159d3076ad633";
const action = process.argv[2] ?? "probe";

if (!["probe", "integrate", "integrate-exceptions"].includes(action)) {
  throw new Error(
    "Usage: node scripts/test-phase3-strk20-devnet.mjs <probe|integrate|integrate-exceptions>",
  );
}

if (!sdkRoot || !poolSierraPath || !poolCasmPath) {
  throw new Error(
    "PAYO_PRIVACY_SDK_ROOT, PAYO_PRIVACY_POOL_SIERRA, and PAYO_PRIVACY_POOL_CASM are required.",
  );
}

async function importFile(path) {
  return import(pathToFileURL(resolve(path)).href);
}

const [
  sdk,
  sdkTesting,
  starknet,
  poolAbiModule,
  invocationFactoryModule,
  screeningSignerModule,
  proofFactsModule,
] = await Promise.all([
  importFile(resolve(sdkRoot, "dist/index.js")),
  importFile(resolve(sdkRoot, "dist/testing/index.js")),
  importFile(resolve(sdkRoot, "node_modules/starknet/dist/index.mjs")),
  importFile(resolve(sdkRoot, "dist/internal/abi.js")),
  importFile(resolve(sdkRoot, "dist/internal/proof-invocation-factory.js")),
  importFile(resolve(sdkRoot, "dist/testing/screening-signer.js")),
  importFile(resolve(sdkRoot, "dist/utils/proof-facts.js")),
]);

const {
  createPrivateTransfers,
  ProvingServiceProofProvider,
} = sdk;
const { CallMockProofProvider, ContractDiscoveryProvider } = sdkTesting;
const {
  Account,
  CallData,
  Contract,
  EDataAvailabilityMode,
  ETransactionVersion,
  OutsideExecutionVersion,
  RpcProvider,
  constants,
  hash,
  num,
} = starknet;
const { PrivacyPoolABI } = poolAbiModule;
const { extractExecuteViewCalldata } = invocationFactoryModule;
const {
  SCREENING_SIGNER_PRIVATE_KEY,
  SCREENING_SIGNER_PUBLIC_KEY,
  signScreeningAttestation,
} = screeningSignerModule;
const { buildProofFacts } = proofFactsModule;
const clientActionsType = "core::array::Span::<privacy::actions::ClientAction>";
const actionsDecoder = new CallData(PrivacyPoolABI);

const provider = new RpcProvider({
  nodeUrl: rpcUrl,
  batch: 0,
  chainId: constants.StarknetChainId.SN_SEPOLIA,
});

async function rpc(method, params = {}) {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: method, method, params }),
  });
  if (!response.ok) throw new Error(`${method} returned HTTP ${response.status}.`);
  const body = await response.json();
  if (body.error) throw new Error(`${method} failed: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function waitFor(transactionHash) {
  const receipt = await provider.waitForTransaction(transactionHash, {
    retries: 1_200,
    retryInterval: 100,
  });
  if (!receipt.isSuccess()) {
    throw new Error(`Transaction ${transactionHash} did not succeed.`);
  }
  return receipt;
}

async function createBlocks(count) {
  for (let index = 0; index < count; index += 1) {
    await rpc("devnet_createBlock");
  }
}

function accountFor(raw) {
  return new Account({
    provider,
    address: raw.address,
    signer: raw.private_key,
    cairoVersion: "1",
  });
}

const resourceBounds = {
  l1_gas: { max_amount: 10_000_000_000n, max_price_per_unit: 1n },
  l2_gas: { max_amount: 10_000_000_000n, max_price_per_unit: 1n },
  l1_data_gas: { max_amount: 10_000_000_000n, max_price_per_unit: 1n },
};

function transactionDetails(overrides = {}) {
  return {
    resourceBounds,
    tip: 0n,
    feeDataAvailabilityMode: EDataAvailabilityMode.L2,
    nonceDataAvailabilityMode: EDataAvailabilityMode.L2,
    version: ETransactionVersion.V3,
    ...overrides,
  };
}

async function executePrivate(admin, callAndProof) {
  if (
    devnetProofMode !== "none"
    && (!callAndProof?.proof?.data || callAndProof.proof.data.length === 0)
  ) {
    throw new Error("The privacy SDK returned no transaction proof.");
  }
  if (!Array.isArray(callAndProof.proof.proofFacts) || callAndProof.proof.proofFacts.length === 0) {
    throw new Error("The privacy SDK returned no proof facts.");
  }

  await createBlocks(10);
  // Outside-execution windows are checked against Starknet block time. Devnet
  // tests deliberately move chain time to exercise policy windows, so host
  // wall-clock time would create an invalid or misleading signature window.
  const now = Number((await provider.getBlock("latest")).timestamp);
  const outside = await admin.getOutsideTransaction(
    {
      caller: admin.address,
      execute_after: Math.max(0, now - 3_600),
      execute_before: now + 3_600,
    },
    callAndProof.call,
    OutsideExecutionVersion.V2,
  );
  const response = await admin.executeFromOutside(outside, {
    ...transactionDetails(),
    proofFacts: callAndProof.proof.proofFacts,
    proof: callAndProof.proof.data,
  });
  return waitFor(response.transaction_hash);
}

const rpcVersion = await rpc("starknet_specVersion", []);
if (rpcVersion !== "0.10.2") {
  throw new Error(`Expected Devnet RPC 0.10.2, received ${rpcVersion}.`);
}
if (await provider.getChainId() !== constants.StarknetChainId.SN_SEPOLIA) {
  throw new Error("Refusing to run outside a SN_SEPOLIA Devnet.");
}

const accounts = await rpc("devnet_getPredeployedAccounts");
if (!Array.isArray(accounts) || accounts.length < 3) {
  throw new Error("At least three deterministic Devnet accounts are required.");
}
const alice = accountFor(accounts[0]);
const bob = accountFor(accounts[1]);
const admin = accountFor(accounts.at(-1));

const [poolSierraRaw, poolCasmRaw] = await Promise.all([
  readFile(resolve(poolSierraPath), "utf8"),
  readFile(resolve(poolCasmPath), "utf8"),
]);
const poolSierra = JSON.parse(poolSierraRaw);
const poolCasm = JSON.parse(poolCasmRaw);
const actualPoolClassHash = num.toHex(BigInt(hash.computeContractClassHash(poolSierra)));
if (actualPoolClassHash !== num.toHex(BigInt(expectedPoolClassHash))) {
  throw new Error(
    `Privacy pool class hash ${actualPoolClassHash} does not match pinned ${expectedPoolClassHash}.`,
  );
}

let poolAddress;
if (action === "probe") {
  let declaration;
  try {
    declaration = await admin.declareIfNot(
      {
        contract: poolSierra,
        casm: poolCasm,
        compiledClassHash: hash.computeCompiledClassHash(poolCasm),
      },
      transactionDetails(),
    );
  } catch (error) {
    const rpcError = error?.baseError;
    throw new Error(
      rpcError
        ? `Privacy pool declaration failed (${rpcError.code}): ${rpcError.message}; ${JSON.stringify(rpcError.data)}`
        : `Privacy pool declaration failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (declaration.transaction_hash) await waitFor(declaration.transaction_hash);
  const deployment = await admin.deployContract(
    {
      classHash: declaration.class_hash,
      constructorCalldata: [
        admin.address,
        "0x1",
        num.toHex(SCREENING_SIGNER_PUBLIC_KEY),
        "450",
      ],
      salt: "0x5041594f5f5354524b32305f504f4f4c",
      unique: false,
    },
    transactionDetails(),
  );
  await waitFor(deployment.transaction_hash);
  poolAddress = num.toHex(BigInt(deployment.contract_address));
} else {
  if (!process.env.PAYO_DEVNET_POOL_ADDRESS) {
    throw new Error("PAYO_DEVNET_POOL_ADDRESS is required for the integrated settlement test.");
  }
  poolAddress = num.toHex(BigInt(process.env.PAYO_DEVNET_POOL_ADDRESS));
}
const deployedClassHash = num.toHex(BigInt(await provider.getClassHashAt(poolAddress)));
if (deployedClassHash !== actualPoolClassHash) {
  throw new Error(`Deployed pool class ${deployedClassHash} does not match ${actualPoolClassHash}.`);
}

const pool = new Contract({
  abi: PrivacyPoolABI,
  address: poolAddress,
  providerOrAccount: admin,
}).typedv2(PrivacyPoolABI);
const discovery = new ContractDiscoveryProvider(pool);
const upstreamProofProvider = new ProvingServiceProofProvider(
  rpcUrl,
  constants.StarknetChainId.SN_SEPOLIA,
  {
    requestTimeoutMs: 20 * 60 * 1_000,
    blockIdentifier: "latest",
    nodeUrl: rpcUrl,
    poolAddress,
    retry: { maxRetries: 0 },
  },
);
const callProofProvider = new CallMockProofProvider(
  provider,
  constants.StarknetChainId.SN_SEPOLIA,
);

async function screeningDataFor(invocation, blockIdentifier) {
  const innerCalldata = extractExecuteViewCalldata(invocation.calldata);
  if (innerCalldata.length < 3) return undefined;
  const decodedActions = actionsDecoder.decodeParameters(
    clientActionsType,
    innerCalldata.slice(2),
  );
  if (!decodedActions.some((action) => action.activeVariant() === "Deposit")) {
    return undefined;
  }
  const block = await provider.getBlock(blockIdentifier);
  return {
    signature: signScreeningAttestation(
      SCREENING_SIGNER_PRIVATE_KEY,
      BigInt(await provider.getChainId()),
      BigInt(innerCalldata[0]),
      Number(block.timestamp),
    ),
  };
}

// starknet-devnet 0.8.0-rc.3 adds an `order` field to L2-to-L1 messages even
// though the pinned Privacy SDK's deliberately strict wire schema predates it.
// Keep the SDK's invocation/default-details implementation, but normalize that
// one documented node extension at this boundary. Proof bytes, proof facts,
// message addresses, and payloads pass through unchanged.
const proofProvider = {
  getDefaultDetails: () => upstreamProofProvider.getDefaultDetails(),
  async prove(invocation, blockIdentifier = "latest") {
    if (devnetProofMode === "none") {
      const compiled = await callProofProvider.prove(invocation, blockIdentifier);
      return {
        ...compiled,
        additionalData: await screeningDataFor(invocation, blockIdentifier),
      };
    }
    const blockId =
      typeof blockIdentifier === "number" || typeof blockIdentifier === "bigint"
        ? { block_number: Number(blockIdentifier) }
        : blockIdentifier;
    const provingBlock = await provider.getBlock(blockIdentifier);
    const result = await rpc("starknet_proveTransaction", {
      block_id: blockId,
      transaction: invocation,
    });
    if (
      !result
      || typeof result.proof !== "string"
      || (devnetProofMode !== "none" && result.proof.length === 0)
      || !Array.isArray(result.proof_facts)
      || result.proof_facts.length === 0
      || !Array.isArray(result.l2_to_l1_messages)
    ) {
      throw new Error("Devnet returned an invalid transaction-proof response.");
    }
    const poolMessage = result.l2_to_l1_messages.find(
      (message) =>
        typeof message?.from_address === "string"
        && message.from_address.toLowerCase() === String(invocation.sender_address).toLowerCase(),
    );
    if (!poolMessage || !Array.isArray(poolMessage.payload) || poolMessage.payload.length === 0) {
      throw new Error("Devnet proof response omitted the privacy-pool L2-to-L1 payload.");
    }
    const additionalData =
      await screeningDataFor(invocation, blockIdentifier) ?? result.additional_data;
    const poolClassHash = poolMessage.payload[0];
    const serverActions = poolMessage.payload.slice(1);
    const contractProofFacts = buildProofFacts(
      invocation.sender_address,
      poolClassHash,
      serverActions,
      BigInt(provingBlock.block_number),
      provingBlock.block_hash ?? "0x0",
      await provider.getChainId(),
    );
    return {
      data: result.proof,
      output: poolMessage.payload,
      proofFacts: contractProofFacts,
      additionalData,
    };
  },
};
const aliceTransfers = createPrivateTransfers({
  account: alice,
  viewingKeyProvider: { getViewingKey: async () => 0xA11CEn },
  provingProvider: proofProvider,
  discoveryProvider: discovery,
  poolContractAddress: poolAddress,
  poolMode: "screening",
});
const bobTransfers = createPrivateTransfers({
  account: bob,
  viewingKeyProvider: { getViewingKey: async () => 0xB0Bn },
  provingProvider: proofProvider,
  discoveryProvider: discovery,
  poolContractAddress: poolAddress,
  poolMode: "screening",
});

const strkAddress =
  "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

if (action === "probe") {
  const bobRegistration = await bobTransfers.build().register().execute();
  const bobRegistrationReceipt = await executePrivate(admin, bobRegistration.callAndProof);

  const approval = await alice.execute(
  {
    contractAddress: strkAddress,
    entrypoint: "approve",
    calldata: [poolAddress, "100", "0"],
  },
  transactionDetails(),
);
await waitFor(approval.transaction_hash);

  const privateTransfer = await aliceTransfers
  .build({
    autoRegister: true,
    autoSetup: true,
    autoDiscover: { notes: "refresh", channels: "refresh" },
  })
  .with(strkAddress)
  .deposit({ amount: 100n })
  .transfer({ recipient: bob.address, amount: 40n })
  .surplusTo(alice.address)
  .execute();
  const privateTransferReceipt = await executePrivate(admin, privateTransfer.callAndProof);

  await createBlocks(1);
  const [{ notes: aliceNotes }, { notes: bobNotes }] = await Promise.all([
  aliceTransfers.discoverNotes(),
  bobTransfers.discoverNotes(),
]);
  const aliceStrkNotes = aliceNotes.get(BigInt(strkAddress)) ?? [];
  const bobStrkNotes = bobNotes.get(BigInt(strkAddress)) ?? [];
  const alicePrivateBalance = aliceStrkNotes.reduce((sum, note) => sum + note.amount, 0n);
  const bobPrivateBalance = bobStrkNotes.reduce((sum, note) => sum + note.amount, 0n);
  if (alicePrivateBalance !== 60n || bobPrivateBalance !== 40n) {
    throw new Error(
      `Private balance mismatch: Alice ${alicePrivateBalance}, Bob ${bobPrivateBalance}.`,
    );
  }

  const evidence = {
  schemaVersion: "payo.phase3.strk20-probe.v1",
  generatedAt: new Date().toISOString(),
  chainId: await provider.getChainId(),
  devnetVersion: process.env.PAYO_DEVNET_VERSION ?? "0.8.0-rc.3",
  rpcVersion,
  proofMode: devnetProofMode,
  privacySdkRevision: "PRIVACY-0.14.3-RC.2",
  privacyPoolRevision: "PRIVACY-0.14.3-RC.0",
  privacyPoolClassHash: actualPoolClassHash,
  privacyPoolArtifactSha256: {
    sierra: createHash("sha256").update(poolSierraRaw).digest("hex"),
    casm: createHash("sha256").update(poolCasmRaw).digest("hex"),
  },
  privacyPoolAddress: poolAddress,
  registrationTransactionHash: bobRegistrationReceipt.transaction_hash,
  approvalTransactionHash: approval.transaction_hash,
  privateTransferTransactionHash: privateTransferReceipt.transaction_hash,
  privateBalancesAtomic: {
    alice: alicePrivateBalance.toString(),
    bob: bobPrivateBalance.toString(),
  },
  checks: {
    proofBytesPresent: Boolean(privateTransfer.callAndProof.proof.data),
    fullTransactionProofVerification: false,
    proofFactsPresent: true,
    recipientDiscoveredPrivateNote: true,
    senderChangeDiscoveredPrivateNote: true,
  },
  };

  await writeFile(
    resolve(root, "evidence/phase3-strk20-probe.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
    { mode: 0o600 },
  );
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}

function normalizeHex(value) {
  return num.toHex(BigInt(value));
}

function asScalar(value) {
  if (typeof value === "boolean") return value ? 1n : 0n;
  if (["bigint", "number", "string"].includes(typeof value)) return BigInt(value);
  if (Array.isArray(value) && value.length === 1) return asScalar(value[0]);
  if (value && typeof value === "object") {
    const values = Object.values(value);
    if (values.length === 1) return asScalar(values[0]);
  }
  throw new Error(`Expected scalar response, received ${JSON.stringify(value)}.`);
}

async function readJson(relativePath) {
  return JSON.parse(await readFile(resolve(root, relativePath), "utf8"));
}

async function privateStrkBalances() {
  await createBlocks(1);
  const [{ notes: aliceNotes }, { notes: bobNotes }] = await Promise.all([
    aliceTransfers.discoverNotes(),
    bobTransfers.discoverNotes(),
  ]);
  const sum = (notes) => (notes.get(BigInt(strkAddress)) ?? [])
    .reduce((total, note) => total + note.amount, 0n);
  return { alice: sum(aliceNotes), bob: sum(bobNotes) };
}

if (action === "integrate") {
  const [deployment, proofSummary, sealArtifact, policyArtifact, obligationArtifact,
    shard0Source, shard1Source] = await Promise.all([
    readJson("evidence/phase3-devnet-deployment.json"),
    readJson("evidence/phase3-devnet-fixtures/advanced-matrix-proof.json"),
    readJson("contracts/target/dev/payo_contracts_PayoPayrollSeal.contract_class.json"),
    readJson("contracts/target/dev/payo_contracts_PayoPolicyRegistry.contract_class.json"),
    readJson("contracts/target/dev/payo_contracts_PayoObligationRootRegistry.contract_class.json"),
    readFile(resolve(root, "evidence/phase3-devnet-fixtures/advanced-matrix-shard-0.txt"), "utf8"),
    readFile(resolve(root, "evidence/phase3-devnet-fixtures/advanced-matrix-shard-1.txt"), "utf8"),
  ]);
  const shards = [shard0Source, shard1Source]
    .map((source) => source.trim().split(/\s+/).filter(Boolean));
  if (shards.some((shard) => shard.length < 1_000 || shard.some((felt) => !/^0x[0-9a-f]+$/i.test(felt)))) {
    throw new Error("The workflow-matrix proof calldata is missing or malformed.");
  }
  const first = proofSummary.shards?.[0]?.publicInputs;
  const second = proofSummary.shards?.[1]?.publicInputs;
  if (!first || !second) throw new Error("The workflow-matrix proof manifest is incomplete.");
  for (const key of Object.keys(first)) {
    if (key !== "shardIndex" && normalizeHex(first[key]) !== normalizeHex(second[key])) {
      throw new Error(`Workflow-matrix proof shards disagree on ${key}.`);
    }
  }
  const fields = {
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
  if (fields.chainId !== normalizeHex(await provider.getChainId())) {
    throw new Error("The workflow-matrix proof is bound to another chain.");
  }
  if (fields.sealAddress !== normalizeHex(deployment.contracts.payrollSeal.address)) {
    throw new Error("The workflow-matrix proof is not bound to this PAYO seal.");
  }

  const seal = new Contract({
    abi: sealArtifact.abi,
    address: deployment.contracts.payrollSeal.address,
    providerOrAccount: admin,
  });
  const policy = new Contract({
    abi: policyArtifact.abi,
    address: deployment.contracts.policyRegistry.address,
    providerOrAccount: admin,
  });
  const obligations = new Contract({
    abi: obligationArtifact.abi,
    address: deployment.contracts.obligationRegistry.address,
    providerOrAccount: admin,
  });
  const configuredPool = normalizeHex(await seal.call("get_pool"));
  if (configuredPool !== poolAddress) {
    throw new Error(`PAYO seal pool ${configuredPool} does not match official pool ${poolAddress}.`);
  }

  const proofHashes = shards.map((shard, index) => {
    const actual = normalizeHex(hash.computePoseidonHashOnElements(shard));
    if (actual !== normalizeHex(proofSummary.shards[index].calldataHash)) {
      throw new Error(`Workflow-matrix shard ${index} is not hash-bound to its manifest.`);
    }
    return actual;
  });
  const activationTime = Math.max(1, fields.validityStart - 100);
  const existingStatus = asScalar(await seal.call("get_run_status", fields.nullifier));
  if (existingStatus !== 0n && existingStatus !== 1n) {
    throw new Error(`Integrated test cannot resume from PAYO status ${existingStatus}.`);
  }
  let scheduleTransactionHash;
  if (existingStatus === 0n) {
    await rpc("devnet_setTime", { time: activationTime });
    const schedule = await admin.execute([
      policy.populate("schedule_policy_root", [...fields.policy, activationTime, fields.validityExpiry]),
      policy.populate("schedule_fx_root", [...fields.fx, activationTime, fields.validityExpiry]),
      policy.populate("schedule_verifier", [
        0,
        fields.proofVersion,
        deployment.contracts.advancedBundle.address,
        activationTime,
        fields.validityExpiry,
      ]),
      obligations.populate("schedule_obligation_root", [
        ...fields.agreement,
        activationTime,
        fields.validityExpiry,
      ]),
    ], transactionDetails());
    await waitFor(schedule.transaction_hash);
    scheduleTransactionHash = schedule.transaction_hash;
  } else {
    const policyEvents = await provider.getEvents({
      address: deployment.contracts.policyRegistry.address,
      from_block: { block_number: 0 },
      to_block: "latest",
      chunk_size: 100,
    });
    scheduleTransactionHash = policyEvents.events.at(-1)?.transaction_hash;
    if (!scheduleTransactionHash) throw new Error("Could not recover the registry schedule receipt.");
  }
  await rpc("devnet_setTime", { time: fields.validityStart });
  const configurationActive = await Promise.all([
    policy.call("is_policy_root_valid", fields.policy),
    policy.call("is_fx_root_valid", fields.fx),
    policy.call("is_verifier_valid", [0, fields.proofVersion]),
    obligations.call("is_obligation_root_valid", fields.agreement),
  ]);
  if (!configurationActive.every(Boolean)) {
    throw new Error("A proof-bound registry entry is inactive before private settlement.");
  }

  if (!Array.isArray(proofSummary.coverage) || proofSummary.coverage.length !== 7) {
    throw new Error("The integrated settlement requires all seven Phase 3 workflow profiles.");
  }
  // Create a distinct private note for every proved workflow. Direct equality
  // between these private outputs and committed manifest lines remains the
  // separate Phase 4 SettlementMatch assertion and is not claimed here.
  const workflowPrivateOutputs = proofSummary.coverage.map((entry) => ({
    workflow: entry.workflow,
    recipient: bob.address,
    amount: 1n,
  }));
  const settlementAmount = workflowPrivateOutputs
    .reduce((total, output) => total + output.amount, 0n);
  const sealCalldata = [
    0,
    fields.proofVersion,
    fields.schemaVersion,
    ...fields.agreement,
    ...fields.manifest,
    ...fields.policy,
    ...fields.fx,
    ...fields.nullifier,
    fields.validityStart,
    fields.validityExpiry,
    ...proofHashes,
    [],
    [],
  ];
  let before;
  let afterSettlement;
  let privateSettlementTransactionHash;
  let privateSettlementBlockNumber;
  let privateSettlementProofBytesPresent = false;
  if (existingStatus === 0n) {
    before = await privateStrkBalances();
    if (before.alice < settlementAmount) {
      throw new Error(`Alice has only ${before.alice} private STRK atomic units.`);
    }
    const privateSettlement = await aliceTransfers
      .build({
        autoSetup: true,
        autoSelectNotes: "all",
        autoDiscover: { notes: "refresh", channels: "refresh" },
      })
      .with(strkAddress)
      .transfer(...workflowPrivateOutputs.map((output) => ({
        recipient: output.recipient,
        amount: output.amount,
      })))
      .surplusTo(alice.address)
      .done()
      .invoke(() => ({
        contractAddress: deployment.contracts.payrollSeal.address,
        calldata: sealCalldata,
      }))
      .execute();
    const privateSettlementReceipt = await executePrivate(admin, privateSettlement.callAndProof);
    privateSettlementTransactionHash = privateSettlementReceipt.transaction_hash;
    privateSettlementBlockNumber = privateSettlementReceipt.block_number;
    privateSettlementProofBytesPresent = Boolean(privateSettlement.callAndProof.proof.data);
    if (asScalar(await seal.call("get_run_status", fields.nullifier)) !== 1n) {
      throw new Error("The atomic private settlement did not leave PAYO in sealed status.");
    }
    afterSettlement = await privateStrkBalances();
  } else {
    afterSettlement = await privateStrkBalances();
    before = {
      alice: afterSettlement.alice + settlementAmount,
      bob: afterSettlement.bob - settlementAmount,
    };
    if (before.bob < 0n) throw new Error("Recovered recipient balance is inconsistent.");
    const sealEvents = await provider.getEvents({
      address: deployment.contracts.payrollSeal.address,
      from_block: { block_number: 0 },
      to_block: "latest",
      chunk_size: 100,
    });
    const sealedEvent = sealEvents.events.findLast((event) =>
      event.keys?.some((key) => normalizeHex(key) === normalizeHex(fields.nullifier[0]))
      && event.keys?.some((key) => normalizeHex(key) === normalizeHex(fields.nullifier[1]))
    );
    if (!sealedEvent) throw new Error("Could not recover the atomic PAYO seal receipt.");
    privateSettlementTransactionHash = sealedEvent.transaction_hash;
    privateSettlementBlockNumber = sealedEvent.block_number;
  }
  if (
    afterSettlement.alice !== before.alice - settlementAmount
    || afterSettlement.bob !== before.bob + settlementAmount
  ) {
    throw new Error(
      `Private settlement mismatch: before ${before.alice}/${before.bob}, after ${afterSettlement.alice}/${afterSettlement.bob}.`,
    );
  }

  const tampered = [...shards[0]];
  tampered[tampered.length - 1] = normalizeHex(BigInt(tampered.at(-1)) ^ 1n);
  let tamperedProofRejected = false;
  try {
    const tamperedResponse = await admin.execute(
      seal.populate("verify_sealed_shard", [...fields.nullifier, 0, tampered]),
      transactionDetails(),
    );
    await waitFor(tamperedResponse.transaction_hash);
  } catch {
    tamperedProofRejected = true;
  }
  if (!tamperedProofRejected) throw new Error("PAYO accepted tampered proof calldata.");
  if (
    asScalar(await seal.call("get_run_status", fields.nullifier)) !== 1n
    || asScalar(await seal.call("is_sealed_shard_verified", [...fields.nullifier, 0])) !== 0n
  ) {
    throw new Error("Rejected tampered calldata changed PAYO proof state.");
  }

  const verifierReceipts = [];
  for (const [shardIndex, calldata] of shards.entries()) {
    const response = await admin.execute(
      seal.populate("verify_sealed_shard", [...fields.nullifier, shardIndex, calldata]),
      transactionDetails(),
    );
    const receipt = await waitFor(response.transaction_hash);
    verifierReceipts.push({
      shardIndex,
      transactionHash: response.transaction_hash,
      blockNumber: receipt.block_number,
    });
  }
  const finalStatus = asScalar(await seal.call("get_run_status", fields.nullifier));
  if (finalStatus !== 2n) throw new Error(`PAYO final status is ${finalStatus}, expected 2.`);

  const replay = await aliceTransfers
    .build({
      autoSetup: true,
      autoSelectNotes: "all",
      autoDiscover: { notes: "refresh", channels: "refresh" },
    })
    .with(strkAddress)
    .transfer({ recipient: bob.address, amount: 1n })
    .surplusTo(alice.address)
    .done()
    .invoke(() => ({
      contractAddress: deployment.contracts.payrollSeal.address,
      calldata: sealCalldata,
    }))
    .execute();
  let replayRejected = false;
  try {
    await executePrivate(admin, replay.callAndProof);
  } catch {
    replayRejected = true;
  }
  if (!replayRejected) throw new Error("PAYO accepted a pool-originated nullifier replay.");
  const afterReplay = await privateStrkBalances();
  if (afterReplay.alice !== afterSettlement.alice || afterReplay.bob !== afterSettlement.bob) {
    throw new Error("A rejected nullifier replay changed private STRK balances.");
  }

  const evidence = {
    schemaVersion: "payo.phase3.private-settlement.v1",
    generatedAt: new Date().toISOString(),
    passed: true,
    chainId: await provider.getChainId(),
    devnetVersion: process.env.PAYO_DEVNET_VERSION ?? "0.8.0-rc.3",
    rpcVersion,
    proofMode: devnetProofMode,
    privacySdkRevision: "PRIVACY-0.14.3-RC.2",
    privacyPoolRevision: "PRIVACY-0.14.3-RC.0",
    privacyPoolClassHash: actualPoolClassHash,
    privacyPoolAddress: poolAddress,
    payoSealAddress: normalizeHex(deployment.contracts.payrollSeal.address),
    workflowCoverage: proofSummary.coverage,
    proofBindings: {
      manifestRoot: fields.manifest.map(normalizeHex),
      runNullifier: fields.nullifier.map(normalizeHex),
      proofHashes,
    },
    privateSettlement: {
      tokenAddress: strkAddress,
      recipientAddress: normalizeHex(bob.address),
      amountAtomic: settlementAmount.toString(),
      workflowOutputs: workflowPrivateOutputs.map((output) => ({
        workflow: output.workflow,
        recipientAddress: normalizeHex(output.recipient),
        amountAtomic: output.amount.toString(),
      })),
      transactionHash: privateSettlementTransactionHash,
      blockNumber: privateSettlementBlockNumber,
      balancesBeforeAtomic: {
        alice: before.alice.toString(),
        bob: before.bob.toString(),
      },
      balancesAfterAtomic: {
        alice: afterSettlement.alice.toString(),
        bob: afterSettlement.bob.toString(),
      },
    },
    transactions: {
      schedule: scheduleTransactionHash,
      privateSettlementAndSeal: privateSettlementTransactionHash,
      verifierShards: verifierReceipts,
    },
    finalStatus: Number(finalStatus),
    checks: {
      officialPoolClassMatched: true,
      sealConfiguredForOfficialPool: true,
      privateTransferAndPayoSealAtomic: true,
      recipientDiscoveredPrivateNote: true,
      payoProofVerifiedOnchain: true,
      tamperedProofRejected,
      poolOriginatedReplayRejected: replayRejected,
      replayPreservedPrivateBalances: true,
      proofBytesPresent: privateSettlementProofBytesPresent,
      fullTransactionProofVerification: false,
      directPrivateAmountToManifestReconciliation: false,
    },
    limitations: [
      "Pinned Starknet Devnet does not implement full transaction-proof verification; the official pool executes in proof-mode none with SDK-compiled proof facts.",
      "Direct private-note amount reconciliation against the payroll manifest is a Phase 4 SettlementMatch requirement and is not claimed here.",
    ],
  };
  await writeFile(
    resolve(root, "evidence/phase3-private-settlement-devnet.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
    { mode: 0o600 },
  );
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}

if (action === "integrate-exceptions") {
  async function readExceptionProof(profile) {
    const [summary, shard0Source, shard1Source] = await Promise.all([
      readJson(`evidence/phase3-devnet-fixtures/${profile}-proof.json`),
      readFile(resolve(root, `evidence/phase3-devnet-fixtures/${profile}-shard-0.txt`), "utf8"),
      readFile(resolve(root, `evidence/phase3-devnet-fixtures/${profile}-shard-1.txt`), "utf8"),
    ]);
    const proofShards = [shard0Source, shard1Source]
      .map((source) => source.trim().split(/\s+/).filter(Boolean));
    if (
      proofShards.some((shard) =>
        shard.length < 1_000 || shard.some((felt) => !/^0x[0-9a-f]+$/i.test(felt))
      )
    ) {
      throw new Error(`${profile} proof calldata is missing or malformed.`);
    }
    const first = summary.shards?.[0]?.publicInputs;
    const second = summary.shards?.[1]?.publicInputs;
    if (!first || !second) throw new Error(`${profile} proof manifest is incomplete.`);
    for (const key of Object.keys(first)) {
      if (key !== "shardIndex" && normalizeHex(first[key]) !== normalizeHex(second[key])) {
        throw new Error(`${profile} proof shards disagree on ${key}.`);
      }
    }
    const fields = {
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
    const proofHashes = proofShards.map((shard, index) => {
      const actual = normalizeHex(hash.computePoseidonHashOnElements(shard));
      if (actual !== normalizeHex(summary.shards[index].calldataHash)) {
        throw new Error(`${profile} shard ${index} is not hash-bound to its manifest.`);
      }
      return actual;
    });
    return { profile, summary, shards: proofShards, fields, proofHashes };
  }

  const [deployment, claim, remediation, linkage, sealArtifact, policyArtifact, obligationArtifact] =
    await Promise.all([
      readJson("evidence/phase3-devnet-deployment.json"),
      readExceptionProof("claim"),
      readExceptionProof("remediation"),
      readJson("evidence/phase3-devnet-fixtures/claim-remediation-linkage.json"),
      readJson("contracts/target/dev/payo_contracts_PayoPayrollSeal.contract_class.json"),
      readJson("contracts/target/dev/payo_contracts_PayoPolicyRegistry.contract_class.json"),
      readJson("contracts/target/dev/payo_contracts_PayoObligationRootRegistry.contract_class.json"),
    ]);
  for (const proof of [claim, remediation]) {
    if (proof.fields.chainId !== normalizeHex(await provider.getChainId())) {
      throw new Error(`${proof.profile} proof is bound to another chain.`);
    }
    if (proof.fields.sealAddress !== normalizeHex(deployment.contracts.payrollSeal.address)) {
      throw new Error(`${proof.profile} proof is not bound to this PAYO seal.`);
    }
  }
  if (
    claim.fields.nullifier.map(normalizeHex).join(":")
      !== remediation.fields.nullifier.map(normalizeHex).join(":")
  ) {
    throw new Error("The remediation proof is not linked to the wage-claim nullifier.");
  }
  if (claim.fields.proofVersion !== 3 || remediation.fields.proofVersion !== 4) {
    throw new Error("The exception proofs use unexpected verifier versions.");
  }
  if (
    linkage.token !== "STRK"
    || normalizeHex(linkage.recipientAddress) !== normalizeHex(bob.address)
    || BigInt(linkage.shortfallAtomic) <= 0n
  ) {
    throw new Error("The committed claim token, recipient, or shortfall does not match settlement.");
  }

  const seal = new Contract({
    abi: sealArtifact.abi,
    address: deployment.contracts.payrollSeal.address,
    providerOrAccount: admin,
  });
  const policy = new Contract({
    abi: policyArtifact.abi,
    address: deployment.contracts.policyRegistry.address,
    providerOrAccount: admin,
  });
  const obligations = new Contract({
    abi: obligationArtifact.abi,
    address: deployment.contracts.obligationRegistry.address,
    providerOrAccount: admin,
  });
  if (normalizeHex(await seal.call("get_pool")) !== poolAddress) {
    throw new Error("Exception PAYO seal is not configured for the official privacy pool.");
  }

  const activationTime = Math.max(1, claim.fields.validityStart - 100);
  await rpc("devnet_setTime", { time: activationTime });
  const schedule = await admin.execute([
    policy.populate("schedule_policy_root", [
      ...claim.fields.policy,
      activationTime,
      claim.fields.validityExpiry,
    ]),
    policy.populate("schedule_fx_root", [
      ...claim.fields.fx,
      activationTime,
      claim.fields.validityExpiry,
    ]),
    policy.populate("schedule_verifier", [
      2,
      claim.fields.proofVersion,
      deployment.contracts.claimBundle.address,
      activationTime,
      claim.fields.validityExpiry,
    ]),
    policy.populate("schedule_verifier", [
      3,
      remediation.fields.proofVersion,
      deployment.contracts.remediationBundle.address,
      activationTime,
      remediation.fields.validityExpiry,
    ]),
    obligations.populate("schedule_obligation_root", [
      ...claim.fields.agreement,
      activationTime,
      claim.fields.validityExpiry,
    ]),
  ], transactionDetails());
  await waitFor(schedule.transaction_hash);
  await rpc("devnet_setTime", { time: claim.fields.validityStart });
  const active = await Promise.all([
    policy.call("is_policy_root_valid", claim.fields.policy),
    policy.call("is_fx_root_valid", claim.fields.fx),
    policy.call("is_verifier_valid", [2, claim.fields.proofVersion]),
    policy.call("is_verifier_valid", [3, remediation.fields.proofVersion]),
    obligations.call("is_obligation_root_valid", claim.fields.agreement),
  ]);
  if (!active.every(Boolean)) throw new Error("An exception proof registry binding is inactive.");

  function sealCalldataFor(proof, mode) {
    return [
      mode,
      proof.fields.proofVersion,
      proof.fields.schemaVersion,
      ...proof.fields.agreement,
      ...proof.fields.manifest,
      ...proof.fields.policy,
      ...proof.fields.fx,
      ...proof.fields.nullifier,
      proof.fields.validityStart,
      proof.fields.validityExpiry,
      ...proof.proofHashes,
      [],
      [],
    ];
  }

  async function rejectTamperedAndVerify(proof, terminalStatus) {
    const tampered = [...proof.shards[0]];
    tampered[tampered.length - 1] = normalizeHex(BigInt(tampered.at(-1)) ^ 1n);
    let tamperedRejected = false;
    try {
      const response = await admin.execute(
        seal.populate("verify_sealed_shard", [...proof.fields.nullifier, 0, tampered]),
        transactionDetails(),
      );
      await waitFor(response.transaction_hash);
    } catch {
      tamperedRejected = true;
    }
    if (!tamperedRejected) throw new Error(`${proof.profile} accepted tampered calldata.`);
    if (
      asScalar(await seal.call("get_run_status", proof.fields.nullifier)) !== 1n
      || asScalar(await seal.call("is_sealed_shard_verified", [...proof.fields.nullifier, 0])) !== 0n
    ) {
      throw new Error(`${proof.profile} tamper rejection changed proof state.`);
    }
    const receipts = [];
    for (const [shardIndex, calldata] of proof.shards.entries()) {
      const response = await admin.execute(
        seal.populate("verify_sealed_shard", [...proof.fields.nullifier, shardIndex, calldata]),
        transactionDetails(),
      );
      const receipt = await waitFor(response.transaction_hash);
      receipts.push({
        shardIndex,
        transactionHash: response.transaction_hash,
        blockNumber: receipt.block_number,
      });
    }
    const status = asScalar(await seal.call("get_run_status", proof.fields.nullifier));
    if (status !== BigInt(terminalStatus)) {
      throw new Error(`${proof.profile} final status ${status}; expected ${terminalStatus}.`);
    }
    return { receipts, tamperedRejected };
  }

  const balancesBeforeClaim = await privateStrkBalances();
  if (balancesBeforeClaim.bob < 1n) throw new Error("Claimant lacks a private note for claim invocation.");
  const claimCalldata = sealCalldataFor(claim, 2);
  const claimInvocation = await bobTransfers
    .build({
      autoSetup: true,
      autoSelectNotes: "all",
      autoDiscover: { notes: "refresh", channels: "refresh" },
    })
    .with(strkAddress)
    .transfer({ recipient: bob.address, amount: 1n })
    .surplusTo(bob.address)
    .done()
    .invoke(() => ({
      contractAddress: deployment.contracts.payrollSeal.address,
      calldata: claimCalldata,
    }))
    .execute();
  const claimReceipt = await executePrivate(admin, claimInvocation.callAndProof);
  if (asScalar(await seal.call("get_run_status", claim.fields.nullifier)) !== 1n) {
    throw new Error("Pool-originated wage claim did not enter sealed status.");
  }
  const claimVerification = await rejectTamperedAndVerify(claim, 4);
  const balancesAfterClaim = await privateStrkBalances();
  if (
    balancesAfterClaim.alice !== balancesBeforeClaim.alice
    || balancesAfterClaim.bob !== balancesBeforeClaim.bob
  ) {
    throw new Error("The no-payment wage-claim invocation changed private balances.");
  }

  const remediationAmount = BigInt(linkage.shortfallAtomic);
  if (balancesAfterClaim.alice < remediationAmount) {
    throw new Error("Employer lacks private STRK for remediation.");
  }
  const remediationCalldata = sealCalldataFor(remediation, 3);
  const remediationInvocation = await aliceTransfers
    .build({
      autoSetup: true,
      autoSelectNotes: "all",
      autoDiscover: { notes: "refresh", channels: "refresh" },
    })
    .with(strkAddress)
    .transfer({ recipient: bob.address, amount: remediationAmount })
    .surplusTo(alice.address)
    .done()
    .invoke(() => ({
      contractAddress: deployment.contracts.payrollSeal.address,
      calldata: remediationCalldata,
    }))
    .execute();
  const remediationReceipt = await executePrivate(admin, remediationInvocation.callAndProof);
  if (asScalar(await seal.call("get_run_status", remediation.fields.nullifier)) !== 1n) {
    throw new Error("Pool-originated remediation did not enter sealed status.");
  }
  const remediationVerification = await rejectTamperedAndVerify(remediation, 5);
  const balancesAfterRemediation = await privateStrkBalances();
  if (
    balancesAfterRemediation.alice !== balancesAfterClaim.alice - remediationAmount
    || balancesAfterRemediation.bob !== balancesAfterClaim.bob + remediationAmount
  ) {
    throw new Error("The private remediation amount did not reach the claimant.");
  }

  const replayInvocation = await aliceTransfers
    .build({
      autoSetup: true,
      autoSelectNotes: "all",
      autoDiscover: { notes: "refresh", channels: "refresh" },
    })
    .with(strkAddress)
    .transfer({ recipient: bob.address, amount: 1n })
    .surplusTo(alice.address)
    .done()
    .invoke(() => ({
      contractAddress: deployment.contracts.payrollSeal.address,
      calldata: remediationCalldata,
    }))
    .execute();
  let replayRejected = false;
  try {
    await executePrivate(admin, replayInvocation.callAndProof);
  } catch {
    replayRejected = true;
  }
  if (!replayRejected) throw new Error("PAYO accepted a pool-originated remediation replay.");
  const balancesAfterReplay = await privateStrkBalances();
  if (
    balancesAfterReplay.alice !== balancesAfterRemediation.alice
    || balancesAfterReplay.bob !== balancesAfterRemediation.bob
  ) {
    throw new Error("Rejected remediation replay changed private balances.");
  }

  const evidence = {
    schemaVersion: "payo.phase3.private-exceptions.v1",
    generatedAt: new Date().toISOString(),
    passed: true,
    chainId: await provider.getChainId(),
    devnetVersion: process.env.PAYO_DEVNET_VERSION ?? "0.8.0-rc.3",
    rpcVersion,
    proofMode: devnetProofMode,
    privacySdkRevision: "PRIVACY-0.14.3-RC.2",
    privacyPoolRevision: "PRIVACY-0.14.3-RC.0",
    privacyPoolClassHash: actualPoolClassHash,
    privacyPoolAddress: poolAddress,
    payoSealAddress: normalizeHex(deployment.contracts.payrollSeal.address),
    sharedClaimNullifier: claim.fields.nullifier.map(normalizeHex),
    committedClaim: {
      token: linkage.token,
      recipientAddress: normalizeHex(linkage.recipientAddress),
      shortfallAtomic: linkage.shortfallAtomic,
      disputedManifestRoot: linkage.disputedManifestRoot,
      remediationManifestRoot: linkage.remediationManifestRoot,
    },
    claim: {
      privateInvocationTransactionHash: claimReceipt.transaction_hash,
      verifierShards: claimVerification.receipts,
      finalStatus: 4,
      tamperedProofRejected: claimVerification.tamperedRejected,
      balancesBeforeAtomic: {
        alice: balancesBeforeClaim.alice.toString(),
        bob: balancesBeforeClaim.bob.toString(),
      },
      balancesAfterAtomic: {
        alice: balancesAfterClaim.alice.toString(),
        bob: balancesAfterClaim.bob.toString(),
      },
    },
    remediation: {
      tokenAddress: strkAddress,
      amountAtomic: remediationAmount.toString(),
      recipientAddress: normalizeHex(bob.address),
      privatePaymentAndSealTransactionHash: remediationReceipt.transaction_hash,
      verifierShards: remediationVerification.receipts,
      finalStatus: 5,
      tamperedProofRejected: remediationVerification.tamperedRejected,
      balancesBeforeAtomic: {
        alice: balancesAfterClaim.alice.toString(),
        bob: balancesAfterClaim.bob.toString(),
      },
      balancesAfterAtomic: {
        alice: balancesAfterRemediation.alice.toString(),
        bob: balancesAfterRemediation.bob.toString(),
      },
    },
    transactions: { schedule: schedule.transaction_hash },
    checks: {
      officialPoolClassMatched: true,
      sealConfiguredForOfficialPool: true,
      claimAndRemediationNullifierLinked: true,
      remediationMatchesCommittedClaimFields: true,
      claimReachedDisputedStatus: true,
      remediationPaymentAndSealAtomic: true,
      remediationReachedReconciledStatus: true,
      recipientDiscoveredPrivateRemediation: true,
      claimTamperRejected: claimVerification.tamperedRejected,
      remediationTamperRejected: remediationVerification.tamperedRejected,
      poolOriginatedReplayRejected: replayRejected,
      replayPreservedPrivateBalances: true,
      fullTransactionProofVerification: false,
      directPrivateAmountToManifestReconciliation: false,
    },
    limitations: [
      "Pinned Starknet Devnet does not implement full transaction-proof verification; the official pool executes in proof-mode none with SDK-compiled proof facts.",
      "Direct private remediation amount reconciliation against the committed claim is a Phase 4 SettlementMatch requirement and is not claimed here.",
    ],
  };
  await writeFile(
    resolve(root, "evidence/phase3-private-exceptions-devnet.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
    { mode: 0o600 },
  );
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}
