import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Account,
  RpcProvider,
  constants,
  num,
  uint256,
  validateAndParseAddress,
} from "starknet";
import {
  assertFreshPayoWageClaimDeployArtifacts,
  readAllPayoWageClaimDeployArtifacts,
  repositoryRoot,
} from "./lib/payo-contract-artifacts.mjs";
import {
  WAGE_CLAIM_PROFILES,
  assertPayoWageClaimMainnetPlan,
  buildPayoWageClaimMainnetPlan,
  wageClaimDeploymentPayloads,
} from "./lib/payo-wage-claim-mainnet.mjs";

const DEFAULT_RPC_URL = "https://api.cartridge.gg/x/starknet/mainnet";
const STRK_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const DEFAULT_MUTATION_TIP = 1n;
const MAX_MUTATION_TIP = 1_000_000n;
const LIVE_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-multitenant-mainnet-deployment.json",
);
const PLAN_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-wage-claim-mainnet-plan.json",
);
const EVIDENCE_PATH = resolve(
  repositoryRoot,
  "circuits/payroll_integrity/target/payo-wage-claim-mainnet-deployment.json",
);
const PUBLIC_EVIDENCE_PATH = resolve(
  repositoryRoot,
  "evidence/phase3-wage-claim-mainnet.json",
);
const PROOF_FIXTURE_DIRECTORY = resolve(
  repositoryRoot,
  "contracts/exception_vnext_integration/tests",
);
const CONTRACT_NAMES = Object.freeze([
  "snapshotVerifier",
  "claimVerifier",
  "remediationVerifier",
  "exceptionSeal",
]);
const ACTIONS = new Set([
  "plan",
  "status",
  "estimate",
  "declare",
  "deploy",
  "activate",
  "verify",
]);
const action = process.argv[2];
if (!ACTIONS.has(action)) {
  throw new Error(
    "Usage: node scripts/payo-wage-claim-mainnet.mjs "
      + "<plan|status|estimate|declare|deploy|activate|verify>",
  );
}

const provider = new RpcProvider({
  nodeUrl: process.env.STARKNET_RPC_URL
    ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL
    ?? DEFAULT_RPC_URL,
});

function normalizeError(error) {
  return error instanceof Error ? error.message : String(error);
}

function submissionError(error) {
  return {
    name: error?.name ?? "Error",
    code: error?.code ?? null,
    message: normalizeError(error),
    rpcError: error?.baseError ?? error?.response?.data?.error ?? null,
  };
}

function mutationTip() {
  const raw = process.env.PAYO_WAGE_CLAIM_MAINNET_TIP ?? DEFAULT_MUTATION_TIP.toString();
  if (!/^\d+$/.test(raw)) {
    throw new Error("PAYO_WAGE_CLAIM_MAINNET_TIP must be an unsigned integer.");
  }
  const tip = BigInt(raw);
  if (tip < 1n || tip > MAX_MUTATION_TIP) {
    throw new Error(
      `PAYO_WAGE_CLAIM_MAINNET_TIP must be between 1 and ${MAX_MUTATION_TIP}.`,
    );
  }
  return tip;
}

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

function sameHex(left, right) {
  return BigInt(left) === BigInt(right);
}

function isMissingClass(error) {
  return /class hash not found|undeclared class|class_hash_not_found/i
    .test(normalizeError(error));
}

function isMissingContract(error) {
  return /contract not found|contract_address_not_found|uninitialized contract/i
    .test(normalizeError(error));
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function readJsonIfExists(path, fallback) {
  try {
    return await readJson(path);
  } catch (error) {
    if (error?.code === "ENOENT") return fallback;
    throw error;
  }
}

async function saveJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function requireMainnet() {
  const chainId = await provider.getChainId();
  if (BigInt(chainId) !== BigInt(constants.StarknetChainId.SN_MAIN)) {
    throw new Error(`Refusing wage-claim deployment: RPC reports non-Mainnet chain ${chainId}.`);
  }
  return num.toHex(BigInt(chainId));
}

async function classDeclared(classHash) {
  try {
    await provider.getClass(classHash, "latest");
    return true;
  } catch (error) {
    if (isMissingClass(error)) return false;
    throw error;
  }
}

async function deployedClassHash(address, blockIdentifier = "latest") {
  try {
    return num.toHex(BigInt(await provider.getClassHashAt(address, blockIdentifier)));
  } catch (error) {
    if (isMissingContract(error)) return null;
    throw error;
  }
}

async function readBalance(address) {
  const result = await provider.callContract({
    contractAddress: STRK_ADDRESS,
    entrypoint: "balance_of",
    calldata: [address],
  }, "latest");
  return uint256.uint256ToBN({ low: result[0], high: result[1] });
}

function accountFromEnvironment(expectedAddress) {
  const address = canonicalAddress(
    process.env.PAYO_PROOF_RELAYER_ADDRESS,
    "PAYO_PROOF_RELAYER_ADDRESS",
  );
  if (!sameHex(address, expectedAddress)) {
    throw new Error("The configured deployment account does not match the reviewed plan.");
  }
  const privateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]+$/.test(privateKey)) {
    throw new Error("PAYO_PROOF_RELAYER_PRIVATE_KEY is required for simulation or mutation.");
  }
  return new Account({ provider, address, signer: privateKey, cairoVersion: "1" });
}

async function waitFor(transactionHash) {
  return provider.waitForTransaction(transactionHash, {
    retries: 400,
    retryInterval: 3_000,
  });
}

async function waitForPostcondition(transactionHash, label, postcondition) {
  try {
    return {
      receipt: await waitFor(transactionHash),
      recoveredFromWaitError: false,
    };
  } catch (waitError) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      if (await postcondition()) {
        try {
          return {
            receipt: await provider.getTransactionReceipt(transactionHash),
            recoveredFromWaitError: true,
          };
        } catch {
          // The deterministic state is visible before the receipt on some RPC nodes.
        }
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 3_000));
    }
    throw new Error(
      `${label} did not reach its on-chain postcondition after the RPC wait failed: `
        + normalizeError(waitError),
    );
  }
}

function actualFee(receipt) {
  return BigInt(receipt.actual_fee?.amount ?? 0).toString();
}

async function loadContext() {
  await assertFreshPayoWageClaimDeployArtifacts();
  const [liveEvidence, artifacts] = await Promise.all([
    readJson(LIVE_EVIDENCE_PATH),
    readAllPayoWageClaimDeployArtifacts(),
  ]);
  if (!liveEvidence.plan || liveEvidence.verification?.passed !== true) {
    throw new Error("The tenant-aware Mainnet topology lacks passing read-back evidence.");
  }
  return {
    livePlan: liveEvidence.plan,
    liveVerification: liveEvidence.verification,
    artifacts,
  };
}

async function loadReviewedPlan(context) {
  const plan = await readJson(PLAN_PATH);
  assertPayoWageClaimMainnetPlan(plan, context);
  return plan;
}

async function assertLiveDependencies(plan, blockIdentifier = "latest") {
  const chainId = await requireMainnet();
  if (!sameHex(chainId, plan.chainId)) {
    throw new Error("The reviewed wage-claim plan is bound to another chain.");
  }
  const checks = [];
  for (const name of ["policyRegistry", "obligationRegistry"]) {
    const expected = plan.liveTopology[name];
    const actual = await deployedClassHash(expected.address, blockIdentifier);
    checks.push({
      name,
      expectedClassHash: expected.classHash,
      actualClassHash: actual,
      passed: actual !== null && sameHex(actual, expected.classHash),
    });
  }
  const adminResult = await provider.callContract({
    contractAddress: plan.liveTopology.policyRegistry.address,
    entrypoint: "get_admin",
    calldata: [],
  }, blockIdentifier);
  checks.push({
    name: "policyAdmin",
    expectedAddress: plan.deployerAddress,
    actualAddress: num.toHex(BigInt(adminResult[0] ?? 0)),
    passed: sameHex(adminResult[0] ?? 0, plan.deployerAddress),
  });
  if (!checks.every(({ passed }) => passed)) {
    throw new Error("A live Mainnet dependency failed class-hash or admin read-back.");
  }
  return checks;
}

async function readProfile(plan, profile, blockIdentifier = "latest") {
  const policy = plan.liveTopology.policyRegistry.address;
  const activeResult = await provider.callContract({
    contractAddress: policy,
    entrypoint: "is_verifier_valid",
    calldata: [profile.mode.toString(), profile.proofVersion.toString()],
  }, blockIdentifier);
  const active = BigInt(activeResult[0] ?? 0) !== 0n;
  let address = null;
  if (active) {
    const result = await provider.callContract({
      contractAddress: policy,
      entrypoint: "get_verifier",
      calldata: [profile.mode.toString(), profile.proofVersion.toString()],
    }, blockIdentifier);
    address = num.toHex(BigInt(result[0]));
    if (!sameHex(address, profile.address)) {
      throw new Error(
        `Active verifier ${profile.mode}/${profile.proofVersion} points to an unexpected address.`,
      );
    }
  }
  return { ...profile, active, address };
}

async function liveStatus(plan) {
  const blockNumber = await provider.getBlockNumber();
  const declarations = {};
  const contracts = {};
  for (const name of CONTRACT_NAMES) {
    declarations[name] = await classDeclared(plan.contracts[name].classHash);
    const actualClassHash = await deployedClassHash(plan.contracts[name].address, blockNumber);
    if (actualClassHash && !sameHex(actualClassHash, plan.contracts[name].classHash)) {
      throw new Error(`${name} predicted address contains an unexpected Mainnet class.`);
    }
    contracts[name] = {
      address: plan.contracts[name].address,
      expectedClassHash: plan.contracts[name].classHash,
      actualClassHash,
      deployed: actualClassHash !== null,
    };
  }
  const profiles = [];
  for (const profile of plan.verifierProfiles) {
    profiles.push(await readProfile(plan, profile, blockNumber));
  }
  return {
    observedAt: new Date().toISOString(),
    blockNumber,
    declarations,
    contracts,
    profiles,
  };
}

async function updateEvidence(plan, change) {
  const current = await readJsonIfExists(EVIDENCE_PATH, {
    schemaVersion: 1,
    network: "starknet-mainnet",
    plan,
    declarations: {},
  });
  const next = { ...(await change(current)), updatedAt: new Date().toISOString() };
  await Promise.all([
    saveJson(EVIDENCE_PATH, next),
    saveJson(PUBLIC_EVIDENCE_PATH, {
      ...next,
      plan: {
        ...next.plan,
        source: "circuits/payroll_integrity/target/payo-wage-claim-mainnet-plan.json",
      },
    }),
  ]);
}

function activationCalls(plan, validAfter, expiresAt) {
  return plan.verifierProfiles.map((profile) => ({
    contractAddress: plan.liveTopology.policyRegistry.address,
    entrypoint: "schedule_verifier",
    calldata: [
      profile.mode.toString(),
      profile.proofVersion.toString(),
      profile.address,
      validAfter.toString(),
      expiresAt.toString(),
    ],
  }));
}

async function activationWindow() {
  const block = await provider.getBlock("latest");
  const validAfter = Number(block.timestamp);
  return {
    blockNumber: block.block_number,
    validAfter,
    expiresAt: validAfter + 365 * 24 * 60 * 60,
  };
}

async function estimateAll(plan, context, account) {
  const status = await liveStatus(plan);
  const tip = mutationTip();
  const estimates = [];
  for (const name of CONTRACT_NAMES) {
    if (!status.declarations[name]) {
      const fee = await account.estimateDeclareFee({
        contract: context.artifacts[name].sierra,
        casm: context.artifacts[name].casm,
      }, { tip });
      estimates.push({
        label: `declare.${name}`,
        feeFri: fee.overall_fee.toString(),
        feeStrk: Number(fee.overall_fee) / 1e18,
      });
    }
  }
  const pendingDeployments = wageClaimDeploymentPayloads(plan)
    .filter(({ name }) => !status.contracts[name].deployed);
  for (const item of pendingDeployments) {
    let fee;
    if (status.declarations[item.name]) {
      fee = await account.estimateDeployFee(item.payload);
    } else {
      const pair = await account.estimateFeeBulk([
        {
          type: "DECLARE",
          payload: {
            contract: context.artifacts[item.name].sierra,
            casm: context.artifacts[item.name].casm,
          },
        },
        { type: "DEPLOY", payload: item.payload },
      ], { tip });
      fee = pair[1];
    }
    estimates.push({
      label: `deploy.${item.name}`,
      feeFri: fee.overall_fee.toString(),
      feeStrk: Number(fee.overall_fee) / 1e18,
    });
  }
  const inactiveProfiles = status.profiles.filter(({ active }) => !active);
  let window = null;
  if (inactiveProfiles.length > 0) {
    window = await activationWindow();
    const fee = await account.estimateInvokeFee(
      activationCalls(plan, window.validAfter, window.expiresAt),
      { tip },
    );
    estimates.push({
      label: "activate",
      feeFri: fee.overall_fee.toString(),
      feeStrk: Number(fee.overall_fee) / 1e18,
    });
  }
  const total = estimates.reduce((sum, estimate) => sum + BigInt(estimate.feeFri), 0n);
  const balance = await readBalance(plan.deployerAddress);
  return {
    observedAt: new Date().toISOString(),
    status,
    pendingDeployments: pendingDeployments.map(({ name }) => name),
    inactiveProfiles: inactiveProfiles.map(({ mode, proofVersion }) => ({ mode, proofVersion })),
    activationWindow: window,
    estimates,
    totalFeeFri: total.toString(),
    totalFeeStrk: Number(total) / 1e18,
    balanceFri: balance.toString(),
    balanceStrk: Number(balance) / 1e18,
    currentlyFunded: balance >= total,
    mutationTip: tip.toString(),
  };
}

async function verifyProofFixture(plan, profile) {
  const fixtureNames = {
    snapshotVerifier: "obligation_snapshot_v5.txt",
    claimVerifier: "wage_claim_v6.txt",
    remediationVerifier: "wage_remediation_v7.txt",
  };
  const proof = (await readFile(
    resolve(PROOF_FIXTURE_DIRECTORY, fixtureNames[profile.name]),
    "utf8",
  )).trim().split(/\s+/);
  if (proof.length === 0 || proof.some((felt) => !/^0x[0-9a-fA-F]+$/.test(felt))) {
    throw new Error(`${profile.name} proof fixture is malformed.`);
  }
  const result = await provider.callContract({
    contractAddress: plan.contracts[profile.name].address,
    entrypoint: "verify_ultra_keccak_zk_honk_proof",
    calldata: [proof.length.toString(), ...proof],
  }, "latest");
  if (result[0] !== "0x0" || BigInt(result[1] ?? 0) !== 23n || result.length !== 48) {
    throw new Error(`${profile.name} rejected its valid proof fixture.`);
  }
  const tampered = [...proof];
  tampered[2] = num.toHex(BigInt(tampered[2]) ^ 1n);
  let tamperRejected = false;
  try {
    const tamperedResult = await provider.callContract({
      contractAddress: plan.contracts[profile.name].address,
      entrypoint: "verify_ultra_keccak_zk_honk_proof",
      calldata: [tampered.length.toString(), ...tampered],
    }, "latest");
    tamperRejected = tamperedResult[0] !== "0x0";
  } catch {
    tamperRejected = true;
  }
  if (!tamperRejected) {
    throw new Error(`${profile.name} accepted tampered proof calldata.`);
  }
  return { name: profile.name, calldataFelts: proof.length, tamperRejected };
}

const context = await loadContext();
await requireMainnet();

if (action === "plan") {
  const plan = buildPayoWageClaimMainnetPlan(context);
  assertPayoWageClaimMainnetPlan(plan, context);
  await assertLiveDependencies(plan);
  await saveJson(PLAN_PATH, plan);
  process.stdout.write(`${JSON.stringify({ planPath: PLAN_PATH, plan }, null, 2)}\n`);
  process.exit(0);
}

const plan = await loadReviewedPlan(context);
await assertLiveDependencies(plan);

if (action === "status") {
  const [status, balance] = await Promise.all([
    liveStatus(plan),
    readBalance(plan.deployerAddress),
  ]);
  process.stdout.write(`${JSON.stringify({
    planPath: PLAN_PATH,
    balanceFri: balance.toString(),
    balanceStrk: Number(balance) / 1e18,
    status,
  }, null, 2)}\n`);
  process.exit(0);
}

const account = accountFromEnvironment(plan.deployerAddress);

if (action === "estimate") {
  process.stdout.write(`${JSON.stringify(
    await estimateAll(plan, context, account),
    null,
    2,
  )}\n`);
  process.exit(0);
}

if (action === "declare") {
  if (process.env.PAYO_WAGE_CLAIM_MAINNET_CONFIRM !== "DECLARE_PAYO_WAGE_CLAIM_MAINNET") {
    throw new Error(
      "Refusing declarations without "
        + "PAYO_WAGE_CLAIM_MAINNET_CONFIRM=DECLARE_PAYO_WAGE_CLAIM_MAINNET.",
    );
  }
  const tip = mutationTip();
  for (const name of CONTRACT_NAMES) {
    const contract = plan.contracts[name];
    if (await classDeclared(contract.classHash)) continue;
    const payload = {
      contract: context.artifacts[name].sierra,
      casm: context.artifacts[name].casm,
    };
    const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
    const fee = await account.estimateDeclareFee(payload, {
      nonce,
      skipValidate: false,
      tip,
    });
    const balance = await readBalance(plan.deployerAddress);
    if (balance < BigInt(fee.overall_fee)) {
      throw new Error(`${name} declaration requires ${fee.overall_fee} FRI; balance is ${balance}.`);
    }
    let submitted;
    try {
      submitted = await account.declare(payload, {
        nonce,
        resourceBounds: fee.resourceBounds,
        tip,
      });
    } catch (error) {
      process.stderr.write(`${JSON.stringify({
        failed: `declare.${name}`,
        nonce: num.toHex(BigInt(nonce)),
        error: submissionError(error),
      }, null, 2)}\n`);
      throw new Error(`${name} declaration submission failed.`);
    }
    const confirmation = await waitForPostcondition(
      submitted.transaction_hash,
      `${name} declaration`,
      () => classDeclared(contract.classHash),
    );
    if (!(await classDeclared(contract.classHash))) {
      throw new Error(`${name} declaration failed class-hash read-back.`);
    }
    const { receipt } = confirmation;
    const declaration = {
      transactionHash: submitted.transaction_hash,
      classHash: contract.classHash,
      nonce: num.toHex(BigInt(nonce)),
      tip: tip.toString(),
      recoveredFromWaitError: confirmation.recoveredFromWaitError,
      simulatedFeeFri: fee.overall_fee.toString(),
      actualFeeFri: actualFee(receipt),
      blockNumber: receipt.block_number,
    };
    await updateEvidence(plan, async (evidence) => ({
      ...evidence,
      declarations: { ...evidence.declarations, [name]: declaration },
    }));
    process.stdout.write(`${JSON.stringify({ declared: name, ...declaration })}\n`);
  }
  process.exit(0);
}

if (action === "deploy") {
  for (const name of CONTRACT_NAMES) {
    if (!(await classDeclared(plan.contracts[name].classHash))) {
      throw new Error(`Declare ${name} before deployment.`);
    }
  }
  const status = await liveStatus(plan);
  const pending = wageClaimDeploymentPayloads(plan)
    .filter(({ name }) => !status.contracts[name].deployed);
  if (pending.length === 0) {
    process.stdout.write(`${JSON.stringify({ alreadyDeployed: true })}\n`);
    process.exit(0);
  }
  const tip = mutationTip();
  const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
  const payloads = pending.map(({ payload }) => payload);
  const fee = await account.estimateDeployFee(payloads, {
    nonce,
    skipValidate: false,
    tip,
  });
  const balance = await readBalance(plan.deployerAddress);
  if (balance < BigInt(fee.overall_fee)) {
    throw new Error(`Deployment requires ${fee.overall_fee} FRI; balance is ${balance}.`);
  }
  if (process.env.PAYO_WAGE_CLAIM_MAINNET_CONFIRM !== "DEPLOY_PAYO_WAGE_CLAIM_MAINNET") {
    throw new Error(
      "Refusing deployment without "
        + "PAYO_WAGE_CLAIM_MAINNET_CONFIRM=DEPLOY_PAYO_WAGE_CLAIM_MAINNET.",
    );
  }
  const submitted = await account.deploy(payloads, {
    nonce,
    resourceBounds: fee.resourceBounds,
    tip,
  });
  const confirmation = await waitForPostcondition(
    submitted.transaction_hash,
    "vNext contract deployment",
    async () => {
      for (const item of pending) {
        const actual = await deployedClassHash(item.address);
        if (!actual || !sameHex(actual, plan.contracts[item.name].classHash)) return false;
      }
      return true;
    },
  );
  for (const item of pending) {
    const actual = await deployedClassHash(item.address);
    if (!actual || !sameHex(actual, plan.contracts[item.name].classHash)) {
      throw new Error(`${item.name} failed post-deployment class-hash verification.`);
    }
  }
  const { receipt } = confirmation;
  const deployment = {
    names: pending.map(({ name }) => name),
    transactionHash: submitted.transaction_hash,
    nonce: num.toHex(BigInt(nonce)),
    tip: tip.toString(),
    recoveredFromWaitError: confirmation.recoveredFromWaitError,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: actualFee(receipt),
    blockNumber: receipt.block_number,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, deployment }));
  process.stdout.write(`${JSON.stringify(deployment, null, 2)}\n`);
  process.exit(0);
}

if (action === "activate") {
  const status = await liveStatus(plan);
  if (!Object.values(status.contracts).every(({ deployed }) => deployed)) {
    throw new Error("Deploy every vNext contract before registry activation.");
  }
  const inactive = status.profiles.filter(({ active }) => !active);
  if (inactive.length === 0) {
    process.stdout.write(`${JSON.stringify({ alreadyActive: true })}\n`);
    process.exit(0);
  }
  const window = await activationWindow();
  const calls = activationCalls(plan, window.validAfter, window.expiresAt);
  const tip = mutationTip();
  const nonce = await provider.getNonceForAddress(plan.deployerAddress, "pre_confirmed");
  const fee = await account.estimateInvokeFee(calls, {
    nonce,
    skipValidate: false,
    tip,
  });
  const balance = await readBalance(plan.deployerAddress);
  if (balance < BigInt(fee.overall_fee)) {
    throw new Error(`Activation requires ${fee.overall_fee} FRI; balance is ${balance}.`);
  }
  if (process.env.PAYO_WAGE_CLAIM_MAINNET_CONFIRM !== "ACTIVATE_PAYO_WAGE_CLAIM_MAINNET") {
    throw new Error(
      "Refusing activation without "
        + "PAYO_WAGE_CLAIM_MAINNET_CONFIRM=ACTIVATE_PAYO_WAGE_CLAIM_MAINNET.",
    );
  }
  const submitted = await account.execute(calls, {
    nonce,
    resourceBounds: fee.resourceBounds,
    tip,
  });
  const confirmation = await waitForPostcondition(
    submitted.transaction_hash,
    "verifier-profile activation",
    async () => {
      const profiles = [];
      for (const profile of plan.verifierProfiles) {
        profiles.push(await readProfile(plan, profile));
      }
      return profiles.every(({ active }) => active);
    },
  );
  const activated = await liveStatus(plan);
  if (!activated.profiles.every(({ active }) => active)) {
    throw new Error("A vNext verifier profile failed activation read-back.");
  }
  const { receipt } = confirmation;
  const activation = {
    transactionHash: submitted.transaction_hash,
    nonce: num.toHex(BigInt(nonce)),
    tip: tip.toString(),
    recoveredFromWaitError: confirmation.recoveredFromWaitError,
    simulatedFeeFri: fee.overall_fee.toString(),
    actualFeeFri: actualFee(receipt),
    blockNumber: receipt.block_number,
    validAfter: window.validAfter,
    expiresAt: window.expiresAt,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, activation }));
  process.stdout.write(`${JSON.stringify(activation, null, 2)}\n`);
  process.exit(0);
}

if (action === "verify") {
  const blockNumber = await provider.getBlockNumber();
  const [dependencies, status] = await Promise.all([
    assertLiveDependencies(plan, blockNumber),
    liveStatus(plan),
  ]);
  if (
    !Object.values(status.declarations).every(Boolean)
    || !Object.values(status.contracts).every(({ deployed }) => deployed)
    || !status.profiles.every(({ active }) => active)
  ) {
    throw new Error("The vNext Mainnet topology is not fully declared, deployed and active.");
  }
  const priorPayrollProfile = await provider.callContract({
    contractAddress: plan.liveTopology.policyRegistry.address,
    entrypoint: "is_verifier_valid",
    calldata: ["0", "2"],
  }, blockNumber);
  if (BigInt(priorPayrollProfile[0] ?? 0) === 0n) {
    throw new Error("The existing PayrollIntegrity v2 verifier is no longer active.");
  }
  const proofChecks = [];
  for (const profile of WAGE_CLAIM_PROFILES) {
    proofChecks.push(await verifyProofFixture(plan, profile));
  }
  const verification = {
    passed: true,
    observedAt: new Date().toISOString(),
    blockNumber,
    dependencies,
    status,
    priorPayrollV2Active: true,
    proofChecks,
  };
  await updateEvidence(plan, async (evidence) => ({ ...evidence, verification }));
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
  process.exit(0);
}
