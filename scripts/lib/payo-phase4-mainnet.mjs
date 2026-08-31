import { hash, num } from "starknet";

export const PAYO_PHASE4_SETTLEMENT_VERIFIER_SALT =
  "0x7061796f2d7068617365342d736574746c656d656e742d7638";
export const PAYO_PHASE4_PAYROLL_SEAL_SALT =
  "0x7061796f2d7068617365342d706179726f6c6c2d7365616c";
export const PAYO_PHASE4_POLICY_ACCOUNT_SALT =
  "0x7061796f2d7068617365342d706f6c6963792d6163636f756e74";

const SETTLEMENT_FIXTURE = Object.freeze({
  proofVersion: 8,
  circuitSha256: "0xa208f7c548a5205e9e777f4926e282510e918bee4ce7902db3bb8b2d46454033",
  verificationKeySha256: "0x4dba54029e3b3b507baad28f6f4f416b9eca9651f98cbad9312d91a637528e23",
  publicInputCount: 11,
  measuredProofCalldataFelts: 3247,
  maximumProofCalldataFelts: 4992,
});

function canonical(value) {
  return num.toHex(BigInt(value));
}

function predictedAddress(classHash, constructorCalldata, salt) {
  return canonical(hash.calculateContractAddressFromHash(
    salt,
    classHash,
    constructorCalldata,
    0,
  ));
}

function artifactIdentity(artifact) {
  return {
    classHash: canonical(artifact.classHash),
    compiledClassHash: canonical(artifact.compiledClassHash),
    sierraSha256: artifact.sierraSha256,
    casmSha256: artifact.casmSha256,
  };
}

export function buildPayoPhase4MainnetPlan({
  livePlan,
  liveVerification,
  artifacts,
  policyOwnerPublicKey,
  generatedAt = new Date().toISOString(),
}) {
  const poolCheck = liveVerification?.checks?.find(
    ({ code, passed }) => code === "pool.deployed" && passed === true,
  );
  if (
    livePlan?.network !== "starknet-mainnet"
    || liveVerification?.passed !== true
    || !poolCheck?.classHash
    || !livePlan.contracts?.policyRegistry?.address
    || !livePlan.contracts?.obligationRegistry?.address
    || !livePlan.contracts?.payrollSeal?.address
    || !livePlan.poolAddress
    || !livePlan.deployerAddress
  ) {
    throw new Error("The verified tenant-aware Phase 3 Mainnet topology is required.");
  }
  for (const name of ["settlementVerifier", "payrollSeal", "policyAccount"]) {
    if (!artifacts?.[name]?.classHash || !artifacts[name].compiledClassHash) {
      throw new Error(`The ${name} deploy artifact is missing.`);
    }
  }
  const ownerPublicKey = canonical(policyOwnerPublicKey);
  if (BigInt(ownerPublicKey) === 0n) {
    throw new Error("The policy-account owner public key must be non-zero.");
  }

  const dependencies = {
    pool: {
      address: canonical(livePlan.poolAddress),
      classHash: canonical(poolCheck.classHash),
    },
    policyRegistry: {
      address: canonical(livePlan.contracts.policyRegistry.address),
      classHash: canonical(livePlan.contracts.policyRegistry.classHash),
    },
    obligationRegistry: {
      address: canonical(livePlan.contracts.obligationRegistry.address),
      classHash: canonical(livePlan.contracts.obligationRegistry.classHash),
    },
    previousPayrollSeal: {
      address: canonical(livePlan.contracts.payrollSeal.address),
      classHash: canonical(livePlan.contracts.payrollSeal.classHash),
    },
  };
  const settlementVerifier = {
    salt: PAYO_PHASE4_SETTLEMENT_VERIFIER_SALT,
    constructorCalldata: [],
    ...artifactIdentity(artifacts.settlementVerifier),
  };
  settlementVerifier.address = predictedAddress(
    settlementVerifier.classHash,
    settlementVerifier.constructorCalldata,
    settlementVerifier.salt,
  );
  const payrollSeal = {
    salt: PAYO_PHASE4_PAYROLL_SEAL_SALT,
    constructorCalldata: [
      dependencies.pool.address,
      dependencies.policyRegistry.address,
      dependencies.obligationRegistry.address,
      canonical(livePlan.chainId),
    ],
    ...artifactIdentity(artifacts.payrollSeal),
  };
  payrollSeal.address = predictedAddress(
    payrollSeal.classHash,
    payrollSeal.constructorCalldata,
    payrollSeal.salt,
  );
  const policyAccount = {
    salt: PAYO_PHASE4_POLICY_ACCOUNT_SALT,
    constructorCalldata: [ownerPublicKey],
    ownerPublicKey,
    ...artifactIdentity(artifacts.policyAccount),
  };
  policyAccount.address = predictedAddress(
    policyAccount.classHash,
    policyAccount.constructorCalldata,
    policyAccount.salt,
  );

  return {
    schemaVersion: 1,
    generatedAt,
    network: "starknet-mainnet",
    chainId: canonical(livePlan.chainId),
    deployerAddress: canonical(livePlan.deployerAddress),
    dependencies,
    settlementCircuit: { ...SETTLEMENT_FIXTURE },
    verifierProfile: {
      mode: 1,
      proofVersion: 8,
      validityDays: 365,
    },
    contracts: { settlementVerifier, payrollSeal, policyAccount },
  };
}

export function assertPayoPhase4MainnetPlan(plan, context) {
  const rebuilt = buildPayoPhase4MainnetPlan({
    ...context,
    generatedAt: plan.generatedAt,
  });
  if (JSON.stringify(rebuilt) !== JSON.stringify(plan)) {
    throw new Error("The reviewed Phase 4 Mainnet plan is stale or modified.");
  }
  if (
    BigInt(plan.contracts.payrollSeal.address)
      === BigInt(plan.dependencies.previousPayrollSeal.address)
  ) {
    throw new Error("Phase 4 must deploy the FINALIZE-capable Payroll Seal as a new contract.");
  }
  if (
    plan.settlementCircuit.proofVersion !== 8
    || plan.settlementCircuit.publicInputCount !== 11
    || plan.settlementCircuit.measuredProofCalldataFelts
      > plan.settlementCircuit.maximumProofCalldataFelts
  ) {
    throw new Error("The reviewed SettlementMatch v8 proof exceeds its protocol bounds.");
  }
}

export function phase4DeploymentPayloads(plan) {
  return ["settlementVerifier", "payrollSeal", "policyAccount"].map((name) => {
    const contract = plan.contracts[name];
    return {
      name,
      address: contract.address,
      payload: {
        classHash: contract.classHash,
        constructorCalldata: contract.constructorCalldata,
        salt: contract.salt,
        unique: false,
      },
    };
  });
}
