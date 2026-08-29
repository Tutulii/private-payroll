import { hash, num } from "starknet";

export const WAGE_CLAIM_SALTS = Object.freeze({
  snapshotVerifier: "0x7061796f2d766e6578742d736e617073686f742d7635",
  claimVerifier: "0x7061796f2d766e6578742d636c61696d2d7636",
  remediationVerifier: "0x7061796f2d766e6578742d72656d6564696174696f6e2d7637",
  exceptionSeal: "0x7061796f2d766e6578742d657863657074696f6e2d7365616c",
});

export const WAGE_CLAIM_PROFILES = Object.freeze([
  Object.freeze({ name: "snapshotVerifier", mode: 0, proofVersion: 5 }),
  Object.freeze({ name: "claimVerifier", mode: 2, proofVersion: 6 }),
  Object.freeze({ name: "remediationVerifier", mode: 3, proofVersion: 7 }),
]);

function canonicalHex(value) {
  return num.toHex(BigInt(value));
}

function sameHex(left, right) {
  return BigInt(left) === BigInt(right);
}

function predictedAddress(classHash, constructorCalldata, salt) {
  return canonicalHex(hash.calculateContractAddressFromHash(
    salt,
    classHash,
    constructorCalldata,
    0,
  ));
}

function artifactIdentity(artifact) {
  return {
    classHash: artifact.classHash,
    compiledClassHash: artifact.compiledClassHash,
    sierraSha256: artifact.sierraSha256,
    casmSha256: artifact.casmSha256,
  };
}

export function buildPayoWageClaimMainnetPlan({
  livePlan,
  liveVerification,
  artifacts,
  generatedAt = new Date().toISOString(),
}) {
  if (
    livePlan?.network !== "starknet-mainnet"
    || liveVerification?.passed !== true
    || !livePlan.poolAddress
    || !livePlan.deployerAddress
    || !livePlan.contracts?.policyRegistry?.address
    || !livePlan.contracts?.obligationRegistry?.address
  ) {
    throw new Error("The verified tenant-aware Mainnet topology is required.");
  }
  for (const name of Object.keys(WAGE_CLAIM_SALTS)) {
    if (!artifacts[name]?.classHash || !artifacts[name]?.compiledClassHash) {
      throw new Error(`Missing reviewed ${name} deployment artifact.`);
    }
  }

  const contracts = {};
  for (const name of ["snapshotVerifier", "claimVerifier", "remediationVerifier"]) {
    const constructorCalldata = [];
    contracts[name] = {
      address: predictedAddress(
        artifacts[name].classHash,
        constructorCalldata,
        WAGE_CLAIM_SALTS[name],
      ),
      salt: WAGE_CLAIM_SALTS[name],
      constructorCalldata,
      ...artifactIdentity(artifacts[name]),
    };
  }
  const sealConstructor = [
    canonicalHex(livePlan.poolAddress),
    canonicalHex(livePlan.contracts.policyRegistry.address),
    canonicalHex(livePlan.contracts.obligationRegistry.address),
    canonicalHex(livePlan.chainId),
  ];
  contracts.exceptionSeal = {
    address: predictedAddress(
      artifacts.exceptionSeal.classHash,
      sealConstructor,
      WAGE_CLAIM_SALTS.exceptionSeal,
    ),
    salt: WAGE_CLAIM_SALTS.exceptionSeal,
    constructorCalldata: sealConstructor,
    ...artifactIdentity(artifacts.exceptionSeal),
  };

  return {
    schemaVersion: 1,
    generatedAt,
    network: "starknet-mainnet",
    chainId: canonicalHex(livePlan.chainId),
    poolAddress: canonicalHex(livePlan.poolAddress),
    deployerAddress: canonicalHex(livePlan.deployerAddress),
    liveTopology: {
      policyRegistry: { ...livePlan.contracts.policyRegistry },
      obligationRegistry: { ...livePlan.contracts.obligationRegistry },
      previousPayrollSeal: { ...livePlan.contracts.payrollSeal },
    },
    contracts,
    verifierProfiles: WAGE_CLAIM_PROFILES.map(({ name, mode, proofVersion }) => ({
      mode,
      proofVersion,
      address: contracts[name].address,
    })),
  };
}

export function assertPayoWageClaimMainnetPlan(plan, context) {
  const rebuilt = buildPayoWageClaimMainnetPlan({
    ...context,
    generatedAt: plan.generatedAt,
  });
  if (JSON.stringify(rebuilt) !== JSON.stringify(plan)) {
    throw new Error("The reviewed wage-claim Mainnet plan is stale or was modified.");
  }
  const addresses = Object.values(plan.contracts).map(({ address }) => canonicalHex(address));
  if (new Set(addresses).size !== addresses.length) {
    throw new Error("The wage-claim Mainnet plan contains an address collision.");
  }
  if (addresses.some((address) => sameHex(address, plan.liveTopology.previousPayrollSeal.address))) {
    throw new Error("The vNext topology must not overwrite the active payroll seal.");
  }
}

export function wageClaimDeploymentPayloads(plan) {
  return ["snapshotVerifier", "claimVerifier", "remediationVerifier", "exceptionSeal"]
    .map((name) => ({
      name,
      address: plan.contracts[name].address,
      payload: {
        classHash: plan.contracts[name].classHash,
        constructorCalldata: plan.contracts[name].constructorCalldata,
        salt: plan.contracts[name].salt,
        unique: false,
      },
    }));
}
