import { hash, num } from "starknet";

export const PAYO_VESTING_V3_VERIFIER_SALT =
  "0x7061796f2d76657374696e672d76332d76657269666965722d7631";
export const PAYO_VESTING_V3_BUNDLE_SALT =
  "0x7061796f2d76657374696e672d76332d62756e646c652d7631";
export const PAYO_VESTING_BOOK_SEAL_SALT =
  "0x7061796f2d76657374696e672d626f6f6b2d7365616c2d7631";

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
    classHash: canonicalHex(artifact.classHash),
    compiledClassHash: canonicalHex(artifact.compiledClassHash),
    sierraSha256: artifact.sierraSha256,
    casmSha256: artifact.casmSha256,
  };
}

export function buildPayoVestingBookMainnetPlan({
  livePlan,
  liveVerification,
  v2UpgradeEvidence,
  exceptionEvidence,
  vestingVerifierArtifact,
  vestingBundleArtifact,
  vestingBookSealArtifact,
  generatedAt = new Date().toISOString(),
}) {
  if (
    livePlan?.network !== "starknet-mainnet"
    || liveVerification?.passed !== true
    || !livePlan.contracts?.policyRegistry?.address
    || !livePlan.contracts?.obligationRegistry?.address
    || !livePlan.poolAddress
    || !livePlan.deployerAddress
  ) {
    throw new Error("The verified tenant-aware Mainnet topology is required.");
  }
  const activeV2Bundle = v2UpgradeEvidence?.activation?.activeBundle;
  if (
    v2UpgradeEvidence?.network !== "starknet-mainnet"
    || v2UpgradeEvidence?.verification?.passed !== true
    || !activeV2Bundle
    || !sameHex(v2UpgradeEvidence.plan?.chainId ?? 0, livePlan.chainId)
    || !sameHex(v2UpgradeEvidence.plan?.liveTopology?.policyRegistry?.address ?? 0,
      livePlan.contracts.policyRegistry.address)
  ) {
    throw new Error("The verified active PayrollIntegrity v2 upgrade is required.");
  }
  const exceptionSeal = exceptionEvidence?.plan?.contracts?.exceptionSeal;
  if (
    exceptionEvidence?.network !== "starknet-mainnet"
    || exceptionEvidence?.verification?.passed !== true
    || !exceptionSeal?.address
    || !exceptionSeal?.classHash
    || !sameHex(exceptionEvidence.plan?.chainId ?? 0, livePlan.chainId)
    || !sameHex(exceptionEvidence.plan?.liveTopology?.policyRegistry?.address ?? 0,
      livePlan.contracts.policyRegistry.address)
  ) {
    throw new Error("The verified live wage-exception seal is required.");
  }

  const chainId = canonicalHex(livePlan.chainId);
  const poolAddress = canonicalHex(livePlan.poolAddress);
  const deployerAddress = canonicalHex(livePlan.deployerAddress);
  const policyRegistryAddress = canonicalHex(livePlan.contracts.policyRegistry.address);
  const obligationRegistryAddress = canonicalHex(livePlan.contracts.obligationRegistry.address);
  const exceptionSealAddress = canonicalHex(exceptionSeal.address);
  const exceptionSealClassHash = canonicalHex(exceptionSeal.classHash);
  const verifierAddress = predictedAddress(
    vestingVerifierArtifact.classHash,
    [],
    PAYO_VESTING_V3_VERIFIER_SALT,
  );
  const bundleAddress = predictedAddress(
    vestingBundleArtifact.classHash,
    [verifierAddress],
    PAYO_VESTING_V3_BUNDLE_SALT,
  );
  const sealConstructor = [
    poolAddress,
    policyRegistryAddress,
    obligationRegistryAddress,
    exceptionSealAddress,
    chainId,
  ];
  const sealAddress = predictedAddress(
    vestingBookSealArtifact.classHash,
    sealConstructor,
    PAYO_VESTING_BOOK_SEAL_SALT,
  );

  return {
    schemaVersion: 1,
    generatedAt,
    network: "starknet-mainnet",
    chainId,
    deployerAddress,
    poolAddress,
    reusedTopology: {
      policyRegistry: {
        address: policyRegistryAddress,
        classHash: canonicalHex(livePlan.contracts.policyRegistry.classHash),
      },
      obligationRegistry: {
        address: obligationRegistryAddress,
        classHash: canonicalHex(livePlan.contracts.obligationRegistry.classHash),
      },
      exceptionSeal: {
        address: exceptionSealAddress,
        classHash: exceptionSealClassHash,
      },
      payrollV2Bundle: canonicalHex(activeV2Bundle),
    },
    circuit: {
      proofVersion: 3,
      schemaVersion: 1,
      publicInputCount: 58,
      circuitSha256: "0xbb1a8029e604de7b47a28f2ab7dc49f7a3859bc0c3c66b4bf502bdb1b943aec6",
      verificationKeySha256: "0xafad41c9d11ec920fe9cb091b04dc4ed092d2dfee561444a95b2af855ae80a20",
      measuredProofCalldataFelts: 3269,
      maximumProofCalldataFelts: 4992,
    },
    verifierProfile: {
      mode: 0,
      proofVersion: 3,
      address: bundleAddress,
    },
    contracts: {
      vestingVerifier: {
        address: verifierAddress,
        salt: PAYO_VESTING_V3_VERIFIER_SALT,
        constructorCalldata: [],
        ...artifactIdentity(vestingVerifierArtifact),
      },
      vestingBundle: {
        address: bundleAddress,
        salt: PAYO_VESTING_V3_BUNDLE_SALT,
        constructorCalldata: [verifierAddress],
        ...artifactIdentity(vestingBundleArtifact),
      },
      vestingBookSeal: {
        address: sealAddress,
        salt: PAYO_VESTING_BOOK_SEAL_SALT,
        constructorCalldata: sealConstructor,
        ...artifactIdentity(vestingBookSealArtifact),
      },
    },
  };
}

export function assertPayoVestingBookMainnetPlan(plan, context) {
  const rebuilt = buildPayoVestingBookMainnetPlan({
    ...context,
    generatedAt: plan.generatedAt,
  });
  if (JSON.stringify(rebuilt) !== JSON.stringify(plan)) {
    throw new Error("The reviewed VestingBook Mainnet plan is stale or modified.");
  }
  const addresses = Object.values(plan.contracts).map(({ address }) => canonicalHex(address));
  if (new Set(addresses).size !== addresses.length || addresses.some((address) => BigInt(address) === 0n)) {
    throw new Error("The VestingBook topology has a zero or colliding address.");
  }
  if (
    plan.circuit.measuredProofCalldataFelts > plan.circuit.maximumProofCalldataFelts
    || !sameHex(plan.verifierProfile.address, plan.contracts.vestingBundle.address)
    || plan.contracts.vestingBookSeal.constructorCalldata.length !== 5
    || !sameHex(plan.contracts.vestingBookSeal.constructorCalldata[3],
      plan.reusedTopology.exceptionSeal.address)
  ) {
    throw new Error("The VestingBook plan violates its proof or constructor bounds.");
  }
}

export function vestingBookDeploymentPayloads(plan) {
  return ["vestingVerifier", "vestingBundle", "vestingBookSeal"].map((name) => {
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
