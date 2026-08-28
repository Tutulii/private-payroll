import { hash, num } from "starknet";

export const PAYO_PHASE3_V2_VERIFIER_SALT =
  "0x7061796f2d76322d6d65726765642d76657269666965722d7631";
export const PAYO_PHASE3_V2_BUNDLE_SALT =
  "0x7061796f2d76322d6d65726765642d62756e646c652d7631";

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

export function buildPayoPhase3V2UpgradePlan({
  livePlan,
  liveVerification,
  advancedVerifierArtifact,
  integrityBundleArtifact,
  generatedAt = new Date().toISOString(),
}) {
  if (
    livePlan?.network !== "starknet-mainnet"
    || liveVerification?.passed !== true
    || !livePlan.contracts?.policyRegistry?.address
    || !livePlan.contracts?.obligationRegistry?.address
    || !livePlan.contracts?.payrollSeal?.address
  ) {
    throw new Error("The verified tenant-aware Mainnet topology is required.");
  }
  const existingV2 = livePlan.verifierProfiles?.find((profile) =>
    profile.mode === 0 && profile.proofVersion === 2);
  const claim = livePlan.verifierProfiles?.find((profile) =>
    profile.mode === 2 && profile.proofVersion === 3);
  const remediation = livePlan.verifierProfiles?.find((profile) =>
    profile.mode === 3 && profile.proofVersion === 4);
  if (!existingV2?.address || !claim?.address || !remediation?.address) {
    throw new Error("The live topology is missing a required Phase 3 verifier profile.");
  }

  const verifierAddress = predictedAddress(
    advancedVerifierArtifact.classHash,
    [],
    PAYO_PHASE3_V2_VERIFIER_SALT,
  );
  const bundleAddress = predictedAddress(
    integrityBundleArtifact.classHash,
    [verifierAddress],
    PAYO_PHASE3_V2_BUNDLE_SALT,
  );

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
      payrollSeal: { ...livePlan.contracts.payrollSeal },
      previousAdvancedBundle: canonicalHex(existingV2.address),
      claimBundle: canonicalHex(claim.address),
      remediationBundle: canonicalHex(remediation.address),
    },
    circuit: {
      proofVersion: 2,
      circuitSha256: "0x755bb9374c9cfc72cbd36b1a3e1d8c5e2792b11b8b08e190d2743dc508ebbe41",
      verificationKeySha256: "0x50063de39c922bf1fe1089ff8b5e6839a56387da99e82e9071f067b9f72c90d7",
      maximumProofCalldataFelts: 4992,
      measuredProofCalldataFelts: 3223,
    },
    contracts: {
      advancedVerifier: {
        address: verifierAddress,
        salt: PAYO_PHASE3_V2_VERIFIER_SALT,
        constructorCalldata: [],
        ...artifactIdentity(advancedVerifierArtifact),
      },
      advancedBundle: {
        address: bundleAddress,
        salt: PAYO_PHASE3_V2_BUNDLE_SALT,
        constructorCalldata: [verifierAddress],
        ...artifactIdentity(integrityBundleArtifact),
      },
    },
  };
}

export function assertPayoPhase3V2UpgradePlan(plan, {
  livePlan,
  liveVerification,
  advancedVerifierArtifact,
  integrityBundleArtifact,
}) {
  const rebuilt = buildPayoPhase3V2UpgradePlan({
    livePlan,
    liveVerification,
    advancedVerifierArtifact,
    integrityBundleArtifact,
    generatedAt: plan.generatedAt,
  });
  if (JSON.stringify(rebuilt) !== JSON.stringify(plan)) {
    throw new Error("The reviewed v2 upgrade plan is stale or was modified.");
  }
  if (
    sameHex(plan.contracts.advancedVerifier.address, plan.liveTopology.previousAdvancedBundle)
    || sameHex(plan.contracts.advancedBundle.address, plan.liveTopology.previousAdvancedBundle)
  ) {
    throw new Error("The v2 upgrade must deploy a new verifier topology.");
  }
  if (plan.circuit.measuredProofCalldataFelts > plan.circuit.maximumProofCalldataFelts) {
    throw new Error("The reviewed v2 proof exceeds the Mainnet calldata budget.");
  }
}

export function v2UpgradeDeploymentPayloads(plan) {
  return ["advancedVerifier", "advancedBundle"].map((name) => {
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

export function assertV2UpgradeProofSummary(plan, summary) {
  if (
    summary?.circuitSha256 !== plan.circuit.circuitSha256
    || !Array.isArray(summary.shards)
    || summary.shards.length !== 2
  ) {
    throw new Error("The merged-v2 proof fixture does not match the reviewed circuit.");
  }
  const common = summary.shards[0]?.publicInputs;
  if (
    BigInt(common?.chainId ?? 0) !== BigInt(plan.chainId)
    || BigInt(common?.sealAddress ?? 0) !== BigInt(plan.liveTopology.payrollSeal.address)
    || BigInt(common?.proofVersion ?? 0) !== 2n
  ) {
    throw new Error("The merged-v2 proof fixture is not bound to the live tenant-aware Mainnet topology.");
  }
  for (const shardIndex of [0, 1]) {
    const shard = summary.shards[shardIndex];
    const publicInputs = shard?.publicInputs;
    if (
      shard?.shardIndex !== shardIndex
      || shard?.proofCalldataFelts !== plan.circuit.measuredProofCalldataFelts
      || shard?.resultingInvokeCalldataFelts > 5_000
      || BigInt(publicInputs?.chainId ?? 0) !== BigInt(plan.chainId)
      || BigInt(publicInputs?.sealAddress ?? 0) !== BigInt(plan.liveTopology.payrollSeal.address)
      || BigInt(publicInputs?.proofVersion ?? 0) !== 2n
      || BigInt(publicInputs?.shardIndex ?? -1) !== BigInt(shardIndex)
    ) {
      throw new Error(`Merged v2 shard ${shardIndex} violates its reviewed deployment binding or calldata budget.`);
    }
    for (const name of Object.keys(common).filter((name) => name !== "shardIndex")) {
      if (BigInt(publicInputs[name]) !== BigInt(common[name])) {
        throw new Error(`Merged v2 shard ${shardIndex} disagrees on public input ${name}.`);
      }
    }
  }
}
