import { constants, hash, num } from "starknet";

export const PAYO_PHASE3_MAINNET_POOL =
  "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a";
export const PAYO_PHASE3_MAINNET_CHAIN_ID = num.toHex(
  BigInt(constants.StarknetChainId.SN_MAIN),
);

export const phase3DeclarationOrder = Object.freeze([
  "advancedVerifier",
  "claimVerifier",
  "remediationVerifier",
  "advancedBundle",
  "payrollSeal",
]);

export const phase3VerifierDeploymentOrder = Object.freeze([
  "advancedVerifier",
  "claimVerifier",
  "remediationVerifier",
  "advancedBundle",
  "claimBundle",
  "remediationBundle",
]);

export const phase3DeploymentSalts = Object.freeze({
  advancedVerifier: "0x7061796f3302",
  claimVerifier: "0x7061796f3303",
  remediationVerifier: "0x7061796f3304",
  advancedBundle: "0x7061796f3305",
  claimBundle: "0x7061796f3306",
  remediationBundle: "0x7061796f3307",
  payrollSeal: "0x7061796f3310",
});

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

function requirePhase2Contract(phase2Plan, name) {
  const contract = phase2Plan.contracts?.[name];
  if (!contract?.address || !contract?.classHash) {
    throw new Error(`The verified Phase 2 plan is missing ${name}.`);
  }
  return contract;
}

export function buildPayoPhase3MainnetPlan({
  phase2Plan,
  artifacts,
  deployerAddress,
  generatedAt = new Date().toISOString(),
}) {
  if (!sameHex(phase2Plan.chainId, PAYO_PHASE3_MAINNET_CHAIN_ID)) {
    throw new Error("The reused Phase 2 topology is not bound to Starknet Mainnet.");
  }
  if (!sameHex(phase2Plan.poolAddress, PAYO_PHASE3_MAINNET_POOL)) {
    throw new Error("The reused Phase 2 topology is not bound to the canonical STRK20 pool.");
  }
  const baseVerifier = requirePhase2Contract(phase2Plan, "generatedVerifier");
  const integrityBundle = requirePhase2Contract(phase2Plan, "bundleVerifier");
  const policyRegistry = requirePhase2Contract(phase2Plan, "policyRegistry");
  const obligationRegistry = requirePhase2Contract(phase2Plan, "obligationRegistry");

  for (const name of [
    "baseVerifier",
    "advancedVerifier",
    "claimVerifier",
    "remediationVerifier",
    "advancedBundle",
    "integrityBundle",
    "policyRegistry",
    "obligationRegistry",
    "payrollSeal",
  ]) {
    if (!artifacts[name]) throw new Error(`Missing Phase 3 artifact ${name}.`);
  }
  for (const [phase2, phase3, label] of [
    [baseVerifier, artifacts.baseVerifier, "base verifier"],
    [integrityBundle, artifacts.integrityBundle, "integrity bundle"],
    [policyRegistry, artifacts.policyRegistry, "policy registry"],
    [obligationRegistry, artifacts.obligationRegistry, "obligation registry"],
  ]) {
    if (!sameHex(phase2.classHash, phase3.classHash)) {
      throw new Error(`The Phase 3 ${label} artifact does not match the deployed Phase 2 class.`);
    }
  }

  const contracts = {
    baseVerifier: {
      reuse: true,
      address: canonicalHex(baseVerifier.address),
      ...artifactIdentity(artifacts.baseVerifier),
    },
    policyRegistry: {
      reuse: true,
      address: canonicalHex(policyRegistry.address),
      ...artifactIdentity(artifacts.policyRegistry),
    },
    obligationRegistry: {
      reuse: true,
      address: canonicalHex(obligationRegistry.address),
      ...artifactIdentity(artifacts.obligationRegistry),
    },
  };

  function add(name, artifactName, constructorCalldata) {
    const artifact = artifacts[artifactName];
    const salt = phase3DeploymentSalts[name];
    const address = predictedAddress(artifact.classHash, constructorCalldata, salt);
    contracts[name] = {
      reuse: false,
      artifactName,
      address,
      salt,
      constructorCalldata,
      ...artifactIdentity(artifact),
    };
    return address;
  }

  const advancedVerifier = add("advancedVerifier", "advancedVerifier", []);
  const claimVerifier = add("claimVerifier", "claimVerifier", []);
  const remediationVerifier = add("remediationVerifier", "remediationVerifier", []);
  add("advancedBundle", "advancedBundle", [contracts.baseVerifier.address, advancedVerifier]);
  add("claimBundle", "integrityBundle", [claimVerifier]);
  add("remediationBundle", "integrityBundle", [remediationVerifier]);
  add("payrollSeal", "payrollSeal", [
    PAYO_PHASE3_MAINNET_POOL,
    contracts.policyRegistry.address,
    contracts.obligationRegistry.address,
    PAYO_PHASE3_MAINNET_CHAIN_ID,
  ]);

  return {
    schemaVersion: 1,
    generatedAt,
    network: "starknet-mainnet",
    chainId: PAYO_PHASE3_MAINNET_CHAIN_ID,
    poolAddress: PAYO_PHASE3_MAINNET_POOL,
    deployerAddress: canonicalHex(deployerAddress),
    adminAddress: canonicalHex(phase2Plan.adminAddress),
    phase2PlanGeneratedAt: phase2Plan.generatedAt,
    deploymentPolicy: {
      unique: false,
      verifierStageBeforeSeal: true,
      oneDeclarationPerConfirmation: true,
      reusePhase2Registries: true,
    },
    declarations: Object.fromEntries(phase3DeclarationOrder.map((name) => {
      const artifactName = contracts[name].artifactName;
      return [name, { artifactName, ...artifactIdentity(artifacts[artifactName]) }];
    })),
    contracts,
  };
}

export function assertPayoPhase3PlanMatchesArtifacts(plan, artifacts) {
  if (plan.schemaVersion !== 1 || plan.network !== "starknet-mainnet") {
    throw new Error("The Phase 3 plan has an unsupported schema or network.");
  }
  if (!sameHex(plan.chainId, PAYO_PHASE3_MAINNET_CHAIN_ID)
    || !sameHex(plan.poolAddress, PAYO_PHASE3_MAINNET_POOL)) {
    throw new Error("The Phase 3 plan is not bound to the expected Mainnet pool and chain.");
  }
  for (const [name, declaration] of Object.entries(plan.declarations ?? {})) {
    const artifact = artifacts[declaration.artifactName];
    if (!artifact) throw new Error(`Plan declaration ${name} has no current artifact.`);
    for (const field of ["classHash", "compiledClassHash", "sierraSha256", "casmSha256"]) {
      const matches = field.endsWith("Hash")
        ? sameHex(declaration[field], artifact[field])
        : declaration[field] === artifact[field];
      if (!matches) throw new Error(`Phase 3 ${name} ${field} changed after plan review.`);
    }
  }
  for (const name of [...phase3VerifierDeploymentOrder, "payrollSeal"]) {
    const contract = plan.contracts?.[name];
    if (!contract || !phase3DeploymentSalts[name]) {
      throw new Error(`The Phase 3 plan is missing deployment ${name}.`);
    }
    const expected = predictedAddress(
      contract.classHash,
      contract.constructorCalldata,
      phase3DeploymentSalts[name],
    );
    if (!sameHex(expected, contract.address)) {
      throw new Error(`Phase 3 ${name} predicted address or constructor changed.`);
    }
  }
}

export function deploymentPayloads(plan, stage) {
  const names = stage === "verifiers"
    ? phase3VerifierDeploymentOrder
    : stage === "seal"
      ? ["payrollSeal"]
      : null;
  if (!names) throw new Error(`Unknown Phase 3 deployment stage ${stage}.`);
  return names.map((name) => {
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
