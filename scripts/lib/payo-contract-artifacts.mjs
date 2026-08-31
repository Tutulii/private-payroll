import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { hash, num } from "starknet";

export const repositoryRoot = resolve(import.meta.dirname, "../..");

export const payoArtifactDefinitions = Object.freeze({
  generatedVerifier: Object.freeze({
    sierra: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.contract_class.json",
    casm: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.compiled_contract_class.json",
    sourcePackage: "verifier",
  }),
  bundleVerifier: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoIntegrityBundleVerifier.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoIntegrityBundleVerifier.compiled_contract_class.json",
    sourcePackage: "contracts",
  }),
  policyRegistry: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.compiled_contract_class.json",
    sourcePackage: "contracts",
  }),
  obligationRegistry: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoObligationRootRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoObligationRootRegistry.compiled_contract_class.json",
    sourcePackage: "contracts",
  }),
  payrollSeal: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoPayrollSeal.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPayrollSeal.compiled_contract_class.json",
    sourcePackage: "contracts",
  }),
});

export const payoPhase3ArtifactDefinitions = Object.freeze({
  baseVerifier: Object.freeze({
    sierra: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.contract_class.json",
    casm: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.compiled_contract_class.json",
    sourceDirectory: "contracts/integrity_verifier",
  }),
  advancedVerifier: Object.freeze({
    sierra: "contracts/advanced_verifier/target/dev/advanced_verifier_PayoAdvancedObligationVerifier.contract_class.json",
    casm: "contracts/advanced_verifier/target/dev/advanced_verifier_PayoAdvancedObligationVerifier.compiled_contract_class.json",
    sourceDirectory: "contracts/advanced_verifier",
  }),
  claimVerifier: Object.freeze({
    sierra: "contracts/claim_verifier/target/dev/claim_verifier_PayoWageClaimVerifier.contract_class.json",
    casm: "contracts/claim_verifier/target/dev/claim_verifier_PayoWageClaimVerifier.compiled_contract_class.json",
    sourceDirectory: "contracts/claim_verifier",
  }),
  remediationVerifier: Object.freeze({
    sierra: "contracts/remediation_verifier/target/dev/remediation_verifier_PayoWageRemediationVerifier.contract_class.json",
    casm: "contracts/remediation_verifier/target/dev/remediation_verifier_PayoWageRemediationVerifier.compiled_contract_class.json",
    sourceDirectory: "contracts/remediation_verifier",
  }),
  advancedBundle: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoAdvancedBundleVerifier.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoAdvancedBundleVerifier.compiled_contract_class.json",
    sourceDirectory: "contracts",
  }),
  integrityBundle: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoIntegrityBundleVerifier.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoIntegrityBundleVerifier.compiled_contract_class.json",
    sourceDirectory: "contracts",
  }),
  policyRegistry: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.compiled_contract_class.json",
    sourceDirectory: "contracts",
  }),
  obligationRegistry: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoObligationRootRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoObligationRootRegistry.compiled_contract_class.json",
    sourceDirectory: "contracts",
  }),
  payrollSeal: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoPayrollSeal.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPayrollSeal.compiled_contract_class.json",
    sourceDirectory: "contracts",
  }),
});

export const payoWageClaimArtifactDefinitions = Object.freeze({
  snapshotVerifier: Object.freeze({
    sierra: "contracts/snapshot_v5_verifier/target/dev/snapshot_v5_verifier_PayoObligationSnapshotV5Verifier.contract_class.json",
    casm: "contracts/snapshot_v5_verifier/target/dev/snapshot_v5_verifier_PayoObligationSnapshotV5Verifier.compiled_contract_class.json",
    sourceDirectory: "contracts/snapshot_v5_verifier",
  }),
  claimVerifier: Object.freeze({
    sierra: "contracts/claim_v6_verifier/target/dev/claim_v6_verifier_PayoWageClaimV6Verifier.contract_class.json",
    casm: "contracts/claim_v6_verifier/target/dev/claim_v6_verifier_PayoWageClaimV6Verifier.compiled_contract_class.json",
    sourceDirectory: "contracts/claim_v6_verifier",
  }),
  remediationVerifier: Object.freeze({
    sierra: "contracts/remediation_v7_verifier/target/dev/remediation_v7_verifier_PayoWageRemediationV7Verifier.contract_class.json",
    casm: "contracts/remediation_v7_verifier/target/dev/remediation_v7_verifier_PayoWageRemediationV7Verifier.compiled_contract_class.json",
    sourceDirectory: "contracts/remediation_v7_verifier",
  }),
  exceptionSeal: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoPayrollExceptionSeal.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPayrollExceptionSeal.compiled_contract_class.json",
    sourceDirectory: "contracts",
  }),
});

export const payoPhase4ArtifactDefinitions = Object.freeze({
  settlementVerifier: Object.freeze({
    sierra: "contracts/settlement_verifier_v8/target/dev/settlement_verifier_v8_PayoSettlementMatchV8Verifier.contract_class.json",
    casm: "contracts/settlement_verifier_v8/target/dev/settlement_verifier_v8_PayoSettlementMatchV8Verifier.compiled_contract_class.json",
    sourceDirectory: "contracts/settlement_verifier_v8",
  }),
  payrollSeal: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoPayrollSeal.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPayrollSeal.compiled_contract_class.json",
    sourceDirectory: "contracts",
  }),
  policyAccount: Object.freeze({
    sierra: "contracts/target/dev/payo_contracts_PayoPolicyAccount.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPolicyAccount.compiled_contract_class.json",
    sourceDirectory: "contracts",
  }),
});

async function filesRecursively(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const path = resolve(directory, entry.name);
    return entry.isDirectory() ? filesRecursively(path) : [path];
  }));
  return nested.flat();
}

async function newestModifiedAt(paths) {
  return Math.max(...(await Promise.all(paths.map(async (path) => (await stat(path)).mtimeMs))));
}

export async function assertFreshPayoDeployArtifacts() {
  const contractSources = [
    resolve(repositoryRoot, "contracts/Scarb.toml"),
    ...(await filesRecursively(resolve(repositoryRoot, "contracts/src"))),
  ];
  const verifierSources = [
    resolve(repositoryRoot, "contracts/integrity_verifier/Scarb.toml"),
    ...(await filesRecursively(resolve(repositoryRoot, "contracts/integrity_verifier/src"))),
  ];
  const sourceBuildTimes = {
    contracts: await newestModifiedAt(contractSources),
    verifier: await newestModifiedAt(verifierSources),
  };
  for (const [name, definition] of Object.entries(payoArtifactDefinitions)) {
    for (const artifactPath of [definition.sierra, definition.casm]) {
      let artifactModifiedAt;
      try {
        artifactModifiedAt = (await stat(resolve(repositoryRoot, artifactPath))).mtimeMs;
      } catch {
        throw new Error(`Missing ${name} deploy artifact ${artifactPath}. Run the pinned Scarb build first.`);
      }
      if (artifactModifiedAt < sourceBuildTimes[definition.sourcePackage]) {
        throw new Error(
          `Refusing stale ${name} deploy artifact ${artifactPath}. Rebuild the affected Scarb package first.`,
        );
      }
    }
  }
}

function sha256(source) {
  return createHash("sha256").update(source).digest("hex");
}

export async function readPayoDeployArtifact(name) {
  const definition = payoArtifactDefinitions[name];
  if (!definition) throw new Error(`Unknown PAYO artifact ${name}.`);
  const [sierraSource, casmSource] = await Promise.all([
    readFile(resolve(repositoryRoot, definition.sierra), "utf8"),
    readFile(resolve(repositoryRoot, definition.casm), "utf8"),
  ]);
  const sierra = JSON.parse(sierraSource);
  const casm = JSON.parse(casmSource);
  return {
    name,
    definition,
    sierra,
    casm,
    classHash: num.toHex(BigInt(hash.computeContractClassHash(sierra))),
    compiledClassHash: num.toHex(BigInt(hash.computeCompiledClassHash(casm))),
    sierraSha256: sha256(sierraSource),
    casmSha256: sha256(casmSource),
  };
}

export async function readAllPayoDeployArtifacts() {
  const entries = await Promise.all(
    Object.keys(payoArtifactDefinitions).map(async (name) => [name, await readPayoDeployArtifact(name)]),
  );
  return Object.fromEntries(entries);
}

async function assertFreshDefinitions(definitions) {
  const sourceBuildTimes = new Map();
  for (const definition of Object.values(definitions)) {
    if (sourceBuildTimes.has(definition.sourceDirectory)) continue;
    const directory = resolve(repositoryRoot, definition.sourceDirectory);
    const sources = [
      resolve(directory, "Scarb.toml"),
      ...(await filesRecursively(resolve(directory, "src"))),
    ];
    sourceBuildTimes.set(definition.sourceDirectory, await newestModifiedAt(sources));
  }
  for (const [name, definition] of Object.entries(definitions)) {
    for (const artifactPath of [definition.sierra, definition.casm]) {
      let artifactModifiedAt;
      try {
        artifactModifiedAt = (await stat(resolve(repositoryRoot, artifactPath))).mtimeMs;
      } catch {
        throw new Error(`Missing ${name} deploy artifact ${artifactPath}. Run the pinned Scarb build first.`);
      }
      if (artifactModifiedAt < sourceBuildTimes.get(definition.sourceDirectory)) {
        throw new Error(
          `Refusing stale ${name} deploy artifact ${artifactPath}. Rebuild the affected Scarb package first.`,
        );
      }
    }
  }
}

export async function assertFreshPayoPhase3DeployArtifacts() {
  await assertFreshDefinitions(payoPhase3ArtifactDefinitions);
}

export async function readPayoPhase3DeployArtifact(name) {
  const definition = payoPhase3ArtifactDefinitions[name];
  if (!definition) throw new Error(`Unknown PAYO Phase 3 artifact ${name}.`);
  const [sierraSource, casmSource] = await Promise.all([
    readFile(resolve(repositoryRoot, definition.sierra), "utf8"),
    readFile(resolve(repositoryRoot, definition.casm), "utf8"),
  ]);
  const sierra = JSON.parse(sierraSource);
  const casm = JSON.parse(casmSource);
  return {
    name,
    definition,
    sierra,
    casm,
    classHash: num.toHex(BigInt(hash.computeContractClassHash(sierra))),
    compiledClassHash: num.toHex(BigInt(hash.computeCompiledClassHash(casm))),
    sierraSha256: sha256(sierraSource),
    casmSha256: sha256(casmSource),
  };
}

export async function readAllPayoPhase3DeployArtifacts() {
  const entries = await Promise.all(
    Object.keys(payoPhase3ArtifactDefinitions).map(async (name) => [
      name,
      await readPayoPhase3DeployArtifact(name),
    ]),
  );
  return Object.fromEntries(entries);
}

export async function assertFreshPayoWageClaimDeployArtifacts() {
  await assertFreshDefinitions(payoWageClaimArtifactDefinitions);
}

export async function readPayoWageClaimDeployArtifact(name) {
  const definition = payoWageClaimArtifactDefinitions[name];
  if (!definition) throw new Error(`Unknown PAYO wage-claim artifact ${name}.`);
  const [sierraSource, casmSource] = await Promise.all([
    readFile(resolve(repositoryRoot, definition.sierra), "utf8"),
    readFile(resolve(repositoryRoot, definition.casm), "utf8"),
  ]);
  const sierra = JSON.parse(sierraSource);
  const casm = JSON.parse(casmSource);
  return {
    name,
    definition,
    sierra,
    casm,
    classHash: num.toHex(BigInt(hash.computeContractClassHash(sierra))),
    compiledClassHash: num.toHex(BigInt(hash.computeCompiledClassHash(casm))),
    sierraSha256: sha256(sierraSource),
    casmSha256: sha256(casmSource),
  };
}

export async function readAllPayoWageClaimDeployArtifacts() {
  const entries = await Promise.all(
    Object.keys(payoWageClaimArtifactDefinitions).map(async (name) => [
      name,
      await readPayoWageClaimDeployArtifact(name),
    ]),
  );
  return Object.fromEntries(entries);
}

export async function assertFreshPayoPhase4DeployArtifacts() {
  await assertFreshDefinitions(payoPhase4ArtifactDefinitions);
}

export async function readPayoPhase4DeployArtifact(name) {
  const definition = payoPhase4ArtifactDefinitions[name];
  if (!definition) throw new Error(`Unknown PAYO Phase 4 artifact ${name}.`);
  const [sierraSource, casmSource] = await Promise.all([
    readFile(resolve(repositoryRoot, definition.sierra), "utf8"),
    readFile(resolve(repositoryRoot, definition.casm), "utf8"),
  ]);
  const sierra = JSON.parse(sierraSource);
  const casm = JSON.parse(casmSource);
  return {
    name,
    definition,
    sierra,
    casm,
    classHash: num.toHex(BigInt(hash.computeContractClassHash(sierra))),
    compiledClassHash: num.toHex(BigInt(hash.computeCompiledClassHash(casm))),
    sierraSha256: sha256(sierraSource),
    casmSha256: sha256(casmSource),
  };
}

export async function readAllPayoPhase4DeployArtifacts() {
  const entries = await Promise.all(
    Object.keys(payoPhase4ArtifactDefinitions).map(async (name) => [
      name,
      await readPayoPhase4DeployArtifact(name),
    ]),
  );
  return Object.fromEntries(entries);
}
