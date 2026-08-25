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
