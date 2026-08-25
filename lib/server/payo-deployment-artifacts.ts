import "server-only";

import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { hash, num } from "starknet";
import type {
  PayoBrowserDeploymentArtifact,
  PayoBrowserDeploymentPackage,
  PayoDeploymentArtifactName,
} from "@/lib/starknet/payo-deployment-plan";

const root = process.cwd();
const definitions: Record<PayoDeploymentArtifactName, {
  sierra: string;
  casm: string;
  sourcePackage: "contracts" | "verifier";
}> = {
  generatedVerifier: {
    sierra: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.contract_class.json",
    casm: "contracts/integrity_verifier/target/dev/integrity_verifier_UltraKeccakZKHonkVerifier.compiled_contract_class.json",
    sourcePackage: "verifier",
  },
  bundleVerifier: {
    sierra: "contracts/target/dev/payo_contracts_PayoIntegrityBundleVerifier.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoIntegrityBundleVerifier.compiled_contract_class.json",
    sourcePackage: "contracts",
  },
  policyRegistry: {
    sierra: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPolicyRegistry.compiled_contract_class.json",
    sourcePackage: "contracts",
  },
  obligationRegistry: {
    sierra: "contracts/target/dev/payo_contracts_PayoObligationRootRegistry.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoObligationRootRegistry.compiled_contract_class.json",
    sourcePackage: "contracts",
  },
  payrollSeal: {
    sierra: "contracts/target/dev/payo_contracts_PayoPayrollSeal.contract_class.json",
    casm: "contracts/target/dev/payo_contracts_PayoPayrollSeal.compiled_contract_class.json",
    sourcePackage: "contracts",
  },
};

async function filesRecursively(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  return (await Promise.all(entries.map((entry) => {
    const path = resolve(directory, entry.name);
    return entry.isDirectory() ? filesRecursively(path) : [path];
  }))).flat();
}

async function sourceBuildTimes() {
  const latest = async (paths: string[]) => Math.max(
    ...(await Promise.all(paths.map(async (path) => (await stat(path)).mtimeMs))),
  );
  return {
    contracts: await latest([
      resolve(root, "contracts/Scarb.toml"),
      ...(await filesRecursively(resolve(root, "contracts/src"))),
    ]),
    verifier: await latest([
      resolve(root, "contracts/integrity_verifier/Scarb.toml"),
      ...(await filesRecursively(resolve(root, "contracts/integrity_verifier/src"))),
    ]),
  };
}

function sha256(source: string): string {
  return createHash("sha256").update(source).digest("hex");
}

let artifactPackage: Promise<PayoBrowserDeploymentPackage> | null = null;

export function readPayoBrowserDeploymentPackage(): Promise<PayoBrowserDeploymentPackage> {
  artifactPackage ??= (async () => {
    const buildTimes = await sourceBuildTimes();
    const entries = await Promise.all(Object.entries(definitions).map(async ([rawName, definition]) => {
      const name = rawName as PayoDeploymentArtifactName;
      const [sierraStat, casmStat, sierraSource, casmSource] = await Promise.all([
        stat(resolve(root, definition.sierra)),
        stat(resolve(root, definition.casm)),
        readFile(resolve(root, definition.sierra), "utf8"),
        readFile(resolve(root, definition.casm), "utf8"),
      ]);
      if (
        sierraStat.mtimeMs < buildTimes[definition.sourcePackage]
        || casmStat.mtimeMs < buildTimes[definition.sourcePackage]
      ) {
        throw new Error(`${name} deploy artifacts are stale. Rebuild the pinned Scarb package.`);
      }
      const contract = JSON.parse(sierraSource);
      const casm = JSON.parse(casmSource);
      const artifact: PayoBrowserDeploymentArtifact = {
        contract,
        casm,
        classHash: num.toHex(BigInt(hash.computeContractClassHash(contract))),
        compiledClassHash: num.toHex(BigInt(hash.computeCompiledClassHash(casm))),
        sierraSha256: sha256(sierraSource),
        casmSha256: sha256(casmSource),
      };
      return [name, artifact] as const;
    }));
    return {
      schemaVersion: 1,
      artifacts: Object.fromEntries(entries) as PayoBrowserDeploymentPackage["artifacts"],
    };
  })();
  return artifactPackage;
}
