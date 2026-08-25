import {
  hash,
  num,
  validateAndParseAddress,
  type CompiledContract,
  type CompiledSierraCasm,
} from "starknet";
import {
  STARKNET_MAINNET_CHAIN_ID,
  STRK20_MAINNET_POOL_ADDRESS,
} from "./deployment";

export const PAYO_DEPLOYMENT_ARTIFACT_NAMES = [
  "generatedVerifier",
  "bundleVerifier",
  "policyRegistry",
  "obligationRegistry",
  "payrollSeal",
] as const;

export type PayoDeploymentArtifactName = typeof PAYO_DEPLOYMENT_ARTIFACT_NAMES[number];

export type PayoBrowserDeploymentArtifact = {
  contract: CompiledContract;
  casm: CompiledSierraCasm;
  classHash: string;
  compiledClassHash: string;
  sierraSha256: string;
  casmSha256: string;
};

export type PayoBrowserDeploymentPackage = {
  schemaVersion: 1;
  artifacts: Record<PayoDeploymentArtifactName, PayoBrowserDeploymentArtifact>;
};

export type PayoPlannedContract = {
  address: string;
  classHash: string;
  compiledClassHash: string;
  salt: string;
  constructorCalldata: string[];
};

export type PayoMainnetTopologyPlan = {
  chainId: string;
  adminAddress: string;
  poolAddress: string;
  contracts: Record<PayoDeploymentArtifactName, PayoPlannedContract>;
};

const SALTS: Record<PayoDeploymentArtifactName, string> = {
  generatedVerifier: "0x7061796f2d7665726966696572",
  bundleVerifier: "0x7061796f2d62756e646c65",
  policyRegistry: "0x7061796f2d706f6c696379",
  obligationRegistry: "0x7061796f2d6f626c69676174696f6e",
  payrollSeal: "0x7061796f2d7365616c",
};

function nonZeroAddress(value: string, label: string): string {
  try {
    const address = validateAndParseAddress(value);
    if (num.toBigInt(address) === 0n) throw new Error();
    return num.toHex(num.toBigInt(address));
  } catch {
    throw new Error(`${label} must be a non-zero Starknet address.`);
  }
}

function canonicalClassHash(value: string, label: string): string {
  if (!/^0x[0-9a-fA-F]+$/.test(value)) throw new Error(`${label} is invalid.`);
  const classHash = num.toBigInt(value);
  if (classHash <= 0n) throw new Error(`${label} is invalid.`);
  return num.toHex(classHash);
}

function plannedAddress(classHash: string, constructorCalldata: string[], salt: string): string {
  return num.toHex(num.toBigInt(hash.calculateContractAddressFromHash(
    salt,
    classHash,
    constructorCalldata,
    0,
  )));
}

/** Creates the exact UDC unique=false topology used by Devnet and Mainnet deployment. */
export function buildPayoMainnetTopologyPlan(input: {
  adminAddress: string;
  artifacts: PayoBrowserDeploymentPackage["artifacts"];
}): PayoMainnetTopologyPlan {
  const adminAddress = nonZeroAddress(input.adminAddress, "PAYO administrator");
  const artifacts = input.artifacts;
  for (const name of PAYO_DEPLOYMENT_ARTIFACT_NAMES) {
    if (!artifacts[name]) throw new Error(`The deployment package is missing ${name}.`);
    canonicalClassHash(artifacts[name].classHash, `${name} class hash`);
    canonicalClassHash(artifacts[name].compiledClassHash, `${name} compiled class hash`);
  }
  const contract = (
    name: PayoDeploymentArtifactName,
    constructorCalldata: string[],
  ): PayoPlannedContract => {
    const artifact = artifacts[name];
    const classHash = canonicalClassHash(artifact.classHash, `${name} class hash`);
    return {
      address: plannedAddress(classHash, constructorCalldata, SALTS[name]),
      classHash,
      compiledClassHash: canonicalClassHash(
        artifact.compiledClassHash,
        `${name} compiled class hash`,
      ),
      salt: SALTS[name],
      constructorCalldata,
    };
  };
  const generatedVerifier = contract("generatedVerifier", []);
  const bundleVerifier = contract("bundleVerifier", [generatedVerifier.address]);
  const policyRegistry = contract("policyRegistry", [adminAddress]);
  const obligationRegistry = contract("obligationRegistry", [adminAddress]);
  const payrollSeal = contract("payrollSeal", [
    STRK20_MAINNET_POOL_ADDRESS,
    policyRegistry.address,
    obligationRegistry.address,
    STARKNET_MAINNET_CHAIN_ID,
  ]);
  return {
    chainId: STARKNET_MAINNET_CHAIN_ID,
    adminAddress,
    poolAddress: STRK20_MAINNET_POOL_ADDRESS,
    contracts: {
      generatedVerifier,
      bundleVerifier,
      policyRegistry,
      obligationRegistry,
      payrollSeal,
    },
  };
}
