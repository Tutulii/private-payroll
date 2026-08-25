import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { RpcProvider, constants } from "starknet";
import { ApiError } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";
import type {
  PayoDeploymentArtifactName,
  PayoMainnetTopologyPlan,
} from "@/lib/starknet/payo-deployment-plan";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type DeploymentEvidence = {
  schemaVersion: 1;
  network: "starknet-mainnet";
  plan: PayoMainnetTopologyPlan;
  declarations: Partial<Record<PayoDeploymentArtifactName, {
    transactionHash: string | null;
  }>>;
  deploymentTransactionHash: string | null;
};

const DEFAULT_EVIDENCE_PATH = resolve(
  process.cwd(),
  "circuits/payroll_integrity/target/payo-mainnet-deployment.json",
);

function scalar(response: string[], label: string): bigint {
  if (response.length !== 1) {
    throw new ApiError(502, `${label} returned an unexpected response.`, "DEPLOYMENT_BINDING_INVALID");
  }
  return BigInt(response[0]);
}

async function readEvidence(): Promise<DeploymentEvidence> {
  try {
    const parsed = JSON.parse(await readFile(
      process.env.PAYO_MAINNET_EVIDENCE_PATH ?? DEFAULT_EVIDENCE_PATH,
      "utf8",
    )) as DeploymentEvidence;
    if (
      parsed.schemaVersion !== 1
      || parsed.network !== "starknet-mainnet"
      || !parsed.plan?.contracts
    ) {
      throw new Error("invalid evidence");
    }
    return parsed;
  } catch {
    throw new ApiError(
      404,
      "A verified PAYO Mainnet deployment record is unavailable.",
      "DEPLOYMENT_EVIDENCE_UNAVAILABLE",
    );
  }
}

export async function GET() {
  try {
    if (
      process.env.NODE_ENV === "production"
      && process.env.PAYO_ENABLE_DEPLOYMENT_OPERATOR !== "true"
    ) {
      throw new ApiError(404, "The deployment operator is disabled.", "DEPLOYMENT_DISABLED");
    }
    const evidence = await readEvidence();
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    if (!rpcUrl) {
      throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    }
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const chainId = await provider.getChainId();
    if (
      BigInt(chainId) !== BigInt(constants.StarknetChainId.SN_MAIN)
      || BigInt(evidence.plan.chainId) !== BigInt(chainId)
    ) {
      throw new ApiError(502, "Deployment evidence is not bound to SN_MAIN.", "DEPLOYMENT_CHAIN_INVALID");
    }
    const verifiedBlockNumber = await provider.getBlockNumber();
    await Promise.all(Object.entries(evidence.plan.contracts).map(async ([name, contract]) => {
      const actual = await provider.getClassHashAt(contract.address, verifiedBlockNumber);
      if (BigInt(actual) !== BigInt(contract.classHash)) {
        throw new ApiError(
          502,
          `${name} failed deployed class-hash verification.`,
          "DEPLOYMENT_CLASS_INVALID",
        );
      }
    }));

    const bindings = [
      [evidence.plan.contracts.bundleVerifier.address, "get_underlying_verifier", evidence.plan.contracts.generatedVerifier.address],
      [evidence.plan.contracts.policyRegistry.address, "get_admin", evidence.plan.adminAddress],
      [evidence.plan.contracts.policyRegistry.address, "get_fx_publisher", evidence.plan.adminAddress],
      [evidence.plan.contracts.obligationRegistry.address, "get_admin", evidence.plan.adminAddress],
      [evidence.plan.contracts.payrollSeal.address, "get_pool", evidence.plan.poolAddress],
      [evidence.plan.contracts.payrollSeal.address, "get_catalog_registry", evidence.plan.contracts.policyRegistry.address],
      [evidence.plan.contracts.payrollSeal.address, "get_obligation_registry", evidence.plan.contracts.obligationRegistry.address],
    ] as const;
    await Promise.all(bindings.map(async ([contractAddress, entrypoint, expected]) => {
      const response = await provider.callContract(
        { contractAddress, entrypoint, calldata: [] },
        verifiedBlockNumber,
      );
      if (scalar(response, entrypoint) !== BigInt(expected)) {
        throw new ApiError(
          502,
          `${entrypoint} failed deployed binding verification.`,
          "DEPLOYMENT_BINDING_INVALID",
        );
      }
    }));

    const declarationTransactionHashes = Object.fromEntries(
      Object.entries(evidence.declarations ?? {})
        .filter((entry): entry is [string, { transactionHash: string }] => (
          typeof entry[1]?.transactionHash === "string"
        ))
        .map(([name, declaration]) => [name, declaration.transactionHash]),
    );
    return Response.json({
      deployment: {
        plan: evidence.plan,
        declarationTransactionHashes,
        deploymentTransactionHash: evidence.deploymentTransactionHash,
        verifiedBlockNumber,
      },
    }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
