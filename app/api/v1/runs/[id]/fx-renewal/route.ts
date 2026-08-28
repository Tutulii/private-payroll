import { RpcProvider } from "starknet";
import { z } from "zod";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  enqueueHistoricalFxRenewal,
  getHistoricalFxRenewalEvidence,
} from "@/lib/persistence/fx-publication-repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";
import { readProofSealState } from "@/lib/server/proof-relayer";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const requestSchema = z.discriminatedUnion("workflowType", [
  z.object({ workflowType: z.literal("wage_claim") }).strict(),
  z.object({
    workflowType: z.literal("wage_remediation"),
    claimId: uuidV7Schema,
  }).strict(),
]);

type FxRenewalContext = { params: Promise<{ id: string }> };

function requireConfiguredPublisher(): string {
  const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  if (!rpcUrl || !process.env.PAYO_PROOF_RELAYER_ADDRESS || !process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY) {
    throw new ApiError(503, "The trusted PAYO FX publisher is not configured.", "FX_PUBLISHER_NOT_CONFIGURED");
  }
  return rpcUrl;
}

function rootLimbs(root: string): { high: string; low: string } {
  const value = BigInt(root);
  return {
    high: (value >> 128n).toString(),
    low: (value & ((1n << 128n) - 1n)).toString(),
  };
}

export async function POST(request: Request, context: FxRenewalContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const runId = uuidV7Schema.parse(id);
    const renewalRequest = requestSchema.parse(await readJson(request));
    const { workflowType } = renewalRequest;
    const rpcUrl = requireConfiguredPublisher();
    const deployment = getPayoDeploymentConfig();
    const evidence = await getHistoricalFxRenewalEvidence(workflowType === "wage_remediation"
      ? { runId, principal, workflowType, claimId: renewalRequest.claimId }
      : { runId, principal, workflowType });
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const [chainId, blockNumber] = await Promise.all([
      provider.getChainId(),
      provider.getBlockNumber(),
    ]);
    if (BigInt(chainId) !== BigInt(deployment.chainId)) {
      throw new ApiError(503, "The FX renewal RPC is on the wrong Starknet chain.", "FX_RENEWAL_CHAIN_MISMATCH");
    }
    const limbs = rootLimbs(evidence.authorizationNullifier);
    const [block, sealState] = await Promise.all([
      provider.getBlock(blockNumber),
      readProofSealState({
        getBlockNumber: async () => blockNumber,
        callContract: (call, blockIdentifier) => provider.callContract(call, blockIdentifier),
      }, {
        sealAddress: deployment.sealAddress,
        runNullifierHigh: limbs.high,
        runNullifierLow: limbs.low,
      }),
    ]);
    const expectedStatus = workflowType === "wage_claim" ? 2 : 4;
    if (sealState.status !== expectedStatus || sealState.shardsVerified.some((verified) => !verified)) {
      throw new ApiError(
        409,
        "The historical payroll is not in the on-chain state required for this exception.",
        "FX_RENEWAL_SEAL_STATE_INVALID",
      );
    }
    const job = await enqueueHistoricalFxRenewal({
      evidence,
      observedAt: Number(block.timestamp),
      principal,
    });
    return Response.json({ job }, { status: job.state === "complete" ? 200 : 202 });
  } catch (error) {
    return apiFailure(error);
  }
}
