import { RpcProvider } from "starknet";
import { z } from "zod";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  enqueueHistoricalFxRenewal,
  getFxPublicationJob,
  getHistoricalFxRenewalEvidence,
} from "@/lib/persistence/fx-publication-repository";
import { isFxRootActive } from "@/lib/server/fx-root-publisher";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import {
  getPayoDeploymentConfig,
  getPayoRegistryConfig,
} from "@/lib/server/payo-deployment";
import {
  assertInvokedPayrollFxAnchor,
  readPayrollRunAnchor,
} from "@/lib/server/payroll-run-anchor";
import { readProofSealState } from "@/lib/server/proof-relayer";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const requestSchema = z.discriminatedUnion("workflowType", [
  z.object({ workflowType: z.literal("wage_claim") }).strict(),
  z.object({ workflowType: z.literal("employer_statement") }).strict(),
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
    const registries = getPayoRegistryConfig();
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
    const sealValidation = workflowType === "employer_statement"
      ? readPayrollRunAnchor({
          callContract: (call, blockIdentifier) =>
            provider.callContract(call, blockIdentifier),
        }, {
          sealAddress: deployment.sealAddress,
          runNullifierHigh: limbs.high,
          runNullifierLow: limbs.low,
          blockNumber,
        }).then((anchor) => {
          try {
            assertInvokedPayrollFxAnchor(anchor, evidence.catalogRoot);
          } catch {
            throw new ApiError(
              409,
              "The historical payroll is not in the on-chain state required for employer evidence.",
              "FX_RENEWAL_SEAL_STATE_INVALID",
            );
          }
        })
      : readProofSealState({
          getBlockNumber: async () => blockNumber,
          callContract: (call, blockIdentifier) =>
            provider.callContract(call, blockIdentifier),
        }, {
          sealAddress: deployment.sealAddress,
          runNullifierHigh: limbs.high,
          runNullifierLow: limbs.low,
        }).then((sealState) => {
          const expectedStatus = workflowType === "wage_remediation" ? 4 : 2;
          if (
            sealState.status !== expectedStatus
            || sealState.shardsVerified.some((verified) => !verified)
          ) {
            throw new ApiError(
              409,
              "The historical payroll is not in the on-chain state required for this exception.",
              "FX_RENEWAL_SEAL_STATE_INVALID",
            );
          }
        });
    const [block, rootActive] = await Promise.all([
      provider.getBlock(blockNumber),
      isFxRootActive({
        rpc: provider,
        policyRegistryAddress: registries.policyRegistryAddress,
        catalogRoot: evidence.catalogRoot,
        blockIdentifier: blockNumber,
      }),
      sealValidation,
    ]);
    if (rootActive) {
      const job = await getFxPublicationJob({
        organizationId: evidence.organizationId,
        catalogRoot: evidence.catalogRoot,
        principal,
      });
      return Response.json({ job }, { status: job.state === "complete" ? 200 : 202 });
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
