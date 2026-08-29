import { RpcProvider } from "starknet";
import { obligationSnapshotPlanSubmissionSchema } from "@/lib/domain/obligation-snapshot-plan";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  getObligationSnapshotPlan,
  recordObligationSnapshotSubmission,
} from "@/lib/persistence/obligation-snapshot-plan-repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { reconcileObligationSnapshotPlan } from "@/lib/server/obligation-snapshot-reconciler";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type SnapshotContext = { params: Promise<{ id: string }> };

async function planId(context: SnapshotContext) {
  const { id } = await context.params;
  return uuidV7Schema.parse(id);
}

export async function GET(request: Request, context: SnapshotContext) {
  try {
    const principal = await requirePrincipal(request);
    const plan = await getObligationSnapshotPlan(await planId(context), principal);
    return Response.json({ plan }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}

/** Records the Ready transaction hash; this never treats submission as registration. */
export async function PATCH(request: Request, context: SnapshotContext) {
  try {
    const principal = await requirePrincipal(request);
    const submission = obligationSnapshotPlanSubmissionSchema.parse(await readJson(request));
    const plan = await recordObligationSnapshotSubmission({
      planId: await planId(context),
      transactionHash: submission.transactionHash,
      principal,
    });
    return Response.json({ plan }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}

/** Reconciles exact finalized Mainnet/Testnet state before changing durable state. */
export async function PUT(request: Request, context: SnapshotContext) {
  try {
    const principal = await requirePrincipal(request);
    const id = await planId(context);
    const plan = await getObligationSnapshotPlan(id, principal);
    const deployment = getPayoDeploymentConfig();
    const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    if (!rpcUrl) {
      throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    }
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const chainId = await provider.getChainId();
    if (BigInt(chainId) !== BigInt(deployment.chainId)) {
      throw new ApiError(503, "Snapshot reconciliation RPC is on the wrong chain.", "SNAPSHOT_CHAIN_MISMATCH");
    }
    const result = await reconcileObligationSnapshotPlan({
      plan,
      sealAddress: deployment.sealAddress,
      rpc: {
        getBlockNumber: () => provider.getBlockNumber(),
        callContract: (call, blockIdentifier) => provider.callContract(call, blockIdentifier),
        getTransactionReceipt: (transactionHash) => provider.getTransactionReceipt(transactionHash),
      },
    });
    return Response.json(result, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
