import { RpcProvider } from "starknet";
import { employerStatementSubmissionSchema } from "@/lib/domain/employer-statement";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  getEmployerStatement,
  recordEmployerStatementSubmission,
} from "@/lib/persistence/employer-statement-repository";
import { getObligationSnapshotPlan } from "@/lib/persistence/obligation-snapshot-plan-repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { reconcileEmployerStatement } from "@/lib/server/employer-statement-reconciler";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type StatementContext = { params: Promise<{ id: string }> };

async function statementId(context: StatementContext) {
  const { id } = await context.params;
  return uuidV7Schema.parse(id);
}

export async function GET(request: Request, context: StatementContext) {
  try {
    const principal = await requirePrincipal(request);
    const statement = await getEmployerStatement(
      await statementId(context),
      principal,
    );
    return Response.json({ statement }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function PATCH(request: Request, context: StatementContext) {
  try {
    const principal = await requirePrincipal(request);
    const submission = employerStatementSubmissionSchema.parse(
      await readJson(request),
    );
    const statement = await recordEmployerStatementSubmission({
      statementId: await statementId(context),
      transactionHash: submission.transactionHash,
      principal,
    });
    return Response.json({ statement }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function PUT(request: Request, context: StatementContext) {
  try {
    const principal = await requirePrincipal(request);
    const id = await statementId(context);
    const statement = await getEmployerStatement(id, principal);
    const snapshot = await getObligationSnapshotPlan(
      statement.snapshotPlanId,
      principal,
    );
    const deployment = getPayoDeploymentConfig();
    const rpcUrl = process.env.STARKNET_RPC_URL
      ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
    if (!rpcUrl) {
      throw new ApiError(
        503,
        "Starknet RPC is not configured.",
        "STARKNET_RPC_NOT_CONFIGURED",
      );
    }
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const chainId = await provider.getChainId();
    if (BigInt(chainId) !== BigInt(deployment.chainId)) {
      throw new ApiError(
        503,
        "Statement reconciliation RPC is on the wrong chain.",
        "STATEMENT_CHAIN_MISMATCH",
      );
    }
    const result = await reconcileEmployerStatement({
      statement,
      snapshot: {
        runNullifier: snapshot.runNullifier,
        snapshotFact: snapshot.snapshotFact,
      },
      sealAddress: deployment.sealAddress,
      rpc: {
        getBlockNumber: () => provider.getBlockNumber(),
        callContract: (call, blockIdentifier) =>
          provider.callContract(call, blockIdentifier),
        getTransactionReceipt: (transactionHash) =>
          provider.getTransactionReceipt(transactionHash),
      },
    });
    return Response.json(result, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
