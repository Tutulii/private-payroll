import { RpcProvider } from "starknet";
import { uuidV7Schema } from "@/lib/domain/records";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import {
  configureAndActivateDirectPrivacyAccount,
  estimateDirectPrivacyAccountActivation,
} from "@/lib/server/direct-privacy-account-activation";
import { getDirectPrivacyDeploymentConfig } from "@/lib/server/direct-privacy-deployment";
import { apiFailure } from "@/lib/server/http";
import { PolicyOwnerSignerClient } from "@/lib/server/policy-owner-signer-client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ActivationContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: ActivationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const accountId = uuidV7Schema.parse(id);
    const rpcUrl = process.env.STARKNET_RPC_URL;
    if (!rpcUrl) {
      throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    }
    const deployment = getDirectPrivacyDeploymentConfig();
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const signer = PolicyOwnerSignerClient.fromEnvironment();
    const estimate = await estimateDirectPrivacyAccountActivation({
      accountId,
      principal,
      provider,
      deployment,
      ownerPublicKey: await signer.getPubKey(),
      estimateConfiguration: (call) => signer.estimatePolicy(call),
    });
    return Response.json({ estimate }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request, context: ActivationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const accountId = uuidV7Schema.parse(id);
    const rpcUrl = process.env.STARKNET_RPC_URL;
    if (!rpcUrl) throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    const deployment = getDirectPrivacyDeploymentConfig();
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const signer = PolicyOwnerSignerClient.fromEnvironment();
    const result = await configureAndActivateDirectPrivacyAccount({
      accountId,
      principal,
      provider,
      deployment,
      ownerPublicKey: await signer.getPubKey(),
      submitConfiguration: async (call) => {
        const response = await signer.configurePolicy(call);
        return response.transactionHash;
      },
    });
    return Response.json(result, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
