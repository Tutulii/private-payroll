import { Account, RpcProvider } from "starknet";
import { uuidV7Schema } from "@/lib/domain/records";
import { withStarknetRelayerSubmissionLock } from "@/lib/persistence/relayer-lock";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { configureAndActivateDirectPrivacyAccount } from "@/lib/server/direct-privacy-account-activation";
import { getDirectPrivacyDeploymentConfig } from "@/lib/server/direct-privacy-deployment";
import { apiFailure } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ActivationContext = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: ActivationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const accountId = uuidV7Schema.parse(id);
    const rpcUrl = process.env.STARKNET_RPC_URL;
    if (!rpcUrl) throw new ApiError(503, "Starknet RPC is not configured.", "STARKNET_RPC_NOT_CONFIGURED");
    const deployment = getDirectPrivacyDeploymentConfig();
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    const ownerPrivateKey = process.env.PAYO_AGENT_POLICY_OWNER_PRIVATE_KEY?.trim()
      || process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY?.trim() || "";
    const result = await configureAndActivateDirectPrivacyAccount({
      accountId,
      principal,
      provider,
      deployment,
      ownerPrivateKey,
      submitConfiguration: async (call) => {
        const owner = new Account({
          provider,
          address: deployment.policyAccountAddress,
          signer: ownerPrivateKey,
          cairoVersion: "1",
        });
        const estimate = await owner.estimateInvokeFee(call);
        const response = await withStarknetRelayerSubmissionLock(
          deployment.policyAccountAddress,
          () => owner.execute(call, { resourceBounds: estimate.resourceBounds }),
        );
        const receipt = await provider.waitForTransaction(response.transaction_hash, {
          retries: 400,
          retryInterval: 3_000,
        });
        if (receipt.isReverted()) {
          throw new ApiError(502, "Policy activation reverted on Starknet.", "DIRECT_POLICY_ACTIVATION_REVERTED");
        }
        return response.transaction_hash;
      },
    });
    return Response.json(result, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
