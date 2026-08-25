import { uuidV7Schema } from "@/lib/domain/records";
import { getSealedRunRecoveryEvidence } from "@/lib/persistence/settlement-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";

type RunRecoveryContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: RunRecoveryContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const chainId = process.env.PAYO_INDEX_CHAIN_ID ?? "SN_MAIN";
    const sealAddress = process.env.PAYO_INDEX_CONTRACT_ADDRESS ?? process.env.PAYO_SEAL_ADDRESS;
    if (!sealAddress) throw new Error("PAYO seal recovery is not configured.");
    return Response.json({
      recovery: await getSealedRunRecoveryEvidence({
        runId: uuidV7Schema.parse(id),
        chainId,
        sealAddress,
        principal,
      }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
