import { uuidV7Schema } from "@/lib/domain/records";
import { getEncryptedProofBundle } from "@/lib/persistence/proof-bundle-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";

type ProofBundleContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: ProofBundleContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({
      proofBundle: await getEncryptedProofBundle({
        proofBundleId: uuidV7Schema.parse(id),
        principal,
      }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
