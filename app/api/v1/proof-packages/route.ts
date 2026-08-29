import { encryptedPayoProofBundleCreateSchema } from "@/lib/domain/proof-bundle";
import { storeEncryptedPayrollIntegrityBundle } from "@/lib/persistence/proof-bundle-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig } from "@/lib/server/payo-deployment";

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const bundle = encryptedPayoProofBundleCreateSchema.parse(await readJson(request));
    const stored = await storeEncryptedPayrollIntegrityBundle({
      bundle,
      principal,
      deployment: getPayoDeploymentConfig(),
    });
    return Response.json({ proofBundle: stored }, { status: stored.replayed ? 200 : 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
