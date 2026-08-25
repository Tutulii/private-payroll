import { uuidV7Schema } from "@/lib/domain/records";
import { vaultRotationRequestSchema } from "@/lib/domain/vault-lifecycle";
import { rotateOrganizationVault } from "@/lib/persistence/vault-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

type Context = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: Context) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const vault = await rotateOrganizationVault({
      organizationId: uuidV7Schema.parse(id),
      rotation: vaultRotationRequestSchema.parse(await readJson(request)),
      principal,
    });
    return Response.json({ vault });
  } catch (error) {
    return apiFailure(error);
  }
}
