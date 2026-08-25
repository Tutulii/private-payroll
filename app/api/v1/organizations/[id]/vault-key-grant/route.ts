import { uuidV7Schema } from "@/lib/domain/records";
import { getCurrentVaultKeyGrant } from "@/lib/persistence/vault-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";

type Context = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: Context) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const grant = await getCurrentVaultKeyGrant({
      organizationId: uuidV7Schema.parse(id),
      principal,
    });
    return Response.json({ grant }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
