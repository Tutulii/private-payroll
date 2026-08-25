import { z } from "zod";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  acknowledgeRecoveryPackage,
  getOrganizationVaultState,
} from "@/lib/persistence/vault-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const recoveryAcknowledgementSchema = z.object({
  packageHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
}).strict();

type OrganizationVaultContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: OrganizationVaultContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const organizationId = uuidV7Schema.parse(id);
    return Response.json({ vault: await getOrganizationVaultState(organizationId, principal) });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request, context: OrganizationVaultContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const organizationId = uuidV7Schema.parse(id);
    const { packageHash } = recoveryAcknowledgementSchema.parse(await readJson(request));
    return Response.json({
      vault: await acknowledgeRecoveryPackage({ organizationId, packageHash, principal }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
