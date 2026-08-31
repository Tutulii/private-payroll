import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { uuidV7Schema } from "@/lib/domain/records";
import { stageDirectPrivacyRunWitness } from "@/lib/persistence/direct-privacy-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const stageSchema = z.object({
  encryptedWitness: encryptedVaultRecordSchema,
}).strict();
type RunContext = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: RunContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const input = stageSchema.parse(await readJson(request));
    const witness = await stageDirectPrivacyRunWitness({
      accountId: uuidV7Schema.parse(id),
      encryptedWitness: input.encryptedWitness,
      principal,
    });
    return Response.json({ witness }, {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
