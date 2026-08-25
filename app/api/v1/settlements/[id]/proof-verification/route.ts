import { proofVerificationRequestSchema } from "@/lib/domain/proof-bundle";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  enqueueProofVerification,
  getProofVerificationJob,
} from "@/lib/persistence/proof-verification-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

type ProofVerificationContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: ProofVerificationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({
      proofVerification: await getProofVerificationJob(uuidV7Schema.parse(id), principal),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request, context: ProofVerificationContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const verification = await enqueueProofVerification({
      settlementId: uuidV7Schema.parse(id),
      request: proofVerificationRequestSchema.parse(await readJson(request)),
      principal,
    });
    return Response.json(
      { proofVerification: verification },
      { status: verification.replayed ? 200 : 201 },
    );
  } catch (error) {
    return apiFailure(error);
  }
}
