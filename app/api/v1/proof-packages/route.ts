import { proofPackageSchema } from "@/lib/domain/payroll";
import { storeProofPackage } from "@/lib/persistence/repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const proofPackage = proofPackageSchema.parse(await readJson(request));
    const stored = await storeProofPackage(proofPackage, principal);
    return Response.json({ proofPackage: stored }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
