import { ApiError } from "@/lib/server/auth";
import { apiFailure } from "@/lib/server/http";
import { readPayoBrowserDeploymentPackage } from "@/lib/server/payo-deployment-artifacts";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    if (
      process.env.NODE_ENV === "production"
      && process.env.PAYO_ENABLE_DEPLOYMENT_OPERATOR !== "true"
    ) {
      throw new ApiError(404, "The deployment operator is disabled.", "DEPLOYMENT_DISABLED");
    }
    return Response.json(await readPayoBrowserDeploymentPackage(), {
      headers: { "cache-control": "private, no-store, max-age=0" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
