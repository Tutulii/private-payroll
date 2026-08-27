import { requirePrincipal } from "@/lib/server/auth";
import { revokeReadySession } from "@/lib/server/ready-auth";
import { apiFailure } from "@/lib/server/http";

export async function DELETE(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    await revokeReadySession(principal);
    return new Response(null, { status: 204 });
  } catch (error) {
    return apiFailure(error);
  }
}
