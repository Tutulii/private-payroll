import {
  readyRecoveryLinkCompletionSchema,
  readyRecoveryLinkRequestSchema,
} from "@/lib/auth/ready-session";
import { requirePrincipal } from "@/lib/server/auth";
import {
  completeReadyRecoveryLink,
  createReadyRecoveryLink,
} from "@/lib/server/ready-auth";
import { apiFailure, readJson } from "@/lib/server/http";

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = readyRecoveryLinkRequestSchema.parse(await readJson(request));
    return Response.json({ recoveryLink: await createReadyRecoveryLink(principal, input) }, {
      status: 201,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function PATCH(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = readyRecoveryLinkCompletionSchema.parse(await readJson(request));
    return Response.json({ session: await completeReadyRecoveryLink(principal, input) }, {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
