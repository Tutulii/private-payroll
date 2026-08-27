import { readyAuthVerificationRequestSchema } from "@/lib/auth/ready-session";
import { verifyReadyAuthenticationChallenge } from "@/lib/server/ready-auth";
import { apiFailure, readJson } from "@/lib/server/http";

export async function POST(request: Request) {
  try {
    const input = readyAuthVerificationRequestSchema.parse(await readJson(request));
    return Response.json({ session: await verifyReadyAuthenticationChallenge(input) }, {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
