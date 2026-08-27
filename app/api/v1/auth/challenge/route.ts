import { readyAuthChallengeRequestSchema } from "@/lib/auth/ready-session";
import { createReadyAuthenticationChallenge } from "@/lib/server/ready-auth";
import { apiFailure, readJson } from "@/lib/server/http";

export async function POST(request: Request) {
  try {
    const input = readyAuthChallengeRequestSchema.parse(await readJson(request));
    return Response.json({ challenge: await createReadyAuthenticationChallenge(request, input) }, {
      status: 201,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return apiFailure(error);
  }
}
