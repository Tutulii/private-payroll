import { z } from "zod";
import { readyWalletAddressSchema } from "@/lib/auth/ready-session";
import {
  findWorkerPublicIdentity,
  publishWorkerPublicIdentity,
} from "@/lib/persistence/public-identity-repository";
import { ApiError, requireReadyPrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const publishIdentitySchema = z.object({ identity: z.unknown() }).strict();

export async function GET(request: Request) {
  try {
    const principal = await requireReadyPrincipal(request);
    const value = new URL(request.url).searchParams.get("walletAddress");
    if (!value) throw new ApiError(400, "walletAddress is required.", "WALLET_ADDRESS_REQUIRED");
    const identity = await findWorkerPublicIdentity({
      walletAddress: readyWalletAddressSchema.parse(value),
      principal,
    });
    return Response.json({ identity });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requireReadyPrincipal(request);
    const input = publishIdentitySchema.parse(await readJson(request));
    const identity = await publishWorkerPublicIdentity({ ...input, principal });
    return Response.json({ identity }, { status: 200 });
  } catch (error) {
    return apiFailure(error);
  }
}
