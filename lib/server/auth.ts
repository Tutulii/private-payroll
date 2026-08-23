import { PrivyClient } from "@privy-io/node";

export type AuthenticatedPrincipal = {
  principalId: string;
  sessionId: string;
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code: string,
  ) {
    super(message);
  }
}

let privyClient: PrivyClient | undefined;

function getPrivyClient(): PrivyClient {
  const appId = process.env.NEXT_PUBLIC_PRIVY_APP_ID;
  const appSecret = process.env.PRIVY_APP_SECRET;
  if (!appId || !appSecret) {
    throw new ApiError(503, "Server authentication is not configured.", "AUTH_NOT_CONFIGURED");
  }
  privyClient ??= new PrivyClient({
    appId,
    appSecret,
    jwtVerificationKey: process.env.PRIVY_JWT_VERIFICATION_KEY || undefined,
  });
  return privyClient;
}

function tokenFromRequest(request: Request): string | undefined {
  const authorization = request.headers.get("authorization");
  if (authorization?.startsWith("Bearer ")) return authorization.slice(7).trim();

  const cookie = request.headers.get("cookie");
  return cookie
    ?.split(";")
    .map((part) => part.trim().split("="))
    .find(([name]) => name === "privy-token")?.[1];
}

export async function requirePrincipal(request: Request): Promise<AuthenticatedPrincipal> {
  const accessToken = tokenFromRequest(request);
  if (!accessToken) throw new ApiError(401, "A Privy access token is required.", "AUTH_REQUIRED");

  try {
    const claim = await getPrivyClient().utils().auth().verifyAccessToken(accessToken);
    return { principalId: claim.user_id, sessionId: claim.session_id };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(401, "The Privy access token is invalid or expired.", "AUTH_INVALID");
  }
}
