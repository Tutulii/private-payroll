import "server-only";

import { verifyAccessToken, type VerifyAccessTokenInput } from "@privy-io/node";
import { createRemoteJWKSet } from "jose";

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

let remoteVerificationKey: {
  appId: string;
  apiUrl: string;
  key: VerifyAccessTokenInput["verification_key"];
} | undefined;

function getPrivyVerification(): {
  appId: string;
  verificationKey: VerifyAccessTokenInput["verification_key"];
} {
  const appId = process.env.NEXT_PUBLIC_PRIVY_APP_ID;
  if (!appId) {
    throw new ApiError(503, "Server authentication is not configured.", "AUTH_NOT_CONFIGURED");
  }
  const verificationKeyOverride = process.env.PRIVY_JWT_VERIFICATION_KEY;
  if (verificationKeyOverride) return { appId, verificationKey: verificationKeyOverride };

  const apiUrl = (process.env.PRIVY_API_URL ?? "https://api.privy.io").replace(/\/$/, "");
  let jwksUrl: URL;
  try {
    jwksUrl = new URL(`${apiUrl}/v1/apps/${encodeURIComponent(appId)}/jwks.json`);
  } catch {
    throw new ApiError(503, "Server authentication is not configured.", "AUTH_NOT_CONFIGURED");
  }
  if (jwksUrl.protocol !== "https:") {
    throw new ApiError(503, "Privy JWKS must use HTTPS.", "AUTH_NOT_CONFIGURED");
  }
  if (!remoteVerificationKey || remoteVerificationKey.appId !== appId || remoteVerificationKey.apiUrl !== apiUrl) {
    remoteVerificationKey = {
      appId,
      apiUrl,
      key: createRemoteJWKSet(jwksUrl, {
        cacheMaxAge: 60 * 60 * 1_000,
        cooldownDuration: 10 * 60 * 1_000,
        headers: { "privy-client": "payo-server" },
      }),
    };
  }
  return { appId, verificationKey: remoteVerificationKey.key };
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
    const { appId, verificationKey } = getPrivyVerification();
    const claim = await verifyAccessToken({
      access_token: accessToken,
      app_id: appId,
      verification_key: verificationKey,
    });
    return { principalId: claim.user_id, sessionId: claim.session_id };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(401, "The Privy access token is invalid or expired.", "AUTH_INVALID");
  }
}
