import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { verifyAccessTokenMock } = vi.hoisted(() => ({
  verifyAccessTokenMock: vi.fn(),
}));

vi.mock("@privy-io/node", () => ({
  verifyAccessToken: verifyAccessTokenMock,
}));

import { ApiError, requirePrincipal } from "./auth";

const originalAppId = process.env.NEXT_PUBLIC_PRIVY_APP_ID;
const originalVerificationKey = process.env.PRIVY_JWT_VERIFICATION_KEY;

describe("Privy server authentication", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_PRIVY_APP_ID = "test-app-id";
    process.env.PRIVY_JWT_VERIFICATION_KEY = "test-public-verification-key";
    verifyAccessTokenMock.mockReset();
  });

  afterEach(() => {
    if (originalAppId === undefined) delete process.env.NEXT_PUBLIC_PRIVY_APP_ID;
    else process.env.NEXT_PUBLIC_PRIVY_APP_ID = originalAppId;
    if (originalVerificationKey === undefined) delete process.env.PRIVY_JWT_VERIFICATION_KEY;
    else process.env.PRIVY_JWT_VERIFICATION_KEY = originalVerificationKey;
  });

  it("requires an access token before initializing verification", async () => {
    await expect(requirePrincipal(new Request("https://payo.test/api"))).rejects.toMatchObject({
      status: 401,
      code: "AUTH_REQUIRED",
    });
    expect(verifyAccessTokenMock).not.toHaveBeenCalled();
  });

  it("fails closed when the public Privy app ID is absent", async () => {
    delete process.env.NEXT_PUBLIC_PRIVY_APP_ID;
    await expect(requirePrincipal(new Request("https://payo.test/api", {
      headers: { authorization: "Bearer token" },
    }))).rejects.toMatchObject({ status: 503, code: "AUTH_NOT_CONFIGURED" });
  });

  it("verifies bearer tokens with the app-bound public verification key", async () => {
    verifyAccessTokenMock.mockResolvedValue({
      user_id: "did:privy:user",
      session_id: "session-1",
    });
    await expect(requirePrincipal(new Request("https://payo.test/api", {
      headers: { authorization: "Bearer valid-token" },
    }))).resolves.toEqual({ principalId: "did:privy:user", sessionId: "session-1" });
    expect(verifyAccessTokenMock).toHaveBeenCalledWith({
      access_token: "valid-token",
      app_id: "test-app-id",
      verification_key: "test-public-verification-key",
    });
  });

  it("accepts the Privy cookie and maps verification failures to AUTH_INVALID", async () => {
    verifyAccessTokenMock.mockRejectedValue(new Error("bad signature"));
    const failure = requirePrincipal(new Request("https://payo.test/api", {
      headers: { cookie: "other=x; privy-token=invalid-token" },
    }));
    await expect(failure).rejects.toBeInstanceOf(ApiError);
    await expect(failure).rejects.toMatchObject({ status: 401, code: "AUTH_INVALID" });
  });
});
