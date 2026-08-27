import { beforeEach, describe, expect, it, vi } from "vitest";

const { getDatabaseMock, limitMock } = vi.hoisted(() => ({
  getDatabaseMock: vi.fn(),
  limitMock: vi.fn(),
}));

vi.mock("@/lib/persistence/db", () => ({ getDatabase: getDatabaseMock }));

import { hashReadySessionToken, requirePrincipal } from "./auth";

describe("Ready session authentication", () => {
  beforeEach(() => {
    limitMock.mockReset();
    getDatabaseMock.mockReset();
    getDatabaseMock.mockReturnValue({
      select: () => ({
        from: () => ({
          where: () => ({ limit: limitMock }),
        }),
      }),
    });
  });

  it("requires a bearer token before touching the database", async () => {
    await expect(requirePrincipal(new Request("https://payo.test/api"))).rejects.toMatchObject({
      status: 401,
      code: "AUTH_REQUIRED",
    });
    expect(getDatabaseMock).not.toHaveBeenCalled();
  });

  it("does not accept the former Privy cookie", async () => {
    await expect(requirePrincipal(new Request("https://payo.test/api", {
      headers: { cookie: "privy-token=legacy" },
    }))).rejects.toMatchObject({ status: 401, code: "AUTH_REQUIRED" });
  });

  it("rejects expired, revoked or unknown session tokens", async () => {
    limitMock.mockResolvedValue([]);
    await expect(requirePrincipal(new Request("https://payo.test/api", {
      headers: { authorization: `Bearer ${"a".repeat(32)}` },
    }))).rejects.toMatchObject({ status: 401, code: "AUTH_INVALID" });
  });

  it("maps an active Ready session to its linked PAYO principal", async () => {
    limitMock.mockResolvedValue([{
      principalId: "did:legacy:payo-admin",
      sessionId: "0198-session",
      walletAddress: "0x0123",
      chainId: "0x534e5f4d41494e",
    }]);
    await expect(requirePrincipal(new Request("https://payo.test/api", {
      headers: { authorization: `Bearer ${"b".repeat(32)}` },
    }))).resolves.toEqual({
      principalId: "did:legacy:payo-admin",
      sessionId: "0198-session",
      walletAddress: "0x0123",
      chainId: "0x534e5f4d41494e",
    });
  });

  it("hashes bearer material deterministically without storing it directly", () => {
    expect(hashReadySessionToken("secret-session-token")).toMatch(/^[0-9a-f]{64}$/);
    expect(hashReadySessionToken("secret-session-token")).toBe(hashReadySessionToken("secret-session-token"));
    expect(hashReadySessionToken("other-session-token")).not.toBe(hashReadySessionToken("secret-session-token"));
  });
});
