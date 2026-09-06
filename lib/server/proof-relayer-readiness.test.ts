import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  requirePrincipal: vi.fn(), getChainId: vi.fn(), callContract: vi.fn(),
}));
vi.mock("@/lib/server/auth", async (original) => ({
  ...await original<typeof import("@/lib/server/auth")>(), requirePrincipal: mocks.requirePrincipal,
}));
vi.mock("starknet", async (original) => ({
  ...await original<typeof import("starknet")>(),
  RpcProvider: class { getChainId = mocks.getChainId; callContract = mocks.callContract; },
}));
vi.mock("@/lib/server/payo-deployment", () => ({
  getPayoDeploymentConfig: () => ({ chainId: "0x1" }),
}));
import { GET } from "@/app/api/v1/proof-relayer-readiness/route";
import { ApiError } from "./auth";

afterEach(() => { vi.resetAllMocks(); vi.unstubAllEnvs(); });
function setup() {
  vi.stubEnv("STARKNET_RPC_URL", "https://rpc.example");
  vi.stubEnv("PAYO_PROOF_RELAYER_ADDRESS", "0x123");
  vi.stubEnv("PAYO_PROOF_RELAYER_PRIVATE_KEY", "test-only");
  vi.stubEnv("PAYO_PROOF_RELAYER_MIN_BALANCE_FRI", "100");
  mocks.requirePrincipal.mockResolvedValue({ principalId: "operator" });
  mocks.getChainId.mockResolvedValue("0x1");
}

describe("proof service admission", () => {
  it.each([["99", false], ["100", true]])("checks the live reserve at %s", async (balance, ready) => {
    setup();
    mocks.callContract.mockResolvedValue([balance, "0"]);
    const response = await GET(new Request("https://payo.example/api/v1/proof-relayer-readiness"));
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ readiness: { ready } });
    expect(response.headers.get("cache-control")).toContain("no-store");
  });
  it("requires authentication before making balance queries", async () => {
    setup();
    mocks.requirePrincipal.mockRejectedValue(new ApiError(401, "Unauthorized", "UNAUTHORIZED"));
    const response = await GET(new Request("https://payo.example/api/v1/proof-relayer-readiness"));
    expect(response.status).toBe(401);
    expect(mocks.callContract).not.toHaveBeenCalled();
  });
  it("refuses an RPC connected to another chain", async () => {
    setup();
    mocks.getChainId.mockResolvedValue("0x2");
    const response = await GET(new Request("https://payo.example/api/v1/proof-relayer-readiness"));
    expect(response.status).toBe(503);
    expect(mocks.callContract).not.toHaveBeenCalled();
  });
});
