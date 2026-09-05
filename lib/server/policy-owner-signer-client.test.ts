import { randomUUID } from "node:crypto";
import type { Call, InvocationsSignerDetails } from "starknet";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PolicyOwnerSignerClient } from "./policy-owner-signer-client";

const expectedPublicKey = "0x123";
const secret = "s".repeat(64);
const call: Call = {
  contractAddress: "0x222",
  entrypoint: "compile_actions",
  calldata: ["0x111", "0x444", "0x1", "0x3", "0x777", "0x888", "0xabc", "0x64", "0x0", "0x999"],
};
const details = {
  walletAddress: "0x222",
  cairoVersion: "1",
  chainId: "0x534e5f4d41494e",
  version: "0x3",
  nonce: 0n,
  resourceBounds: {
    l1_gas: { max_amount: 1n, max_price_per_unit: 0n },
    l2_gas: { max_amount: 100_000_000n, max_price_per_unit: 0n },
    l1_data_gas: { max_amount: 1n, max_price_per_unit: 0n },
  },
  tip: 0n,
  paymasterData: [],
  accountDeploymentData: [],
  nonceDataAvailabilityMode: "L1",
  feeDataAvailabilityMode: "L1",
  skipValidate: true,
} as InvocationsSignerDetails;

function client() {
  return new PolicyOwnerSignerClient({
    url: "http://payo-policy-signer.internal:3000",
    secret,
    expectedPublicKey,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("policy-owner signer client", () => {
  it("sends an authenticated proof request and accepts only a bound response", async () => {
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      const request = JSON.parse(String(init.body));
      const headers = init.headers as Record<string, string>;
      expect(headers["x-payo-signer-authorization"]).toMatch(/^[0-9a-f]{64}$/);
      expect(headers["x-payo-signer-nonce"]).toMatch(/^[0-9a-f]{32}$/);
      return Response.json({
        version: "payo-policy-signer-response-v1",
        requestId: request.requestId,
        signerPublicKey: expectedPublicKey,
        signature: ["0x1", "0x2"],
      });
    }));
    await expect(client().signTransaction([call], details)).resolves.toEqual(["0x1", "0x2"]);
  });

  it("rejects signer substitution and unsupported signer methods", async () => {
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      const request = JSON.parse(String(init.body));
      return Response.json({
        version: "payo-policy-signer-response-v1",
        requestId: request.requestId,
        signerPublicKey: "0x999",
        signature: ["0x1", "0x2"],
      });
    }));
    await expect(client().signTransaction([call], details)).rejects.toThrow("not bound");
    await expect(client().signMessage({} as never, "0x1")).rejects.toThrow("does not sign messages");
    await expect(client().signDeployAccountTransaction({} as never)).rejects.toThrow("does not sign deployments");
    await expect(client().signDeclareTransaction({} as never)).rejects.toThrow("does not sign declarations");
  });

  it("returns only the signer-bound read-only policy estimate", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      expect(url).toContain("/v1/estimate-policy");
      const request = JSON.parse(String(init.body));
      return Response.json({
        version: "payo-policy-configuration-estimate-response-v1",
        requestId: request.requestId,
        signerPublicKey: expectedPublicKey,
        blockNumber: 42,
        blockHash: "0xabc",
        estimatedFeeFri: "123",
        replayed: false,
      });
    }));
    const configuration: Call = {
      contractAddress: "0x111",
      entrypoint: "configure_policy",
      calldata: Array.from({ length: 20 }, (_value, index) => `0x${(index + 1).toString(16)}`),
    };
    await expect(client().estimatePolicy(configuration)).resolves.toEqual({
      blockNumber: 42,
      blockHash: "0xabc",
      estimatedFeeFri: "123",
      replayed: false,
    });
  });

  it("accepts an idempotent policy-configuration response without inventing a transaction hash", async () => {
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      const request = JSON.parse(String(init.body));
      return Response.json({
        version: "payo-policy-configuration-response-v1",
        requestId: request.requestId,
        signerPublicKey: expectedPublicKey,
        transactionHash: null,
        replayed: true,
      });
    }));
    const configuration: Call = {
      contractAddress: "0x111",
      entrypoint: "configure_policy",
      calldata: Array.from({ length: 20 }, (_value, index) => `0x${(index + 1).toString(16)}`),
    };
    await expect(client().configurePolicy(configuration)).resolves.toEqual({ replayed: true });
  });

  it("rejects an unsafe transport or a weak shared secret", () => {
    expect(() => new PolicyOwnerSignerClient({
      url: "http://public.example.com",
      secret,
      expectedPublicKey,
    })).toThrow("HTTPS or a private/local HTTP endpoint");
    expect(() => new PolicyOwnerSignerClient({
      url: "http://localhost:3000",
      secret: randomUUID(),
      expectedPublicKey,
    })).not.toThrow();
    expect(() => new PolicyOwnerSignerClient({
      url: "http://localhost:3000",
      secret: "short",
      expectedPublicKey,
    })).toThrow("too short");
  });

  it("fails closed when only the legacy fee-relayer key is configured", () => {
    vi.stubEnv("PAYO_POLICY_SIGNER_URL", "");
    vi.stubEnv("PAYO_POLICY_SIGNER_SECRET", "");
    vi.stubEnv("PAYO_POLICY_SIGNER_PUBLIC_KEY", "");
    vi.stubEnv("PAYO_PROOF_RELAYER_PRIVATE_KEY", "0x123456");
    expect(() => PolicyOwnerSignerClient.fromEnvironment()).toThrow(
      "isolated PAYO policy signer is not configured",
    );
  });
});
