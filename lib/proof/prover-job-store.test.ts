import { afterEach, describe, expect, it, vi } from "vitest";
import type { RemoteProofRequest } from "./remote-prover";
import {
  agentProofJobNamespace,
  enqueueProverJob,
  getProverJob,
  resetProverJobsForTests,
} from "./prover-job-store";

function request(requestId: string, ciphertext = "ciphertext"): RemoteProofRequest {
  return {
    version: 1,
    requestId,
    encryptedWitness: {
      version: 1,
      algorithm: "XCHACHA20-POLY1305+X25519-HKDF-SHA256",
      aad: {
        schemaVersion: 1,
        organizationId: "organization-1",
        recordType: "payroll-proof-request",
        recordId: requestId,
        revision: 1,
      },
      nonce: "nonce-nonce-nonce",
      ciphertext,
      wrappedKeys: [{
        principalId: "principal-1",
        ephemeralPublicKey: "ephemeral-public-key",
        nonce: "wrapped-nonce-value",
        ciphertext: "wrapped-ciphertext-value",
      }],
    },
    principal: {
      principalId: "principal-1",
      publicKey: "principal-public-key",
      secretKey: "principal-secret-key",
    },
  };
}

function result(requestId: string) {
  return {
    version: 1,
    type: "proof-complete",
    requestId,
    scheme: "ultra_keccak_zk_honk",
    shards: [],
    circuitSha256: "0x" + "11".repeat(32),
    provingTimeMs: 42,
  } as never;
}

afterEach(() => {
  resetProverJobsForTests();
  vi.restoreAllMocks();
});

describe("remote prover job store", () => {
  it("isolates payroll and settlement jobs that share one execution ID", () => {
    const principalId = "principal-1";
    expect(agentProofJobNamespace("agent-payroll-proof", principalId)).not.toBe(
      agentProofJobNamespace("agent-settlement-proof", principalId),
    );
  });

  it("deduplicates retries and retains the completed result", async () => {
    vi.spyOn(console, "info").mockImplementation(() => undefined);
    let resolveProof!: (value: ReturnType<typeof result>) => void;
    const run = vi.fn(() => new Promise<ReturnType<typeof result>>((resolve) => {
      resolveProof = resolve;
    }));
    const proofRequest = request("0198ddf0-9c00-7000-8000-000000000001");

    enqueueProverJob({ principalId: "principal-1", request: proofRequest, run });
    expect(getProverJob("principal-1", proofRequest.requestId)?.state).toBe("processing");
    expect(enqueueProverJob({ principalId: "principal-1", request: proofRequest, run }).state)
      .toBe("processing");
    expect(run).toHaveBeenCalledTimes(1);

    resolveProof(result(proofRequest.requestId));
    await vi.waitFor(() => expect(getProverJob("principal-1", proofRequest.requestId)?.state).toBe("complete"));
    expect(getProverJob("principal-1", proofRequest.requestId)?.result?.provingTimeMs).toBe(42);
    expect(getProverJob("different-principal", proofRequest.requestId)).toBeUndefined();
  });

  it("rejects request ID reuse with different encrypted input", () => {
    vi.spyOn(console, "info").mockImplementation(() => undefined);
    const requestId = "0198ddf0-9c00-7000-8000-000000000002";
    enqueueProverJob({
      principalId: "principal-1",
      request: request(requestId),
      run: async () => result(requestId),
    });

    expect(() => enqueueProverJob({
      principalId: "principal-1",
      request: request(requestId, "different-ciphertext"),
      run: async () => result(requestId),
    })).toThrow("PROVER_REQUEST_ID_REUSED");
  });

  it("serializes proof generation so two WASM provers cannot exhaust the machine", async () => {
    vi.spyOn(console, "info").mockImplementation(() => undefined);
    let resolveFirst!: (value: ReturnType<typeof result>) => void;
    const firstId = "0198ddf0-9c00-7000-8000-000000000003";
    const secondId = "0198ddf0-9c00-7000-8000-000000000004";
    enqueueProverJob({
      principalId: "principal-1",
      request: request(firstId),
      run: () => new Promise((resolve) => {
        resolveFirst = resolve;
      }),
    });
    const secondRun = vi.fn(async () => result(secondId));
    enqueueProverJob({
      principalId: "principal-1",
      request: request(secondId),
      run: secondRun,
    });

    expect(getProverJob("principal-1", secondId)?.state).toBe("queued");
    expect(secondRun).not.toHaveBeenCalled();
    resolveFirst(result(firstId));
    await vi.waitFor(() => expect(getProverJob("principal-1", secondId)?.state).toBe("complete"));
    expect(secondRun).toHaveBeenCalledTimes(1);
  });
});
