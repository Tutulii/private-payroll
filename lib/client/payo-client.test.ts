import { afterEach, describe, expect, it, vi } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { deriveRunNullifier } from "@/lib/crypto/commitments";
import type { SerializedPayrollIntegrityBuildRequest } from "@/lib/proof/input-builder";
import { PayoClient, prepareEncryptedPayrollRun } from "./payo-client";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("client-encrypted payroll preparation", () => {
  it("commits and encrypts salary data before API transport", () => {
    const principal = generateVaultPrincipal("owner");
    const organizationSecret = `0x${"44".repeat(32)}`;
    const runNullifier = deriveRunNullifier({ organizationSecret, cycleId: "2026-08", revision: 1 });
    const runId = "0198ddf0-9c00-7000-8000-000000000001";
    const organizationId = "0198ddf0-9c00-7000-8000-000000000002";
    const agreementId = "0198ddf0-9c00-7000-8000-000000000003";
    const payeeId = "0198ddf0-9c00-7000-8000-000000000004";
    const prepared = prepareEncryptedPayrollRun({
      id: runId,
      organizationId,
      cycleId: "2026-08",
      revision: 1,
      dueAt: "2026-08-27T00:00:00.000Z",
      organizationSecret,
      principals: [principal],
      proofBinding: {
        agreementRoot: `0x${"aa".repeat(32)}`,
        manifestRoot: `0x${"bb".repeat(32)}`,
        policyRoot: `0x${"cc".repeat(32)}`,
        fxRoot: `0x${"dd".repeat(32)}`,
        runNullifier,
      },
      claimProofSource: { buildInput: {} as SerializedPayrollIntegrityBuildRequest },
      lineRecordMetadata: [{
        agreementId,
        payeeId,
        recipientCommitment: `0x${"33".repeat(32)}`,
        policyCommitment: `0x${"55".repeat(32)}`,
      }],
      lines: [{
        agreementId,
        recipientAddress: "0x123",
        token: "STRK",
        earningsAtomic: ["1000000000000000000"],
        deductionsAtomic: ["100000000000000000"],
        committedPolicyId: "policy-us-reference-v1",
        scheduleCommitment: `0x${"11".repeat(32)}`,
        salt: `0x${"22".repeat(32)}`,
      }],
    });
    const wire = JSON.stringify(prepared);
    expect(wire).not.toContain(agreementId);
    expect(wire).not.toContain("1000000000000000000");

    const decrypted = decryptVaultRecord<{ manifest: { lines: Array<{ agreementId: string }> } }>(
      prepared.envelope,
      principal,
    );
    expect(decrypted.manifest.lines[0].agreementId).toBe(agreementId);
    expect(prepared.lineRecords).toHaveLength(1);
    const privateLine = decryptVaultRecord<{ agreementId: string; payeeId: string; netAtomic: string }>(
      prepared.lineRecords[0].envelope,
      principal,
    );
    expect(privateLine).toMatchObject({ agreementId, payeeId, netAtomic: "900000000000000000" });
    expect(prepared.agreementRoot).toBe(`0x${"aa".repeat(32)}`);
    expect(prepared.manifestRoot).toBe(`0x${"bb".repeat(32)}`);
  });
});

describe("remote prover recovery", () => {
  const requestId = "0198ddf0-9c00-7000-8000-000000000001";
  const encryptedWitness = { aad: { recordId: requestId } } as never;

  it("retries an opaque fetch failure before reporting an actionable connection error", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("window", { setTimeout, clearTimeout });
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    vi.stubGlobal("fetch", fetchMock);
    const client = new PayoClient(async () => "a".repeat(64));

    const request = client.provePayrollIntegrityRemotely({
      proverBaseUrl: "https://private-payroll.fly.dev",
      encryptedWitness,
      principal: {} as never,
    });
    const assertion = expect(request).rejects.toMatchObject({
      code: "PROVER_FETCH_FAILED",
      status: 0,
      message: expect.stringContaining("after three connection attempts"),
    });
    await vi.advanceTimersByTimeAsync(3_000);
    await assertion;
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("recovers a completed proof through short authenticated job polls", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("window", { setTimeout, clearTimeout });
    const publicInputs = {
      chainId: "1",
      sealAddress: "2",
      proofVersion: "1",
      schemaVersion: "1",
      agreementRootHigh: "3",
      agreementRootLow: "4",
      manifestRootHigh: "5",
      manifestRootLow: "6",
      policyRootHigh: "7",
      policyRootLow: "8",
      fxRootHigh: "9",
      fxRootLow: "10",
      runNullifierHigh: "11",
      runNullifierLow: "12",
      validityStart: "13",
      validityExpiry: "14",
    };
    const job = {
      version: 2,
      type: "proof-job",
      requestId,
      state: "processing",
      createdAt: "2026-08-27T00:00:00.000Z",
      updatedAt: "2026-08-27T00:00:01.000Z",
    };
    const proof = {
      version: 1,
      type: "proof-complete",
      requestId,
      scheme: "ultra_keccak_zk_honk",
      circuitSha256: "0x" + "11".repeat(32),
      provingTimeMs: 10,
      shards: ([0, 1] as const).map((shardIndex) => ({
        shardIndex,
        proofBase64: "AA==",
        proofCalldata: ["0x1"],
        calldataHash: "0x1",
        publicInputs: { ...publicInputs, shardIndex: shardIndex.toString() },
      })),
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(Response.json(job, { status: 202 }))
      .mockResolvedValueOnce(Response.json(job, { status: 202 }))
      .mockResolvedValueOnce(Response.json(proof));
    vi.stubGlobal("fetch", fetchMock);
    const client = new PayoClient(async () => "a".repeat(64));

    const request = client.provePayrollIntegrityRemotely({
      proverBaseUrl: "https://private-payroll-prover.fly.dev",
      encryptedWitness,
      principal: {} as never,
    });
    const assertion = expect(request).resolves.toMatchObject({ requestId, provingTimeMs: 10 });
    await vi.advanceTimersByTimeAsync(6_000);
    await assertion;
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ method: "POST" });
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({ method: "GET" });
  });
});

describe("PAYO API response recovery", () => {
  it("ends a hung vault read at the shared request deadline", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockImplementation((_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
      }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new PayoClient(async () => "a".repeat(64));

    const request = client.getPayrollFxCatalog({
      organizationId: "0198ddf0-9c00-7000-8000-000000000002",
      medianTokens: ["STRK"],
      protectedTokens: [],
    });
    const assertion = expect(request).rejects.toMatchObject({
      code: "PAYO_API_TIMEOUT",
      status: 504,
    });
    await vi.advanceTimersByTimeAsync(13_000);
    await assertion;
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries a safe FX catalog read after Fly returns an empty successful response", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("", { status: 200 }))
      .mockResolvedValueOnce(Response.json({
        snapshots: [],
        catalogRoot: `0x${"11".repeat(32)}`,
        publicationWindow: { observedAt: 1, maximumAgeSeconds: 60, expiresAt: 61 },
        publicationTicket: "ticket",
        sourceBlocks: { protected: null, median: 1 },
      }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new PayoClient(async () => "a".repeat(64));

    const result = await client.getPayrollFxCatalog({
      organizationId: "0198ddf0-9c00-7000-8000-000000000002",
      medianTokens: ["STRK"],
      protectedTokens: [],
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.catalogRoot).toBe(`0x${"11".repeat(32)}`);
  });

  it("reports an actionable typed error instead of exposing a JSON parser failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => new Response("", { status: 200 })));
    const client = new PayoClient(async () => "a".repeat(64));

    await expect(client.getPayrollFxCatalog({
      organizationId: "0198ddf0-9c00-7000-8000-000000000002",
      medianTokens: ["STRK"],
      protectedTokens: [],
    })).rejects.toMatchObject({
      code: "PAYO_API_EMPTY_RESPONSE",
      status: 502,
      message: expect.stringContaining("safe to retry"),
    });
  });
});
