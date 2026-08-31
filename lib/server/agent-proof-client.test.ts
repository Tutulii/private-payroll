import { describe, expect, it, vi } from "vitest";
import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  SETTLEMENT_MATCH_CIRCUIT_SHA256,
  SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { AgentProofClient } from "./agent-proof-client";

const requestId = "01a00000-0000-7000-8000-000000000001";
const encryptedWitness = {
  version: "payo-vault-record-v1",
} as unknown as EncryptedVaultRecord;
const principal = {
  principalId: "01a00000-0000-7000-8000-000000000002",
} as VaultPrincipalKeyPair;
const secret = "w".repeat(32);

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function settlementResult() {
  const settlementRoot = "0x" + "11".repeat(32);
  const transactionReference = "0x" + "22".repeat(32);
  const root = BigInt(settlementRoot);
  const reference = BigInt(transactionReference);
  const proofCalldata = ["0x1", "0x2"];
  return {
    version: 8,
    type: "settlement-proof-complete",
    requestId,
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: SETTLEMENT_MATCH_CIRCUIT_SHA256,
    verificationKeySha256: SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
    settlementRoot,
    transactionReference,
    provingTimeMs: 3,
    chunks: [{
      chunkIndex: 0,
      chunkCount: 1,
      proofCalldata,
      calldataHash: hashProofCalldata(proofCalldata),
      publicInputs: {
        proofVersion: "8",
        manifestRootHigh: "1",
        manifestRootLow: "2",
        runNullifierHigh: "3",
        runNullifierLow: "4",
        transactionReferenceHigh: (reference >> 128n).toString(),
        transactionReferenceLow: (reference & ((1n << 128n) - 1n)).toString(),
        settlementRootHigh: (root >> 128n).toString(),
        settlementRootLow: (root & ((1n << 128n) - 1n)).toString(),
        chunkIndex: "0",
        chunkCount: "1",
      },
    }],
  } as const;
}

function payrollResult() {
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
    shardIndex: "0",
  };
  return {
    version: 1,
    type: "proof-complete",
    requestId,
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    provingTimeMs: 2,
    shards: ([0, 1] as const).map((shardIndex) => ({
      shardIndex,
      proofBase64: "AA==",
      proofCalldata: ["0x1"],
      calldataHash: "0x1",
      publicInputs: { ...publicInputs, shardIndex: shardIndex.toString() },
    })),
  };
}

describe("agent proof client", () => {
  it("authenticates and decodes a payroll proof", async () => {
    const fetcher = vi.fn(async (_url, init) => {
      expect(init?.headers).toMatchObject({ authorization: "Bearer " + secret });
      expect(JSON.parse(String(init?.body))).toMatchObject({
        version: 1,
        type: "agent-payroll-proof",
        requestId,
      });
      return response(payrollResult());
    }) as unknown as typeof fetch;
    const client = new AgentProofClient("https://prover.example", secret, fetcher);
    const result = await client.payroll({ requestId, encryptedWitness, principal });
    expect(result).toMatchObject({
      type: "proof-complete",
      shards: [{ proof: new Uint8Array([0]) }, { proof: new Uint8Array([0]) }],
    });
  });

  it("returns null while a durable prover job is pending", async () => {
    const fetcher = vi.fn(async () => response({
      version: 1,
      type: "agent-proof-job",
      requestId,
      state: "processing",
      createdAt: "2026-08-31T00:00:00.000Z",
      updatedAt: "2026-08-31T00:00:01.000Z",
    }, 202)) as unknown as typeof fetch;
    const client = new AgentProofClient("https://prover.example", secret, fetcher);
    await expect(client.settlement({
      requestId,
      encryptedPayrollWitness: encryptedWitness,
      encryptedSettlementWitness: encryptedWitness,
      principal,
    })).resolves.toBeNull();
  });

  it("accepts only a fully bound SettlementMatch result", async () => {
    const fetcher = vi.fn(async () => response(settlementResult())) as unknown as typeof fetch;
    const client = new AgentProofClient("https://prover.example", secret, fetcher);
    await expect(client.settlement({
      requestId,
      encryptedPayrollWitness: encryptedWitness,
      encryptedSettlementWitness: encryptedWitness,
      principal,
    })).resolves.toMatchObject({
      type: "settlement-proof-complete",
      settlementRoot: "0x" + "11".repeat(32),
    });

    const tampered = settlementResult();
    const invalid = {
      ...tampered,
      chunks: [{
        ...tampered.chunks[0],
        calldataHash: "0x1",
      }],
    };
    const tamperedClient = new AgentProofClient(
      "https://prover.example",
      secret,
      (async () => response(invalid)) as typeof fetch,
    );
    await expect(tamperedClient.settlement({
      requestId,
      encryptedPayrollWitness: encryptedWitness,
      encryptedSettlementWitness: encryptedWitness,
      principal,
    })).rejects.toThrow("AGENT_SETTLEMENT_PROOF_BINDING_INVALID");
  });

  it("rejects plaintext remote prover transport and weak credentials", () => {
    expect(() => new AgentProofClient("http://prover.example", secret)).toThrow(/HTTPS/);
    expect(() => new AgentProofClient("https://prover.example", "weak")).toThrow(/authorize/);
  });
});
