import { describe, expect, it } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  encryptedExceptionProofBundleCreateSchema,
  encryptedPayrollIntegrityBundleCreateSchema,
} from "@/lib/domain/proof-bundle";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
  type ExceptionProofWorkerSuccess,
  mapPayrollPublicInputs,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import {
  prepareEncryptedExceptionProofBundle,
  prepareEncryptedPayrollIntegrityBundle,
} from "./proof-bundle";

const ORGANIZATION_ID = "0198d3a4-1280-7abc-8def-0123456789ab";
const RUN_ID = "0198d3a4-1281-7abc-8def-0123456789ab";
const BUNDLE_ID = "0198d3a4-1282-7abc-8def-0123456789ab";
const CLAIM_ID = "0198d3a4-1283-7abc-8def-0123456789ab";

function proof(input: { version?: number; circuitSha256?: string; calldataLength?: number } = {}): ProofWorkerSuccess {
  const version = input.version ?? 1;
  const common = [
    "1", "0x12345", String(version), "1",
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "1000", "2000",
  ];
  const calldataLength = input.calldataLength ?? 2;
  const shardCalldata = ([0, 1] as const).map((shardIndex) =>
    Array.from({ length: calldataLength }, (_, index) => `0x${(index + 1 + shardIndex * 2).toString(16)}`));
  return {
    version: 1,
    type: "proof-complete",
    requestId: "request-1",
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: input.circuitSha256 ?? PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    provingTimeMs: 123,
    shards: [0, 1].map((shardIndex) => ({
      shardIndex: shardIndex as 0 | 1,
      proof: Uint8Array.of(shardIndex + 1, 2, 3),
      proofCalldata: shardCalldata[shardIndex],
      calldataHash: hashProofCalldata(shardCalldata[shardIndex]),
      publicInputs: mapPayrollPublicInputs([...common, String(shardIndex)]),
    })) as ProofWorkerSuccess["shards"],
  };
}

describe("encrypted PayrollIntegrity proof bundle", () => {
  it("stores proof bytes and verifier calldata only inside the authenticated vault envelope", () => {
    const principal = generateVaultPrincipal("principal-1");
    const result = prepareEncryptedPayrollIntegrityBundle({
      id: BUNDLE_ID,
      organizationId: ORGANIZATION_ID,
      runId: RUN_ID,
      revision: 1,
      proof: proof(),
      principals: [principal],
    });
    expect(() => encryptedPayrollIntegrityBundleCreateSchema.parse(result)).not.toThrow();
    expect(JSON.stringify(result)).not.toContain("proofBase64");
    expect(JSON.stringify(result)).not.toContain('"proofCalldata"');
    expect(result.envelope.aad).toMatchObject({
      organizationId: ORGANIZATION_ID,
      recordType: "proof-bundle",
      recordId: BUNDLE_ID,
      revision: 1,
    });

    const decrypted = decryptVaultRecord<{
      shards: Array<{ proofBase64: string; proofCalldata: string[] }>;
    }>(result.envelope, principal);
    expect(decrypted.shards[0].proofBase64).toBe("AQID");
    expect(decrypted.shards[1].proofCalldata).toEqual(["0x3", "0x4"]);
  });

  it("fails closed if worker calldata was modified after hashing", () => {
    const principal = generateVaultPrincipal("principal-1");
    const tampered = proof();
    tampered.shards[0].proofCalldata[0] = "0x99";
    expect(() => prepareEncryptedPayrollIntegrityBundle({
      id: BUNDLE_ID,
      organizationId: ORGANIZATION_ID,
      runId: RUN_ID,
      revision: 1,
      proof: tampered,
      principals: [principal],
    })).toThrow("calldata hash is invalid");
  });

  it("persists the pinned merged-v2 profile at its measured Mainnet-safe calldata size", () => {
    const principal = generateVaultPrincipal("principal-1");
    const result = prepareEncryptedPayrollIntegrityBundle({
      id: BUNDLE_ID,
      organizationId: ORGANIZATION_ID,
      runId: RUN_ID,
      revision: 1,
      proof: proof({
        version: 2,
        circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
        calldataLength: 3_223,
      }),
      principals: [principal],
    });
    expect(result.circuitSha256).toBe(ADVANCED_OBLIGATION_CIRCUIT_SHA256);
    expect(result.verificationKeySha256).toBe(ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256);
    expect(() => encryptedPayrollIntegrityBundleCreateSchema.parse(result)).not.toThrow();
  }, 15_000);
});

describe("encrypted vNext exception proof bundle", () => {
  function claimProof(): ExceptionProofWorkerSuccess {
    const proofCalldata = ["0x1", "0x2"];
    return {
      version: 2,
      type: "exception-proof-complete",
      requestId: "request-v6",
      profile: "wage_claim_v6",
      scheme: "ultra_keccak_zk_honk",
      circuitSha256: WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
      provingTimeMs: 234,
      proof: {
        proof: Uint8Array.of(4, 5, 6),
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs: {
          chainId: "1",
          sealAddress: "0x12345",
          proofVersion: "6",
          schemaVersion: "2",
          agreementRootHigh: "1",
          agreementRootLow: "2",
          manifestRootHigh: "3",
          manifestRootLow: "4",
          policyRootHigh: "5",
          policyRootLow: "6",
          fxRootHigh: "7",
          fxRootLow: "8",
          subjectNullifierHigh: "9",
          subjectNullifierLow: "10",
          parentNullifierHigh: "11",
          parentNullifierLow: "12",
          factCommitmentHigh: "13",
          factCommitmentLow: "14",
          parentFactCommitmentHigh: "15",
          parentFactCommitmentLow: "16",
          validityStart: "1000",
          validityExpiry: "2000",
          shardIndex: "0",
        },
      },
    };
  }

  it("publishes only v6 commitments while encrypting proof calldata and bytes", () => {
    const principal = generateVaultPrincipal("worker-claim-principal");
    const result = prepareEncryptedExceptionProofBundle({
      id: BUNDLE_ID,
      organizationId: ORGANIZATION_ID,
      runId: RUN_ID,
      subjectRecordId: CLAIM_ID,
      revision: 1,
      proof: claimProof(),
      principals: [principal],
    });
    expect(() => encryptedExceptionProofBundleCreateSchema.parse(result)).not.toThrow();
    expect(result).toMatchObject({
      proofType: "wage_claim",
      proofVersion: "6",
      subjectRecordId: CLAIM_ID,
    });
    expect(JSON.stringify(result)).not.toContain("proofBase64");
    expect(JSON.stringify(result)).not.toContain('"proofCalldata"');
    const decrypted = decryptVaultRecord<{
      schemaVersion: number;
      profile: string;
      proof: { proofBase64: string; proofCalldata: string[] };
    }>(result.envelope, principal);
    expect(decrypted).toMatchObject({
      schemaVersion: 2,
      profile: "wage_claim_v6",
      proof: { proofBase64: "BAUG", proofCalldata: ["0x1", "0x2"] },
    });
  });

  it("rejects mutation after the proof calldata was committed", () => {
    const principal = generateVaultPrincipal("worker-claim-principal");
    const tampered = claimProof();
    tampered.proof.proofCalldata[0] = "0x9";
    expect(() => prepareEncryptedExceptionProofBundle({
      id: BUNDLE_ID,
      organizationId: ORGANIZATION_ID,
      runId: RUN_ID,
      subjectRecordId: CLAIM_ID,
      revision: 1,
      proof: tampered,
      principals: [principal],
    })).toThrow(/calldata hash is invalid/);
  });
});
