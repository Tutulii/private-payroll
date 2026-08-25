import { describe, expect, it } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { encryptedPayrollIntegrityBundleCreateSchema } from "@/lib/domain/proof-bundle";
import {
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  mapPayrollPublicInputs,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { prepareEncryptedPayrollIntegrityBundle } from "./proof-bundle";

const ORGANIZATION_ID = "0198d3a4-1280-7abc-8def-0123456789ab";
const RUN_ID = "0198d3a4-1281-7abc-8def-0123456789ab";
const BUNDLE_ID = "0198d3a4-1282-7abc-8def-0123456789ab";

function proof(): ProofWorkerSuccess {
  const common = [
    "1", "0x12345", "1", "1",
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "1000", "2000",
  ];
  const shardCalldata = [["0x1", "0x2"], ["0x3", "0x4"]] as const;
  return {
    version: 1,
    type: "proof-complete",
    requestId: "request-1",
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    provingTimeMs: 123,
    shards: [0, 1].map((shardIndex) => ({
      shardIndex: shardIndex as 0 | 1,
      proof: Uint8Array.of(shardIndex + 1, 2, 3),
      proofCalldata: [...shardCalldata[shardIndex]],
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
});
