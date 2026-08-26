import { hashCanonicalJson } from "@/lib/crypto/digest";
import { encryptVaultRecord, type VaultPrincipal } from "@/lib/crypto/vault";
import type { EncryptedPayrollIntegrityBundleCreate } from "@/lib/domain/proof-bundle";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  type PayrollIntegrityPublicInputs,
  type ProofWorkerSuccess,
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";

function canonicalDecimal(value: string): string {
  const parsed = BigInt(value);
  if (parsed < 0n) throw new Error("PayrollIntegrity public inputs cannot be negative.");
  return parsed.toString();
}

function canonicalFelt(value: string): string {
  const parsed = BigInt(value);
  if (parsed < 0n) throw new Error("PayrollIntegrity public inputs cannot be negative.");
  return `0x${parsed.toString(16)}`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function commonInputs(publicInputs: PayrollIntegrityPublicInputs) {
  return {
    chainId: canonicalFelt(publicInputs.chainId),
    sealAddress: canonicalFelt(publicInputs.sealAddress),
    proofVersion: canonicalDecimal(publicInputs.proofVersion),
    schemaVersion: canonicalDecimal(publicInputs.schemaVersion),
    agreementRootHigh: canonicalDecimal(publicInputs.agreementRootHigh),
    agreementRootLow: canonicalDecimal(publicInputs.agreementRootLow),
    manifestRootHigh: canonicalDecimal(publicInputs.manifestRootHigh),
    manifestRootLow: canonicalDecimal(publicInputs.manifestRootLow),
    policyRootHigh: canonicalDecimal(publicInputs.policyRootHigh),
    policyRootLow: canonicalDecimal(publicInputs.policyRootLow),
    fxRootHigh: canonicalDecimal(publicInputs.fxRootHigh),
    fxRootLow: canonicalDecimal(publicInputs.fxRootLow),
    runNullifierHigh: canonicalDecimal(publicInputs.runNullifierHigh),
    runNullifierLow: canonicalDecimal(publicInputs.runNullifierLow),
    validityStart: canonicalDecimal(publicInputs.validityStart),
    validityExpiry: canonicalDecimal(publicInputs.validityExpiry),
  };
}

export function prepareEncryptedPayrollIntegrityBundle(input: {
  id: string;
  organizationId: string;
  runId: string;
  revision: number;
  proof: ProofWorkerSuccess;
  subjectRecordId?: string;
  principals: readonly VaultPrincipal[];
}): EncryptedPayrollIntegrityBundleCreate {
  const [shardZero, shardOne] = input.proof.shards;
  if (shardZero.shardIndex !== 0 || shardOne.shardIndex !== 1) {
    throw new Error("PayrollIntegrity shards are not ordered.");
  }
  const common = commonInputs(shardZero.publicInputs);
  const profile = common.proofVersion === "1" ? {
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    verificationKeySha256: PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  } : common.proofVersion === "2" ? {
    circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
    verificationKeySha256: ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  } : common.proofVersion === "3" ? {
    circuitSha256: WAGE_CLAIM_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  } : common.proofVersion === "4" ? {
    circuitSha256: WAGE_REMEDIATION_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  } : undefined;
  if (!profile || input.proof.circuitSha256 !== profile.circuitSha256) {
    throw new Error("Proof worker returned an unpinned PAYO proof profile.");
  }
  const proofType = common.proofVersion === "3"
    ? "wage_claim" as const
    : common.proofVersion === "4"
      ? "wage_remediation" as const
      : "payroll_integrity" as const;
  const subjectRecordId = proofType === "payroll_integrity" ? input.runId : input.subjectRecordId;
  if (!subjectRecordId) throw new Error(`${proofType} requires its encrypted subject record.`);
  const other = commonInputs(shardOne.publicInputs);
  if (JSON.stringify(common) !== JSON.stringify(other)) {
    throw new Error("PayrollIntegrity shard public inputs do not match.");
  }
  if (BigInt(shardZero.publicInputs.shardIndex) !== 0n || BigInt(shardOne.publicInputs.shardIndex) !== 1n) {
    throw new Error("PayrollIntegrity public shard indices are invalid.");
  }
  for (const shard of input.proof.shards) {
    if (shard.proof.length === 0 || shard.proofCalldata.length === 0) {
      throw new Error(`PayrollIntegrity shard ${shard.shardIndex} is incomplete.`);
    }
    if (BigInt(hashProofCalldata(shard.proofCalldata)) !== BigInt(shard.calldataHash)) {
      throw new Error(`PayrollIntegrity shard ${shard.shardIndex} calldata hash is invalid.`);
    }
  }

  const privatePayload = {
    schemaVersion: 1,
    scheme: input.proof.scheme,
    circuitSha256: input.proof.circuitSha256,
    verificationKeySha256: profile.verificationKeySha256,
    provingTimeMs: input.proof.provingTimeMs,
    shards: input.proof.shards.map((shard) => ({
      shardIndex: shard.shardIndex,
      proofBase64: bytesToBase64(shard.proof),
      proofCalldata: shard.proofCalldata,
      calldataHash: shard.calldataHash,
      publicInputs: shard.publicInputs,
    })),
  };
  const envelope = encryptVaultRecord(
    privatePayload,
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "proof-bundle",
      recordId: input.id,
      revision: input.revision,
    },
    input.principals,
  );
  return {
    id: input.id,
    organizationId: input.organizationId,
    runId: input.runId,
    revision: input.revision,
    proofType,
    subjectRecordId,
    proofVersion: common.proofVersion,
    circuitSha256: profile.circuitSha256,
    verificationKeySha256: profile.verificationKeySha256,
    publicInputsHash: hashCanonicalJson([
      { ...common, shardIndex: "0" },
      { ...common, shardIndex: "1" },
    ]),
    commonInputs: common,
    shardCalldataHashes: [shardZero.calldataHash, shardOne.calldataHash],
    envelope,
  };
}
