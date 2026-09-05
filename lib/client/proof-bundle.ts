import { hashCanonicalJson } from "@/lib/crypto/digest";
import { encryptVaultRecord, type VaultPrincipal } from "@/lib/crypto/vault";
import type {
  EncryptedExceptionProofBundleCreate,
  EncryptedPayrollIntegrityBundleCreate,
  ExceptionAuthorizationRequest,
} from "@/lib/domain/proof-bundle";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256,
  OBLIGATION_SNAPSHOT_LINK_VERIFICATION_KEY_SHA256,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  type PayrollIntegrityPublicInputs,
  type ExceptionProofWorkerSuccess,
  type ProofWorkerSuccess,
  type VestingBookProof,
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
  WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256,
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
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
      publicInputs: {
        ...shard.publicInputs,
        chainId: canonicalFelt(shard.publicInputs.chainId),
        sealAddress: canonicalFelt(shard.publicInputs.sealAddress),
      },
    })),
    ...(input.proof.vestingBook
      ? { vestingBook: prepareVestingBookProofSubmission(input.proof.vestingBook) }
      : {}),
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

export function prepareVestingBookProofSubmission(
  proof: VestingBookProof,
): ExceptionAuthorizationRequest["vestingBook"] {
  if (proof.circuitSha256 !== VESTING_TRANSITION_CIRCUIT_SHA256
    || proof.verificationKeySha256 !== VESTING_TRANSITION_VERIFICATION_KEY_SHA256) {
    throw new Error("The payroll-book proof does not use PAYO's pinned v3 artifacts.");
  }
  return {
    proofVersion: proof.proofVersion,
    entryKind: proof.entryKind,
    circuitSha256: VESTING_TRANSITION_CIRCUIT_SHA256,
    verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
    scheduleId: proof.scheduleId,
    previousStateCommitment: proof.previousStateCommitment,
    nextStateCommitment: proof.nextStateCommitment,
    releaseNullifier: proof.releaseNullifier,
    bookEntry: proof.bookEntry,
    bookEntryCommitment: proof.bookEntryCommitment,
    shards: proof.shards.map((shard) => ({
      shardIndex: shard.shardIndex,
      proofCalldata: shard.proofCalldata,
      calldataHash: shard.calldataHash,
      publicInputs: {
        ...shard.publicInputs,
        chainId: canonicalFelt(shard.publicInputs.chainId),
        sealAddress: canonicalFelt(shard.publicInputs.sealAddress),
      },
    })) as ExceptionAuthorizationRequest["vestingBook"]["shards"],
  };
}

export function prepareEncryptedExceptionProofBundle(input: {
  id: string;
  organizationId: string;
  runId: string;
  revision: number;
  proof: ExceptionProofWorkerSuccess;
  subjectRecordId?: string;
  principals: readonly VaultPrincipal[];
}): EncryptedExceptionProofBundleCreate {
  const profile = input.proof.profile === "obligation_snapshot_v5" ? {
    proofType: "obligation_snapshot" as const,
    proofVersion: "5" as const,
    circuitSha256: OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256,
    verificationKeySha256: OBLIGATION_SNAPSHOT_LINK_VERIFICATION_KEY_SHA256,
  } : input.proof.profile === "wage_claim_v6" ? {
    proofType: "wage_claim" as const,
    proofVersion: "6" as const,
    circuitSha256: WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256,
  } : {
    proofType: "wage_remediation" as const,
    proofVersion: "7" as const,
    circuitSha256: WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256,
  };
  if (input.proof.circuitSha256 !== profile.circuitSha256) {
    throw new Error("Exception proof worker returned an unpinned PAYO profile.");
  }
  const subjectRecordId = profile.proofType === "obligation_snapshot"
    ? input.runId
    : input.subjectRecordId;
  if (!subjectRecordId) throw new Error(`${profile.proofType} requires its encrypted subject record.`);
  const proof = input.proof.proof;
  if (!proof.proof.length || !proof.proofCalldata.length) {
    throw new Error("The vNext exception proof is incomplete.");
  }
  const calculatedHash = hashProofCalldata(proof.proofCalldata);
  if (BigInt(calculatedHash) !== BigInt(proof.calldataHash)) {
    throw new Error("The vNext exception proof calldata hash is invalid.");
  }
  const publicInputs = Object.fromEntries(Object.entries(proof.publicInputs).map(([key, value]) => [
    key,
    key === "chainId" || key === "sealAddress" ? canonicalFelt(value) : canonicalDecimal(value),
  ])) as typeof proof.publicInputs;
  if (
    publicInputs.proofVersion !== profile.proofVersion
    || publicInputs.schemaVersion !== "2"
    || publicInputs.shardIndex !== "0"
  ) throw new Error("The exception proof returned the wrong versioned public-input ABI.");
  if (profile.proofType === "obligation_snapshot" && input.proof.vestingBook) {
    throw new Error("An obligation snapshot cannot carry a payroll-book proof.");
  }
  if (profile.proofType !== "obligation_snapshot" && !input.proof.vestingBook) {
    throw new Error("Claim and remediation proofs require their universal payroll-book proof.");
  }
  const privatePayload = {
    schemaVersion: 2,
    scheme: input.proof.scheme,
    profile: input.proof.profile,
    circuitSha256: input.proof.circuitSha256,
    verificationKeySha256: profile.verificationKeySha256,
    provingTimeMs: input.proof.provingTimeMs,
    proof: {
      proofBase64: bytesToBase64(proof.proof),
      proofCalldata: proof.proofCalldata,
      calldataHash: proof.calldataHash,
      publicInputs,
    },
    ...(input.proof.vestingBook
      ? { vestingBook: prepareVestingBookProofSubmission(input.proof.vestingBook) }
      : {}),
  };
  const envelope = encryptVaultRecord(privatePayload, {
    schemaVersion: 1,
    organizationId: input.organizationId,
    recordType: "proof-bundle",
    recordId: input.id,
    revision: input.revision,
  }, input.principals);
  return {
    id: input.id,
    organizationId: input.organizationId,
    runId: input.runId,
    revision: input.revision,
    proofType: profile.proofType,
    subjectRecordId,
    proofVersion: profile.proofVersion,
    circuitSha256: profile.circuitSha256,
    verificationKeySha256: profile.verificationKeySha256,
    publicInputsHash: hashCanonicalJson(publicInputs),
    publicInputs,
    proofCalldataHash: calculatedHash,
    envelope,
  };
}
