import { z } from "zod";
import { fromBase64 } from "@/lib/crypto/encoding";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { decryptVaultRecord, type VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  payrollIntegrityBundleMetadataSchema,
  payrollIntegrityCommonInputsSchema,
  payrollProofCalldataSchema,
  starknetFeltSchema,
  vestingBookProofSubmissionSchema,
} from "@/lib/domain/proof-bundle";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  type ProofWorkerSuccess,
  type VestingBookProof,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import type { PayoClient } from "./payo-client";

const uintStringSchema = z.string().regex(/^(?:0|[1-9]\d*)$/);
const payrollPublicInputsSchema = payrollIntegrityCommonInputsSchema.extend({
  shardIndex: uintStringSchema,
}).strict();

export const encryptedPayrollProofPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  scheme: z.literal("ultra_keccak_zk_honk"),
  circuitSha256: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  verificationKeySha256: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  provingTimeMs: z.number().nonnegative(),
  shards: z.tuple([
    z.object({
      shardIndex: z.literal(0),
      proofBase64: z.string().min(1),
      proofCalldata: payrollProofCalldataSchema,
      calldataHash: starknetFeltSchema,
      publicInputs: payrollPublicInputsSchema,
    }).strict(),
    z.object({
      shardIndex: z.literal(1),
      proofBase64: z.string().min(1),
      proofCalldata: payrollProofCalldataSchema,
      calldataHash: starknetFeltSchema,
      publicInputs: payrollPublicInputsSchema,
    }).strict(),
  ]),
  vestingBook: vestingBookProofSubmissionSchema.optional(),
}).strict();

type ProofBundleClient = Pick<PayoClient, "getEncryptedProofBundle">;

function reconstructVestingBook(
  stored: z.infer<typeof vestingBookProofSubmissionSchema>,
): VestingBookProof {
  return {
    proofVersion: stored.proofVersion,
    entryKind: stored.entryKind,
    circuitSha256: stored.circuitSha256,
    verificationKeySha256: stored.verificationKeySha256,
    provingTimeMs: 0,
    scheduleId: stored.scheduleId as `0x${string}`,
    previousStateCommitment: stored.previousStateCommitment as `0x${string}`,
    nextStateCommitment: stored.nextStateCommitment as `0x${string}`,
    releaseNullifier: stored.releaseNullifier as `0x${string}`,
    bookEntryCommitment: stored.bookEntryCommitment as `0x${string}`,
    bookEntry: stored.bookEntry as VestingBookProof["bookEntry"],
    shards: stored.shards.map((shard) => ({
      ...shard,
      proof: new Uint8Array(),
    })) as VestingBookProof["shards"],
  };
}

/**
 * Reopens the exact authenticated v2 + v3 proof pair after a browser crash.
 * No server plaintext is trusted: envelope identity, pinned artifacts, public
 * metadata, calldata hashes and both ordered public-input sets are rechecked.
 */
export async function openStoredPayrollBookProof(input: {
  client: ProofBundleClient;
  proofBundleId: string;
  organizationId: string;
  runId: string;
  principal: VaultPrincipalKeyPair;
}) {
  const { proofBundle } = await input.client.getEncryptedProofBundle(input.proofBundleId);
  if (
    proofBundle.id !== input.proofBundleId
    || proofBundle.organizationId !== input.organizationId
    || proofBundle.runId !== input.runId
    || proofBundle.envelope.aad.recordType !== "proof-bundle"
    || proofBundle.envelope.aad.recordId !== proofBundle.id
    || proofBundle.envelope.aad.organizationId !== proofBundle.organizationId
    || proofBundle.envelope.aad.revision !== proofBundle.revision
  ) throw new Error("The stored payroll proof envelope does not match its durable identity.");

  const metadata = payrollIntegrityBundleMetadataSchema.parse(proofBundle.proofPackage);
  if (
    proofBundle.proofType !== "payroll_integrity"
    || proofBundle.proofVersion !== "2"
    || metadata.proofType !== "payroll_integrity"
    || metadata.proofVersion !== "2"
    || metadata.envelopeRecordId !== proofBundle.id
    || metadata.envelopeRevision !== proofBundle.revision
    || metadata.subjectRecordId !== proofBundle.runId
    || proofBundle.subjectRecordId !== proofBundle.runId
  ) throw new Error("This is not the exact recoverable Advanced PayrollIntegrity proof.");

  const payload = encryptedPayrollProofPayloadSchema.parse(
    decryptVaultRecord(proofBundle.envelope, input.principal),
  );
  if (
    payload.circuitSha256 !== ADVANCED_OBLIGATION_CIRCUIT_SHA256
    || payload.verificationKeySha256 !== ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256
    || metadata.circuitSha256 !== ADVANCED_OBLIGATION_CIRCUIT_SHA256
    || metadata.verificationKeySha256 !== ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256
    || payload.shards[0].publicInputs.proofVersion !== "2"
    || payload.shards[1].publicInputs.proofVersion !== "2"
    || payload.shards[0].publicInputs.shardIndex !== "0"
    || payload.shards[1].publicInputs.shardIndex !== "1"
  ) throw new Error("The stored payroll proof does not use PAYO's pinned v2 profile.");

  const publicInputsHash = hashCanonicalJson(payload.shards.map((shard) => shard.publicInputs));
  if (publicInputsHash !== metadata.publicInputsHash) {
    throw new Error("The decrypted payroll public inputs differ from their public commitment.");
  }
  for (const [index, shard] of payload.shards.entries()) {
    const { shardIndex, ...commonInputs } = shard.publicInputs;
    if (
      shardIndex !== String(index)
      || hashCanonicalJson(commonInputs) !== hashCanonicalJson(metadata.commonInputs)
      || BigInt(hashProofCalldata(shard.proofCalldata)) !== BigInt(shard.calldataHash)
      || BigInt(shard.calldataHash) !== BigInt(metadata.shardCalldataHashes[index])
    ) throw new Error(`Stored payroll proof shard ${index} differs from its public commitments.`);
  }
  if (!payload.vestingBook || payload.vestingBook.entryKind !== "agent") {
    throw new Error("The stored autonomous payroll is missing its universal agent-book proof.");
  }

  const payrollProof: ProofWorkerSuccess = {
    version: 1,
    type: "proof-complete",
    requestId: proofBundle.id,
    scheme: payload.scheme,
    circuitSha256: payload.circuitSha256,
    provingTimeMs: payload.provingTimeMs,
    shards: payload.shards.map((shard) => {
      const proof = fromBase64(shard.proofBase64);
      if (!proof.length) throw new Error(`Stored payroll proof shard ${shard.shardIndex} is empty.`);
      return {
        shardIndex: shard.shardIndex,
        proof,
        proofCalldata: shard.proofCalldata,
        calldataHash: shard.calldataHash,
        publicInputs: shard.publicInputs,
      };
    }) as ProofWorkerSuccess["shards"],
  };
  const vestingBook = reconstructVestingBook(payload.vestingBook);
  payrollProof.vestingBook = vestingBook;
  return { proofBundle, metadata, payrollProof, vestingBook };
}
