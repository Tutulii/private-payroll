import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  decryptVaultRecord,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import {
  exceptionProofBundleMetadataSchema,
  exceptionProofCalldataSchema,
  exceptionProofPublicInputsSchema,
  starknetFeltSchema,
} from "@/lib/domain/proof-bundle";
import {
  WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
  WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import type {
  ExceptionAuthorizationStatus,
  PayoClient,
} from "./payo-client";

export const encryptedExceptionProofPayloadSchema = z.object({
  schemaVersion: z.literal(2),
  scheme: z.literal("ultra_keccak_zk_honk"),
  profile: z.enum(["obligation_snapshot_v5", "wage_claim_v6", "wage_remediation_v7"]),
  circuitSha256: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  verificationKeySha256: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  provingTimeMs: z.number().nonnegative(),
  proof: z.object({
    proofBase64: z.string().min(1),
    proofCalldata: exceptionProofCalldataSchema,
    calldataHash: starknetFeltSchema,
    publicInputs: exceptionProofPublicInputsSchema,
  }).strict(),
}).strict();

export type OpenedExceptionProof = z.infer<
  typeof encryptedExceptionProofPayloadSchema
>;

type ProofBundleClient = Pick<PayoClient, "getEncryptedProofBundle">;

export async function openStoredExceptionProof(input: {
  client: ProofBundleClient;
  proofBundleId: string;
  principal: VaultPrincipalKeyPair;
}) {
  const { proofBundle } = await input.client.getEncryptedProofBundle(
    input.proofBundleId,
  );
  if (
    proofBundle.id !== input.proofBundleId
    || proofBundle.envelope.aad.recordType !== "proof-bundle"
    || proofBundle.envelope.aad.recordId !== proofBundle.id
    || proofBundle.envelope.aad.organizationId !== proofBundle.organizationId
    || proofBundle.envelope.aad.revision !== proofBundle.revision
  ) throw new Error("The stored proof envelope does not match its durable identity.");
  const metadata = exceptionProofBundleMetadataSchema.parse(
    proofBundle.proofPackage,
  );
  if (
    metadata.envelopeRecordId !== proofBundle.id
    || metadata.envelopeRevision !== proofBundle.revision
    || metadata.proofType !== proofBundle.proofType
    || metadata.proofVersion !== proofBundle.proofVersion
    || metadata.subjectRecordId !== proofBundle.subjectRecordId
  ) throw new Error("The stored exception proof metadata is inconsistent.");
  const payload = encryptedExceptionProofPayloadSchema.parse(
    decryptVaultRecord(proofBundle.envelope, input.principal),
  );
  const expected = metadata.proofVersion === "6"
    ? {
        profile: "wage_claim_v6" as const,
        circuit: WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
        verificationKey: WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256,
      }
    : metadata.proofVersion === "7"
      ? {
          profile: "wage_remediation_v7" as const,
          circuit: WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
          verificationKey: WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256,
        }
      : null;
  if (!expected || payload.profile !== expected.profile) {
    throw new Error("This is not a recoverable Claim v6 or Remediation v7 proof.");
  }
  if (
    payload.circuitSha256 !== expected.circuit
    || payload.verificationKeySha256 !== expected.verificationKey
    || metadata.circuitSha256 !== expected.circuit
    || metadata.verificationKeySha256 !== expected.verificationKey
    || hashCanonicalJson(payload.proof.publicInputs) !== metadata.publicInputsHash
    || JSON.stringify(payload.proof.publicInputs) !== JSON.stringify(metadata.publicInputs)
    || BigInt(hashProofCalldata(payload.proof.proofCalldata))
      !== BigInt(metadata.proofCalldataHash)
    || BigInt(payload.proof.calldataHash) !== BigInt(metadata.proofCalldataHash)
  ) throw new Error("The decrypted exception proof differs from its public commitments.");
  return { proofBundle, metadata, payload };
}

export async function authorizeStoredExceptionProof(input: {
  client: Pick<PayoClient, "getEncryptedProofBundle" | "enqueueExceptionAuthorization">;
  proofBundleId: string;
  principal: VaultPrincipalKeyPair;
}) {
  const opened = await openStoredExceptionProof(input);
  const { authorization } = await input.client.enqueueExceptionAuthorization({
    proofBundleId: input.proofBundleId,
    proofCalldata: opened.payload.proof.proofCalldata,
  });
  return { ...opened, authorization };
}

export async function waitForExceptionAuthorization(input: {
  client: Pick<PayoClient, "getExceptionAuthorization">;
  proofBundleId: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
  now?: () => number;
  wait?: (milliseconds: number) => Promise<void>;
  onPoll?: (authorization: ExceptionAuthorizationStatus) => void;
}): Promise<ExceptionAuthorizationStatus> {
  const timeoutMs = input.timeoutMs ?? 20 * 60_000;
  const pollIntervalMs = input.pollIntervalMs ?? 2_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs < pollIntervalMs) {
    throw new Error("Authorization timeout must cover at least one poll interval.");
  }
  if (!Number.isFinite(pollIntervalMs) || pollIntervalMs < 100) {
    throw new Error("Authorization polling interval is too short.");
  }
  const now = input.now ?? Date.now;
  const wait = input.wait ?? ((milliseconds: number) =>
    new Promise<void>((resolve) => globalThis.setTimeout(resolve, milliseconds)));
  const deadline = now() + timeoutMs;
  while (true) {
    const { authorization } = await input.client.getExceptionAuthorization(
      input.proofBundleId,
    );
    input.onPoll?.(authorization);
    if (authorization.state === "complete") return authorization;
    if (authorization.state === "dead") {
      throw new Error(
        authorization.lastErrorMessage
        ?? authorization.lastErrorCode
        ?? "The on-chain exception authorization failed.",
      );
    }
    if (now() >= deadline) {
      throw new Error(
        "The on-chain exception authorization is still pending. It is safe to leave this page and resume later.",
      );
    }
    await wait(pollIntervalMs);
  }
}
