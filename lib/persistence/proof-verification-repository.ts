import "server-only";

import { and, eq, isNull, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  payrollIntegrityBundleMetadataSchema,
  payrollProofCalldataSchema,
  type ProofVerificationRequest,
} from "@/lib/domain/proof-bundle";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  hashProofCalldata,
  parsePayrollPublicInputsFromGaragaCalldata,
} from "@/lib/proof/starknet-calldata";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  auditEvents,
  organizationMembers,
  payrollRuns,
  proofBundles,
  proofVerificationJobs,
  settlements,
} from "./schema";

function assertCommonInputs(
  expected: ReturnType<typeof payrollIntegrityBundleMetadataSchema.parse>["commonInputs"],
  actual: ReturnType<typeof parsePayrollPublicInputsFromGaragaCalldata>,
  shardIndex: 0 | 1,
) {
  for (const key of Object.keys(expected) as Array<keyof typeof expected>) {
    if (BigInt(expected[key]) !== BigInt(actual[key])) {
      throw new ApiError(
        400,
        `Proof shard ${shardIndex} public input ${key} does not match its encrypted bundle metadata.`,
        "PROOF_PUBLIC_INPUT_MISMATCH",
      );
    }
  }
  if (BigInt(actual.shardIndex) !== BigInt(shardIndex)) {
    throw new ApiError(400, `Proof shard ${shardIndex} has the wrong index.`, "PROOF_SHARD_INDEX_MISMATCH");
  }
}

export async function enqueueProofVerification(input: {
  settlementId: string;
  request: ProofVerificationRequest;
  principal: AuthenticatedPrincipal;
}) {
  const [shardZero, shardOne] = input.request.shards;
  const shardHashes = [hashProofCalldata(shardZero), hashProofCalldata(shardOne)] as const;
  const shardInputs = [
    parsePayrollPublicInputsFromGaragaCalldata(shardZero),
    parsePayrollPublicInputsFromGaragaCalldata(shardOne),
  ] as const;
  const database = getDatabase();

  return database.transaction(async (transaction) => {
    const [settlement] = await transaction
      .select()
      .from(settlements)
      .where(eq(settlements.id, input.settlementId))
      .limit(1)
      .for("update");
    if (!settlement) throw new ApiError(404, "Settlement not found.", "SETTLEMENT_NOT_FOUND");

    const [membership] = await transaction
      .select({ role: organizationMembers.role })
      .from(organizationMembers)
      .where(and(
        eq(organizationMembers.organizationId, settlement.organizationId),
        eq(organizationMembers.principalId, input.principal.principalId),
        isNull(organizationMembers.revokedAt),
      ))
      .limit(1)
      .for("update");
    if (!membership || !["admin", "operator"].includes(membership.role)) {
      throw new ApiError(403, "You cannot relay proofs for this settlement.", "ORG_FORBIDDEN");
    }
    const awaitingReadyApproval = settlement.state === "approval_pending" && !settlement.transactionHash;
    const submitted = Boolean(settlement.transactionHash)
      && ["submitted", "confirmed", "finalized"].includes(settlement.state);
    if (!awaitingReadyApproval && !submitted) {
      throw new ApiError(
        409,
        "Proof delivery requires a pending Ready approval or a submitted STRK20 settlement.",
        "SETTLEMENT_NOT_SUBMITTED",
      );
    }

    const [proofBundle] = await transaction
      .select()
      .from(proofBundles)
      .where(eq(proofBundles.id, input.request.proofBundleId))
      .limit(1);
    if (
      !proofBundle
      || proofBundle.organizationId !== settlement.organizationId
      || proofBundle.runId !== settlement.runId
    ) {
      throw new ApiError(404, "Proof bundle does not belong to this settlement.", "PROOF_BUNDLE_NOT_FOUND");
    }
    const expectedProofType = settlement.workflowType === "payroll"
      ? "payroll_integrity"
      : settlement.workflowType;
    if (
      proofBundle.proofType !== expectedProofType
      || proofBundle.subjectRecordId !== settlement.subjectRecordId
    ) {
      throw new ApiError(
        409,
        "Proof bundle does not match the settlement workflow subject.",
        "PROOF_SETTLEMENT_WORKFLOW_MISMATCH",
      );
    }
    if (!["locally_verified", "onchain_verified"].includes(proofBundle.verificationState)) {
      throw new ApiError(409, "Proof bundle has not passed local verification.", "PROOF_NOT_LOCALLY_VERIFIED");
    }
    const metadata = payrollIntegrityBundleMetadataSchema.parse(proofBundle.proofPackage);
    for (const shardIndex of [0, 1] as const) {
      if (BigInt(shardHashes[shardIndex]) !== BigInt(metadata.shardCalldataHashes[shardIndex])) {
        throw new ApiError(
          400,
          `Proof shard ${shardIndex} does not match its committed calldata hash.`,
          "PROOF_CALLDATA_HASH_MISMATCH",
        );
      }
      assertCommonInputs(metadata.commonInputs, shardInputs[shardIndex], shardIndex);
    }
    const canonicalPublicInputs = [
      { ...metadata.commonInputs, shardIndex: "0" },
      { ...metadata.commonInputs, shardIndex: "1" },
    ];
    if (hashCanonicalJson(canonicalPublicInputs) !== metadata.publicInputsHash) {
      throw new ApiError(409, "Proof bundle public-input digest is inconsistent.", "PROOF_BUNDLE_INVALID");
    }

    const [existing] = await transaction
      .select()
      .from(proofVerificationJobs)
      .where(eq(proofVerificationJobs.settlementId, input.settlementId))
      .limit(1);
    if (existing) {
      if (existing.proofBundleId !== input.request.proofBundleId) {
        throw new ApiError(409, "Settlement already uses another proof bundle.", "PROOF_JOB_CONFLICT");
      }
      return { ...existing, shard0Calldata: undefined, shard1Calldata: undefined, replayed: true };
    }

    const nowSeconds = BigInt(Math.floor(Date.now() / 1_000));
    if (BigInt(metadata.commonInputs.validityExpiry) <= nowSeconds + 120n) {
      throw new ApiError(
        409,
        "The sealed proof has too little validity remaining for safe on-chain verification.",
        "PROOF_VALIDITY_EXPIRED",
      );
    }

    const id = generateUuidV7();
    const [job] = await transaction
      .insert(proofVerificationJobs)
      .values({
        id,
        settlementId: input.settlementId,
        proofBundleId: input.request.proofBundleId,
        shard0Calldata: shardZero,
        shard1Calldata: shardOne,
      })
      .returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: settlement.organizationId,
      actorId: input.principal.principalId,
      action: awaitingReadyApproval
        ? "proof_verification.prepared"
        : "proof_verification.queued",
      subjectId: id,
      metadata: {
        settlementId: settlement.id,
        proofBundleId: proofBundle.id,
        shard0Hash: shardHashes[0],
        shard1Hash: shardHashes[1],
      },
    });
    return { ...job, shard0Calldata: undefined, shard1Calldata: undefined, replayed: false };
  });
}

const PROOF_JOB_LEASE_MS = 120_000;
const MAX_PROOF_JOB_ATTEMPTS = 80;

export type LeasedProofVerificationJob = {
  id: string;
  settlementId: string;
  proofBundleId: string;
  runId: string;
  organizationId: string;
  attempts: number;
  nextShard: 0 | 1;
  activeTransactionHash: string | null;
  shard0TransactionHash: string | null;
  shard1TransactionHash: string | null;
  runNullifierHigh: string;
  runNullifierLow: string;
  chainId: string;
  sealAddress: string;
  validityExpiry: string;
  proofVersion: string;
  shardCalldataHashes: readonly [string, string];
  shards: readonly [string[], string[]];
  leaseOwner: string;
};

function proofRetryDelayMs(attempts: number): number {
  return Math.min(30_000, 1_500 * 2 ** Math.min(attempts, 4));
}

function safeErrorMessage(message: string): string {
  return message.replace(/[\r\n\t]+/g, " ").slice(0, 500);
}

function transactionHash(value: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(value)) throw new Error("Relayer returned an invalid transaction hash.");
  return value.toLowerCase();
}

async function assertWorkerLease(
  transaction: Parameters<Parameters<ReturnType<typeof getDatabase>["transaction"]>[0]>[0],
  job: LeasedProofVerificationJob,
) {
  const [leased] = await transaction
    .select({ id: proofVerificationJobs.id })
    .from(proofVerificationJobs)
    .where(and(
      eq(proofVerificationJobs.id, job.id),
      eq(proofVerificationJobs.state, "leased"),
      eq(proofVerificationJobs.leaseOwner, job.leaseOwner),
    ))
    .limit(1)
    .for("update");
  if (!leased) throw new Error("Proof verification lease is stale.");
}

export async function leaseProofVerificationJobs(
  workerId: string,
  limit = 2,
  now = new Date(),
): Promise<LeasedProofVerificationJob[]> {
  if (!workerId.trim()) throw new Error("A proof relayer worker ID is required.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 10) {
    throw new Error("Proof relayer job limit must be 1–10.");
  }
  const database = getDatabase();
  const leaseExpiresAt = new Date(now.getTime() + PROOF_JOB_LEASE_MS);
  return database.transaction(async (transaction) => {
    const leased = await transaction
      .update(proofVerificationJobs)
      .set({ state: "leased", leaseOwner: workerId, leaseExpiresAt, updatedAt: now })
      .where(sql`${proofVerificationJobs.id} IN (
        SELECT jobs.id
        FROM proof_verification_jobs AS jobs
        INNER JOIN settlements AS settlement ON settlement.id = jobs.settlement_id
        WHERE settlement.state = 'finalized'
          AND (
            (jobs.state = 'pending' AND jobs.available_at <= ${now.toISOString()}::timestamptz)
            OR (jobs.state = 'leased' AND jobs.lease_expires_at <= ${now.toISOString()}::timestamptz)
          )
        ORDER BY jobs.available_at, jobs.created_at
        FOR UPDATE OF jobs SKIP LOCKED
        LIMIT ${limit}
      )`)
      .returning();

    const jobs: LeasedProofVerificationJob[] = [];
    for (const job of leased) {
      try {
        if (job.nextShard !== 0 && job.nextShard !== 1) throw new Error("Stored proof shard cursor is invalid.");
        const [bundle] = await transaction
          .select({
            organizationId: proofBundles.organizationId,
            runId: proofBundles.runId,
            proofPackage: proofBundles.proofPackage,
          })
          .from(proofBundles)
          .where(eq(proofBundles.id, job.proofBundleId))
          .limit(1);
        if (!bundle) throw new Error("Proof verification job references a missing bundle.");
        const metadata = payrollIntegrityBundleMetadataSchema.parse(bundle.proofPackage);
        const shards = [
          payrollProofCalldataSchema.parse(job.shard0Calldata),
          payrollProofCalldataSchema.parse(job.shard1Calldata),
        ] as const;
        jobs.push({
          id: job.id,
          settlementId: job.settlementId,
          proofBundleId: job.proofBundleId,
          runId: bundle.runId,
          organizationId: bundle.organizationId,
          attempts: job.attempts,
          nextShard: job.nextShard,
          activeTransactionHash: job.activeTransactionHash,
          shard0TransactionHash: job.shard0TransactionHash,
          shard1TransactionHash: job.shard1TransactionHash,
          runNullifierHigh: metadata.commonInputs.runNullifierHigh,
          runNullifierLow: metadata.commonInputs.runNullifierLow,
          chainId: metadata.commonInputs.chainId,
          sealAddress: metadata.commonInputs.sealAddress,
          validityExpiry: metadata.commonInputs.validityExpiry,
          proofVersion: metadata.proofVersion,
          shardCalldataHashes: metadata.shardCalldataHashes,
          shards,
          leaseOwner: workerId,
        });
      } catch (error) {
        await transaction
          .update(proofVerificationJobs)
          .set({
            state: "dead",
            leaseOwner: null,
            leaseExpiresAt: null,
            lastErrorCode: "PROOF_JOB_DATA_INVALID",
            lastErrorMessage: safeErrorMessage(error instanceof Error ? error.message : "Stored proof job is invalid."),
            updatedAt: now,
          })
          .where(eq(proofVerificationJobs.id, job.id));
      }
    }
    return jobs;
  });
}

export async function recordProofVerificationSubmission(
  job: LeasedProofVerificationJob,
  shardIndex: 0 | 1,
  submittedTransactionHash: string,
  now = new Date(),
) {
  if (shardIndex !== job.nextShard) throw new Error("Cannot submit a proof shard out of order.");
  const hash = transactionHash(submittedTransactionHash);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertWorkerLease(transaction, job);
    const [updated] = await transaction
      .update(proofVerificationJobs)
      .set({
        state: "pending",
        activeTransactionHash: hash,
        ...(shardIndex === 0 ? { shard0TransactionHash: hash } : { shard1TransactionHash: hash }),
        attempts: job.attempts + 1,
        availableAt: new Date(now.getTime() + 1_500),
        leaseOwner: null,
        leaseExpiresAt: null,
        lastErrorCode: null,
        lastErrorMessage: null,
        updatedAt: now,
      })
      .where(eq(proofVerificationJobs.id, job.id))
      .returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:proof-relayer",
      action: "proof_verification.submitted",
      subjectId: job.id,
      metadata: { settlementId: job.settlementId, shardIndex, transactionHash: hash },
    });
    return updated;
  });
}

export async function deferProofVerificationJob(
  job: LeasedProofVerificationJob,
  input: {
    errorCode: string;
    errorMessage: string;
    clearActiveTransaction?: boolean;
    nextShard?: 0 | 1;
    permanent?: boolean;
  },
  now = new Date(),
) {
  const database = getDatabase();
  const nextAttempts = job.attempts + 1;
  const dead = input.permanent === true || nextAttempts >= MAX_PROOF_JOB_ATTEMPTS;
  return database.transaction(async (transaction) => {
    await assertWorkerLease(transaction, job);
    const [updated] = await transaction
      .update(proofVerificationJobs)
      .set({
        state: dead ? "dead" : "pending",
        nextShard: input.nextShard ?? job.nextShard,
        ...(input.clearActiveTransaction ? { activeTransactionHash: null } : {}),
        attempts: nextAttempts,
        availableAt: new Date(now.getTime() + proofRetryDelayMs(nextAttempts)),
        leaseOwner: null,
        leaseExpiresAt: null,
        lastErrorCode: dead && !input.permanent ? "PROOF_VERIFICATION_TIMEOUT" : input.errorCode,
        lastErrorMessage: safeErrorMessage(input.errorMessage),
        updatedAt: now,
      })
      .where(eq(proofVerificationJobs.id, job.id))
      .returning();
    return { ...updated, state: dead ? "dead" as const : "pending" as const };
  });
}

export async function recordProofVerificationProgress(
  job: LeasedProofVerificationJob,
  input: { nextShard: 0 | 1 } | { complete: true; verificationTransactionHash?: string | null },
  now = new Date(),
) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertWorkerLease(transaction, job);
    if ("complete" in input) {
      const verificationHash = input.verificationTransactionHash
        ? transactionHash(input.verificationTransactionHash)
        : job.shard1TransactionHash ?? job.shard0TransactionHash;
      const [updated] = await transaction
        .update(proofVerificationJobs)
        .set({
          state: "complete",
          nextShard: 1,
          activeTransactionHash: null,
          leaseOwner: null,
          leaseExpiresAt: null,
          lastErrorCode: null,
          lastErrorMessage: null,
          updatedAt: now,
        })
        .where(eq(proofVerificationJobs.id, job.id))
        .returning();
      await transaction
        .update(proofBundles)
        .set({ verificationState: "onchain_verified", verificationTransactionHash: verificationHash })
        .where(eq(proofBundles.id, job.proofBundleId));
      if (BigInt(job.proofVersion) === 3n) {
        await transaction
          .update(payrollRuns)
          .set({ state: "disputed", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
          .where(and(eq(payrollRuns.id, job.runId), eq(payrollRuns.state, "confirmed")));
      } else if (BigInt(job.proofVersion) === 4n) {
        await transaction
          .update(payrollRuns)
          .set({ state: "reconciled", updatedAt: now, version: sql`${payrollRuns.version} + 1` })
          .where(and(eq(payrollRuns.id, job.runId), eq(payrollRuns.state, "disputed")));
      }
      await transaction.insert(auditEvents).values({
        id: generateUuidV7(),
        organizationId: job.organizationId,
        actorId: "system:proof-relayer",
        action: "proof_verification.completed",
        subjectId: job.id,
        metadata: {
          settlementId: job.settlementId,
          shard0TransactionHash: job.shard0TransactionHash,
          shard1TransactionHash: job.shard1TransactionHash,
        },
      });
      return { ...updated, state: "complete" as const };
    }

    const [updated] = await transaction
      .update(proofVerificationJobs)
      .set({
        state: "pending",
        nextShard: input.nextShard,
        activeTransactionHash: null,
        attempts: job.attempts + 1,
        availableAt: now,
        leaseOwner: null,
        leaseExpiresAt: null,
        lastErrorCode: null,
        lastErrorMessage: null,
        updatedAt: now,
      })
      .where(eq(proofVerificationJobs.id, job.id))
      .returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:proof-relayer",
      action: "proof_verification.shard_observed",
      subjectId: job.id,
      metadata: { settlementId: job.settlementId, nextShard: input.nextShard },
    });
    return { ...updated, state: "pending" as const };
  });
}

export async function getProofVerificationJob(
  settlementId: string,
  principal: AuthenticatedPrincipal,
) {
  const database = getDatabase();
  const [settlement] = await database
    .select({ organizationId: settlements.organizationId })
    .from(settlements)
    .where(eq(settlements.id, settlementId))
    .limit(1);
  if (!settlement) throw new ApiError(404, "Settlement not found.", "SETTLEMENT_NOT_FOUND");
  await requireOrganizationRole(settlement.organizationId, principal, ["admin", "operator", "reviewer"]);
  const [job] = await database
    .select({
      id: proofVerificationJobs.id,
      settlementId: proofVerificationJobs.settlementId,
      proofBundleId: proofVerificationJobs.proofBundleId,
      state: proofVerificationJobs.state,
      nextShard: proofVerificationJobs.nextShard,
      activeTransactionHash: proofVerificationJobs.activeTransactionHash,
      shard0TransactionHash: proofVerificationJobs.shard0TransactionHash,
      shard1TransactionHash: proofVerificationJobs.shard1TransactionHash,
      attempts: proofVerificationJobs.attempts,
      lastErrorCode: proofVerificationJobs.lastErrorCode,
      lastErrorMessage: proofVerificationJobs.lastErrorMessage,
      createdAt: proofVerificationJobs.createdAt,
      updatedAt: proofVerificationJobs.updatedAt,
    })
    .from(proofVerificationJobs)
    .where(eq(proofVerificationJobs.settlementId, settlementId))
    .limit(1);
  if (!job) throw new ApiError(404, "Proof verification job not found.", "PROOF_JOB_NOT_FOUND");
  return job;
}
