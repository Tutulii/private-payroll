import "server-only";

import { and, eq, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { payrollProofCalldataSchema } from "@/lib/domain/proof-bundle";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import { auditEvents, fxPublicationJobs } from "./schema";

const FX_JOB_LEASE_MS = 180_000;
const MAX_FX_JOB_ATTEMPTS = 48;

export type LeasedFxPublicationJob = {
  id: string;
  organizationId: string;
  principalId: string;
  catalogRoot: string;
  proofVersion: 1 | 2;
  proofDigest: string;
  shards: readonly [string[], string[]];
  observedAt: number;
  maximumAgeSeconds: number;
  transactionHash: string | null;
  attempts: number;
  leaseOwner: string;
};

function publicJob<T extends {
  shard0Calldata: unknown;
  shard1Calldata: unknown;
}>(job: T) {
  const { shard0Calldata: _shardZero, shard1Calldata: _shardOne, ...safe } = job;
  return safe;
}

function canonicalTransactionHash(value: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
    throw new Error("The FX publisher returned an invalid transaction hash.");
  }
  return `0x${BigInt(value).toString(16)}`;
}

function safeErrorMessage(value: string): string {
  return value.replace(/[\r\n\t]+/g, " ").slice(0, 500);
}

function retryDelayMs(attempts: number): number {
  return Math.min(30_000, 1_500 * 2 ** Math.min(attempts, 4));
}

export async function enqueueFxPublication(input: {
  organizationId: string;
  catalogRoot: string;
  proofVersion: 1 | 2;
  shards: readonly [readonly string[], readonly string[]];
  observedAt: number;
  maximumAgeSeconds: number;
  principal: AuthenticatedPrincipal;
}) {
  await requireOrganizationRole(input.organizationId, input.principal, ["admin", "operator"]);
  const catalogRoot = `0x${BigInt(input.catalogRoot).toString(16).padStart(64, "0")}`;
  const shards = [
    payrollProofCalldataSchema.parse(input.shards[0]),
    payrollProofCalldataSchema.parse(input.shards[1]),
  ] as const;
  if (!Number.isSafeInteger(input.observedAt) || input.observedAt < 0) {
    throw new ApiError(400, "The FX observation timestamp is invalid.", "FX_PUBLICATION_INVALID");
  }
  if (!Number.isInteger(input.maximumAgeSeconds)
    || input.maximumAgeSeconds < 1
    || input.maximumAgeSeconds > 3_600) {
    throw new ApiError(400, "The FX publication lifetime is invalid.", "FX_PUBLICATION_INVALID");
  }
  const proofDigest = hashCanonicalJson({
    domain: "PAYO_FX_PUBLICATION_JOB_V1",
    catalogRoot,
    proofVersion: input.proofVersion,
    shards,
  });
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [existing] = await transaction
      .select()
      .from(fxPublicationJobs)
      .where(and(
        eq(fxPublicationJobs.organizationId, input.organizationId),
        eq(fxPublicationJobs.catalogRoot, catalogRoot),
      ))
      .limit(1)
      .for("update");
    if (existing) {
      if (existing.proofDigest !== proofDigest
        || existing.observedAt !== input.observedAt
        || existing.maximumAgeSeconds !== input.maximumAgeSeconds) {
        throw new ApiError(
          409,
          "This FX root already has a different publication request.",
          "FX_PUBLICATION_CONFLICT",
        );
      }
      return { ...publicJob(existing), replayed: true };
    }

    const id = generateUuidV7();
    const [job] = await transaction
      .insert(fxPublicationJobs)
      .values({
        id,
        organizationId: input.organizationId,
        principalId: input.principal.principalId,
        catalogRoot,
        proofVersion: input.proofVersion,
        proofDigest,
        shard0Calldata: shards[0],
        shard1Calldata: shards[1],
        observedAt: input.observedAt,
        maximumAgeSeconds: input.maximumAgeSeconds,
      })
      .returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "fx_publication.queued",
      subjectId: id,
      metadata: { catalogRoot, proofVersion: input.proofVersion, proofDigest },
    });
    return { ...publicJob(job), replayed: false };
  });
}

export async function getFxPublicationJob(input: {
  organizationId: string;
  catalogRoot: string;
  principal: AuthenticatedPrincipal;
}) {
  await requireOrganizationRole(input.organizationId, input.principal, ["admin", "operator", "reviewer"]);
  const catalogRoot = `0x${BigInt(input.catalogRoot).toString(16).padStart(64, "0")}`;
  const database = getDatabase();
  const [job] = await database
    .select({
      id: fxPublicationJobs.id,
      organizationId: fxPublicationJobs.organizationId,
      catalogRoot: fxPublicationJobs.catalogRoot,
      state: fxPublicationJobs.state,
      transactionHash: fxPublicationJobs.transactionHash,
      attempts: fxPublicationJobs.attempts,
      lastErrorCode: fxPublicationJobs.lastErrorCode,
      lastErrorMessage: fxPublicationJobs.lastErrorMessage,
      createdAt: fxPublicationJobs.createdAt,
      updatedAt: fxPublicationJobs.updatedAt,
    })
    .from(fxPublicationJobs)
    .where(and(
      eq(fxPublicationJobs.organizationId, input.organizationId),
      eq(fxPublicationJobs.catalogRoot, catalogRoot),
    ))
    .limit(1);
  if (!job) throw new ApiError(404, "FX publication job not found.", "FX_PUBLICATION_NOT_FOUND");
  return job;
}

export async function leaseFxPublicationJobs(
  workerId: string,
  limit = 1,
  now = new Date(),
): Promise<LeasedFxPublicationJob[]> {
  if (!workerId.trim()) throw new Error("An FX publisher worker ID is required.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 5) {
    throw new Error("FX publisher job limit must be 1–5.");
  }
  const database = getDatabase();
  const leaseExpiresAt = new Date(now.getTime() + FX_JOB_LEASE_MS);
  return database.transaction(async (transaction) => {
    const leased = await transaction
      .update(fxPublicationJobs)
      .set({ state: "leased", leaseOwner: workerId, leaseExpiresAt, updatedAt: now })
      .where(sql`${fxPublicationJobs.id} IN (
        SELECT jobs.id
        FROM fx_publication_jobs AS jobs
        WHERE (
          (jobs.state = 'pending' AND jobs.available_at <= ${now.toISOString()}::timestamptz)
          OR (jobs.state = 'leased' AND jobs.lease_expires_at <= ${now.toISOString()}::timestamptz)
        )
        ORDER BY jobs.available_at, jobs.created_at
        FOR UPDATE OF jobs SKIP LOCKED
        LIMIT ${limit}
      )`)
      .returning();

    const jobs: LeasedFxPublicationJob[] = [];
    for (const job of leased) {
      try {
        if (job.proofVersion !== 1 && job.proofVersion !== 2) {
          throw new Error("Stored FX proof version is unsupported.");
        }
        jobs.push({
          id: job.id,
          organizationId: job.organizationId,
          principalId: job.principalId,
          catalogRoot: job.catalogRoot,
          proofVersion: job.proofVersion,
          proofDigest: job.proofDigest,
          shards: [
            payrollProofCalldataSchema.parse(job.shard0Calldata),
            payrollProofCalldataSchema.parse(job.shard1Calldata),
          ],
          observedAt: job.observedAt,
          maximumAgeSeconds: job.maximumAgeSeconds,
          transactionHash: job.transactionHash,
          attempts: job.attempts,
          leaseOwner: workerId,
        });
      } catch (error) {
        await transaction
          .update(fxPublicationJobs)
          .set({
            state: "dead",
            leaseOwner: null,
            leaseExpiresAt: null,
            lastErrorCode: "FX_JOB_DATA_INVALID",
            lastErrorMessage: safeErrorMessage(error instanceof Error ? error.message : "Stored FX job is invalid."),
            updatedAt: now,
          })
          .where(eq(fxPublicationJobs.id, job.id));
      }
    }
    return jobs;
  });
}

async function assertLease(
  transaction: Parameters<Parameters<ReturnType<typeof getDatabase>["transaction"]>[0]>[0],
  job: LeasedFxPublicationJob,
) {
  const [leased] = await transaction
    .select({ id: fxPublicationJobs.id })
    .from(fxPublicationJobs)
    .where(and(
      eq(fxPublicationJobs.id, job.id),
      eq(fxPublicationJobs.state, "leased"),
      eq(fxPublicationJobs.leaseOwner, job.leaseOwner),
    ))
    .limit(1)
    .for("update");
  if (!leased) throw new Error("FX publication lease is stale.");
}

export async function recordFxPublicationSubmission(
  job: LeasedFxPublicationJob,
  submittedTransactionHash: string,
  now = new Date(),
) {
  const transactionHash = canonicalTransactionHash(submittedTransactionHash);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction
      .update(fxPublicationJobs)
      .set({
        state: "pending",
        transactionHash,
        attempts: job.attempts + 1,
        availableAt: new Date(now.getTime() + 2_000),
        leaseOwner: null,
        leaseExpiresAt: null,
        lastErrorCode: null,
        lastErrorMessage: null,
        updatedAt: now,
      })
      .where(eq(fxPublicationJobs.id, job.id))
      .returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:fx-publisher",
      action: "fx_publication.submitted",
      subjectId: job.id,
      metadata: { catalogRoot: job.catalogRoot, transactionHash },
    });
    return updated;
  });
}

export async function recordFxPublicationComplete(
  job: LeasedFxPublicationJob,
  transactionHash: string | null,
  now = new Date(),
) {
  const canonicalHash = transactionHash ? canonicalTransactionHash(transactionHash) : job.transactionHash;
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction
      .update(fxPublicationJobs)
      .set({
        state: "complete",
        transactionHash: canonicalHash,
        leaseOwner: null,
        leaseExpiresAt: null,
        lastErrorCode: null,
        lastErrorMessage: null,
        updatedAt: now,
      })
      .where(eq(fxPublicationJobs.id, job.id))
      .returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:fx-publisher",
      action: "fx_publication.completed",
      subjectId: job.id,
      metadata: { catalogRoot: job.catalogRoot, transactionHash: canonicalHash },
    });
    return updated;
  });
}

export async function deferFxPublicationJob(
  job: LeasedFxPublicationJob,
  input: {
    errorCode: string;
    errorMessage: string;
    permanent?: boolean;
    clearTransactionHash?: boolean;
  },
  now = new Date(),
) {
  const attempts = job.attempts + 1;
  const dead = input.permanent === true || attempts >= MAX_FX_JOB_ATTEMPTS;
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction
      .update(fxPublicationJobs)
      .set({
        state: dead ? "dead" : "pending",
        ...(input.clearTransactionHash ? { transactionHash: null } : {}),
        attempts,
        availableAt: new Date(now.getTime() + retryDelayMs(attempts)),
        leaseOwner: null,
        leaseExpiresAt: null,
        lastErrorCode: dead && input.permanent !== true ? "FX_PUBLICATION_TIMEOUT" : input.errorCode,
        lastErrorMessage: safeErrorMessage(input.errorMessage),
        updatedAt: now,
      })
      .where(eq(fxPublicationJobs.id, job.id))
      .returning();
    return { ...updated, state: dead ? "dead" as const : "pending" as const };
  });
}
