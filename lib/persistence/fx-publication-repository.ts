import "server-only";

import { and, eq, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { payrollProofCalldataSchema } from "@/lib/domain/proof-bundle";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import { auditEvents, fxPublicationJobs, payrollRuns, proofBundles, settlements } from "./schema";

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
  historicalRenewal: boolean;
  renewalRunId: string | null;
  transactionHash: string | null;
  attempts: number;
  leaseOwner: string;
};

function publicJob<T extends {
  shard0Calldata: unknown;
  shard1Calldata: unknown;
}>(job: T) {
  const { shard0Calldata, shard1Calldata, ...safe } = job;
  void shard0Calldata;
  void shard1Calldata;
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
      const recoverableDeadJob = existing.state === "dead"
        && existing.transactionHash === null
        && ["FX_PUBLICATION_PROOF_INVALID", "FX_PUBLICATION_WINDOW_EXPIRED"]
          .includes(existing.lastErrorCode ?? "");
      if (recoverableDeadJob) {
        const now = new Date();
        const [requeued] = await transaction
          .update(fxPublicationJobs)
          .set({
            principalId: input.principal.principalId,
            proofVersion: input.proofVersion,
            proofDigest,
            shard0Calldata: shards[0],
            shard1Calldata: shards[1],
            observedAt: input.observedAt,
            maximumAgeSeconds: input.maximumAgeSeconds,
            historicalRenewal: false,
            renewalRunId: null,
            state: "pending",
            availableAt: now,
            leaseOwner: null,
            leaseExpiresAt: null,
            lastErrorCode: null,
            lastErrorMessage: null,
            updatedAt: now,
          })
          .where(eq(fxPublicationJobs.id, existing.id))
          .returning();
        await transaction.insert(auditEvents).values({
          id: generateUuidV7(),
          organizationId: input.organizationId,
          actorId: input.principal.principalId,
          action: "fx_publication.requeued",
          subjectId: existing.id,
          metadata: {
            catalogRoot,
            proofVersion: input.proofVersion,
            proofDigest,
            previousErrorCode: existing.lastErrorCode,
          },
        });
        return { ...publicJob(requeued), replayed: false, recovered: true };
      }
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

export type HistoricalFxRenewalEvidence = {
  runId: string;
  organizationId: string;
  catalogRoot: string;
  runNullifier: string;
  authorizationNullifier: string;
  transactionHash: string;
};

function exceptionAuthorizationNullifier(input: {
  proofPackage: unknown;
  claimId: string;
}): string {
  const proofPackage = input.proofPackage !== null
    && typeof input.proofPackage === "object"
    && !Array.isArray(input.proofPackage)
    ? input.proofPackage as Record<string, unknown>
    : null;
  const commonInputs = proofPackage?.commonInputs !== null
    && typeof proofPackage?.commonInputs === "object"
    && !Array.isArray(proofPackage.commonInputs)
    ? proofPackage.commonInputs as Record<string, unknown>
    : null;
  if (
    proofPackage?.proofType !== "wage_claim"
    || proofPackage.proofVersion !== "3"
    || proofPackage.subjectRecordId !== input.claimId
    || commonInputs?.proofVersion !== "3"
  ) {
    throw new ApiError(409, "The selected claim proof bindings are invalid.", "FX_RENEWAL_CLAIM_BINDING_INVALID");
  }
  try {
    const high = BigInt(String(commonInputs.runNullifierHigh));
    const low = BigInt(String(commonInputs.runNullifierLow));
    if (high < 0n || high >= 1n << 128n || low < 0n || low >= 1n << 128n) throw new Error("range");
    return `0x${((high << 128n) | low).toString(16).padStart(64, "0")}`;
  } catch {
    throw new ApiError(409, "The selected claim nullifier is invalid.", "FX_RENEWAL_CLAIM_BINDING_INVALID");
  }
}

function assertRenewablePayrollState(state: string): void {
  if (!["confirmed", "reconciled", "disputed"].includes(state)) {
    throw new ApiError(409, "Only a confirmed payroll can renew its historical FX root.", "FX_RENEWAL_RUN_INVALID");
  }
}

export async function getHistoricalFxRenewalEvidence(input: {
  runId: string;
  principal: AuthenticatedPrincipal;
} & ({
  workflowType?: "wage_claim" | "employer_statement";
} | {
  workflowType: "wage_remediation";
  claimId: string;
})): Promise<HistoricalFxRenewalEvidence> {
  const database = getDatabase();
  const [run] = await database
    .select()
    .from(payrollRuns)
    .where(eq(payrollRuns.id, input.runId))
    .limit(1);
  if (!run) throw new ApiError(404, "Payroll run not found.", "RUN_NOT_FOUND");
  await requireOrganizationRole(run.organizationId, input.principal, ["admin", "operator"]);
  assertRenewablePayrollState(run.state);
  if (!run.fxRoot || !run.runNullifier || !run.transactionHash) {
    throw new ApiError(409, "The confirmed payroll is missing its sealed FX evidence.", "FX_RENEWAL_EVIDENCE_MISSING");
  }
  const [settlement] = await database
    .select({ transactionHash: settlements.transactionHash, state: settlements.state })
    .from(settlements)
    .where(and(
      eq(settlements.organizationId, run.organizationId),
      eq(settlements.runId, run.id),
      eq(settlements.workflowType, "payroll"),
    ))
    .limit(1);
  if (
    !settlement?.transactionHash
    || BigInt(settlement.transactionHash) !== BigInt(run.transactionHash)
    || !["confirmed", "finalized", "reconciled"].includes(settlement.state)
  ) {
    throw new ApiError(409, "The payroll has no finalized matching settlement.", "FX_RENEWAL_SETTLEMENT_INVALID");
  }
  const [proof] = await database
    .select({ verificationState: proofBundles.verificationState })
    .from(proofBundles)
    .where(and(
      eq(proofBundles.organizationId, run.organizationId),
      eq(proofBundles.runId, run.id),
      eq(proofBundles.proofType, "payroll_integrity"),
      eq(proofBundles.subjectRecordId, run.id),
    ))
    .limit(1);
  if (proof?.verificationState !== "onchain_verified") {
    throw new ApiError(409, "The payroll proof has not completed on-chain verification.", "FX_RENEWAL_PROOF_UNVERIFIED");
  }
  const [publication] = await database
    .select({ id: fxPublicationJobs.id, state: fxPublicationJobs.state })
    .from(fxPublicationJobs)
    .where(and(
      eq(fxPublicationJobs.organizationId, run.organizationId),
      eq(fxPublicationJobs.catalogRoot, run.fxRoot),
    ))
    .limit(1);
  if (!publication || publication.state === "dead") {
    throw new ApiError(409, "The payroll FX publication evidence is unavailable.", "FX_RENEWAL_PUBLICATION_MISSING");
  }
  let authorizationNullifier = run.runNullifier;
  if (input.workflowType === "wage_remediation") {
    const [claimProof] = await database
      .select({
        proofVersion: proofBundles.proofVersion,
        proofPackage: proofBundles.proofPackage,
        verificationState: proofBundles.verificationState,
        verificationTransactionHash: proofBundles.verificationTransactionHash,
      })
      .from(proofBundles)
      .where(and(
        eq(proofBundles.organizationId, run.organizationId),
        eq(proofBundles.runId, run.id),
        eq(proofBundles.proofType, "wage_claim"),
        eq(proofBundles.proofVersion, "3"),
        eq(proofBundles.subjectRecordId, input.claimId),
      ))
      .limit(1);
    if (
      !claimProof
      || claimProof.verificationState !== "onchain_verified"
      || !claimProof.verificationTransactionHash
    ) {
      throw new ApiError(
        409,
        "The selected wage claim has not completed on-chain verification.",
        "FX_RENEWAL_CLAIM_NOT_VERIFIED",
      );
    }
    const [claimSettlement] = await database
      .select({ state: settlements.state, transactionHash: settlements.transactionHash })
      .from(settlements)
      .where(and(
        eq(settlements.organizationId, run.organizationId),
        eq(settlements.runId, run.id),
        eq(settlements.workflowType, "wage_claim"),
        eq(settlements.subjectRecordId, input.claimId),
      ))
      .limit(1);
    if (
      !claimSettlement?.transactionHash
      || !["confirmed", "finalized", "reconciled"].includes(claimSettlement.state)
    ) {
      throw new ApiError(
        409,
        "The selected wage claim has no finalized settlement.",
        "FX_RENEWAL_CLAIM_SETTLEMENT_INVALID",
      );
    }
    authorizationNullifier = exceptionAuthorizationNullifier({
      proofPackage: claimProof.proofPackage,
      claimId: input.claimId,
    });
  }
  return {
    runId: run.id,
    organizationId: run.organizationId,
    catalogRoot: run.fxRoot,
    runNullifier: run.runNullifier,
    authorizationNullifier,
    transactionHash: run.transactionHash,
  };
}

export async function enqueueHistoricalFxRenewal(input: {
  evidence: HistoricalFxRenewalEvidence;
  observedAt: number;
  principal: AuthenticatedPrincipal;
}) {
  if (!Number.isSafeInteger(input.observedAt) || input.observedAt < 0) {
    throw new ApiError(400, "The renewal block timestamp is invalid.", "FX_RENEWAL_TIME_INVALID");
  }
  await requireOrganizationRole(input.evidence.organizationId, input.principal, ["admin", "operator"]);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [run] = await transaction
      .select()
      .from(payrollRuns)
      .where(eq(payrollRuns.id, input.evidence.runId))
      .limit(1)
      .for("update");
    if (
      !run
      || run.organizationId !== input.evidence.organizationId
      || !run.fxRoot
      || !run.runNullifier
      || !run.transactionHash
      || BigInt(run.fxRoot) !== BigInt(input.evidence.catalogRoot)
      || BigInt(run.runNullifier) !== BigInt(input.evidence.runNullifier)
      || BigInt(run.transactionHash) !== BigInt(input.evidence.transactionHash)
    ) {
      throw new ApiError(409, "The payroll changed during FX renewal.", "FX_RENEWAL_EVIDENCE_CHANGED");
    }
    assertRenewablePayrollState(run.state);
    const [settlement] = await transaction
      .select({ transactionHash: settlements.transactionHash, state: settlements.state })
      .from(settlements)
      .where(and(
        eq(settlements.organizationId, run.organizationId),
        eq(settlements.runId, run.id),
        eq(settlements.workflowType, "payroll"),
      ))
      .limit(1)
      .for("update");
    if (
      !settlement?.transactionHash
      || BigInt(settlement.transactionHash) !== BigInt(run.transactionHash)
      || !["confirmed", "finalized", "reconciled"].includes(settlement.state)
    ) {
      throw new ApiError(409, "The payroll settlement changed during FX renewal.", "FX_RENEWAL_SETTLEMENT_CHANGED");
    }
    const [proof] = await transaction
      .select({ verificationState: proofBundles.verificationState })
      .from(proofBundles)
      .where(and(
        eq(proofBundles.organizationId, run.organizationId),
        eq(proofBundles.runId, run.id),
        eq(proofBundles.proofType, "payroll_integrity"),
        eq(proofBundles.subjectRecordId, run.id),
      ))
      .limit(1)
      .for("update");
    if (proof?.verificationState !== "onchain_verified") {
      throw new ApiError(409, "The payroll proof changed during FX renewal.", "FX_RENEWAL_PROOF_CHANGED");
    }
    const [job] = await transaction
      .select()
      .from(fxPublicationJobs)
      .where(and(
        eq(fxPublicationJobs.organizationId, run.organizationId),
        eq(fxPublicationJobs.catalogRoot, run.fxRoot),
      ))
      .limit(1)
      .for("update");
    if (!job || job.state === "dead") {
      throw new ApiError(409, "The payroll FX publication cannot be renewed.", "FX_RENEWAL_PUBLICATION_MISSING");
    }
    if (job.state === "pending" || job.state === "leased") {
      return { ...publicJob(job), replayed: true };
    }
    const now = new Date();
    const [renewed] = await transaction
      .update(fxPublicationJobs)
      .set({
        historicalRenewal: true,
        renewalRunId: run.id,
        renewalCount: job.renewalCount + 1,
        observedAt: input.observedAt,
        maximumAgeSeconds: 3_600,
        state: "pending",
        transactionHash: null,
        attempts: 0,
        availableAt: now,
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
      organizationId: run.organizationId,
      actorId: input.principal.principalId,
      action: "fx_publication.historical_renewal_queued",
      subjectId: job.id,
      metadata: {
        catalogRoot: run.fxRoot,
        runId: run.id,
        runNullifier: run.runNullifier,
        payrollTransactionHash: run.transactionHash,
        renewalCount: renewed.renewalCount,
        observedAt: input.observedAt,
        previousObservedAt: job.observedAt,
        previousTransactionHash: job.transactionHash,
      },
    });
    return { ...publicJob(renewed), replayed: false };
  });
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
          historicalRenewal: job.historicalRenewal,
          renewalRunId: job.renewalRunId,
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
