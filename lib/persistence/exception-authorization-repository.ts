import "server-only";

import { and, eq, isNull, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  exceptionProofCalldataSchema,
  exceptionProofBundleMetadataSchema,
} from "@/lib/domain/proof-bundle";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  hashProofCalldata,
  parseExceptionPublicInputsFromGaragaCalldata,
} from "@/lib/proof/starknet-calldata";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  auditEvents,
  exceptionAuthorizationJobs,
  obligationClaimAccessGrants,
  organizationMembers,
  proofBundles,
  wageRemediations,
  workerClaims,
} from "./schema";

const LEASE_MS = 120_000;
const MAX_ATTEMPTS = 80;

function safeErrorMessage(message: string): string {
  return message.replace(/[\r\n\t]+/g, " ").slice(0, 500);
}

function transactionHash(value: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
    throw new Error("Exception relayer returned an invalid transaction hash.");
  }
  return value.toLowerCase();
}

function retryDelayMs(attempts: number): number {
  return Math.min(30_000, 1_500 * 2 ** Math.min(attempts, 4));
}

function publicCommitment(high: string, low: string): bigint {
  const upper = BigInt(high);
  const lower = BigInt(low);
  if (upper < 0n || upper >= 1n << 128n || lower < 0n || lower >= 1n << 128n) {
    throw new ApiError(400, "Exception proof commitment limbs exceed u128.", "PROOF_PUBLIC_INPUT_INVALID");
  }
  return (upper << 128n) | lower;
}

function assertPublicInputs(
  expected: ReturnType<typeof exceptionProofBundleMetadataSchema.parse>["publicInputs"],
  actual: ReturnType<typeof parseExceptionPublicInputsFromGaragaCalldata>,
) {
  for (const key of Object.keys(expected) as Array<keyof typeof expected>) {
    if (BigInt(expected[key]) !== BigInt(actual[key])) {
      throw new ApiError(
        400,
        `Exception proof public input ${key} does not match its encrypted bundle metadata.`,
        "PROOF_PUBLIC_INPUT_MISMATCH",
      );
    }
  }
}

export async function enqueueExceptionAuthorization(input: {
  proofBundleId: string;
  proofCalldata: string[];
  principal: AuthenticatedPrincipal;
}) {
  const proofCalldata = exceptionProofCalldataSchema.parse(input.proofCalldata);
  const calculatedHash = hashProofCalldata(proofCalldata);
  const actualInputs = parseExceptionPublicInputsFromGaragaCalldata(proofCalldata);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [bundle] = await transaction
      .select()
      .from(proofBundles)
      .where(eq(proofBundles.id, input.proofBundleId))
      .limit(1)
      .for("update");
    if (!bundle) throw new ApiError(404, "Exception proof bundle not found.", "PROOF_BUNDLE_NOT_FOUND");
    if (bundle.proofType !== "wage_claim" && bundle.proofType !== "wage_remediation") {
      throw new ApiError(409, "This proof profile is not an exception authorization.", "PROOF_TYPE_INVALID");
    }
    const metadata = exceptionProofBundleMetadataSchema.parse(bundle.proofPackage);
    if (metadata.proofType !== bundle.proofType || metadata.subjectRecordId !== bundle.subjectRecordId) {
      throw new ApiError(409, "Exception proof metadata does not match its durable subject.", "PROOF_BUNDLE_INVALID");
    }
    if (BigInt(calculatedHash) !== BigInt(metadata.proofCalldataHash)) {
      throw new ApiError(400, "Exception proof calldata does not match its committed hash.", "PROOF_CALLDATA_HASH_MISMATCH");
    }
    assertPublicInputs(metadata.publicInputs, actualInputs);
    if (hashCanonicalJson(metadata.publicInputs) !== metadata.publicInputsHash) {
      throw new ApiError(409, "Exception proof public-input digest is inconsistent.", "PROOF_BUNDLE_INVALID");
    }
    const nowSeconds = BigInt(Math.floor(Date.now() / 1_000));
    if (BigInt(metadata.publicInputs.validityExpiry) <= nowSeconds + 120n) {
      throw new ApiError(
        409,
        "The exception proof has too little validity remaining for safe authorization.",
        "PROOF_VALIDITY_EXPIRED",
      );
    }
    let routedWorkerClaim: typeof workerClaims.$inferSelect | undefined;
    let routedWageRemediation: typeof wageRemediations.$inferSelect | undefined;
    if (bundle.proofType === "wage_claim" && metadata.proofVersion === "6") {
      const [route] = await transaction.select({
        claim: workerClaims,
        grantRevokedAt: obligationClaimAccessGrants.revokedAt,
      }).from(workerClaims).innerJoin(
        obligationClaimAccessGrants,
        eq(obligationClaimAccessGrants.id, workerClaims.claimAccessGrantId),
      ).where(and(
        eq(workerClaims.id, bundle.subjectRecordId),
        eq(workerClaims.proofBundleId, bundle.id),
        eq(workerClaims.claimantPrincipalId, input.principal.principalId),
      )).limit(1).for("update");
      if (
        !route
        || route.grantRevokedAt
        || route.claim.organizationId !== bundle.organizationId
        || route.claim.runId !== bundle.runId
        || BigInt(route.claim.claimSubjectNullifier) !== publicCommitment(
          metadata.publicInputs.subjectNullifierHigh,
          metadata.publicInputs.subjectNullifierLow,
        )
        || BigInt(route.claim.claimFactCommitment) !== publicCommitment(
          metadata.publicInputs.factCommitmentHigh,
          metadata.publicInputs.factCommitmentLow,
        )
        || !["proved", "authorization_pending", "accepted", "rejected"].includes(route.claim.state)
      ) {
        throw new ApiError(403, "You cannot authorize this worker-owned Claim v6 proof.", "WORKER_CLAIM_FORBIDDEN");
      }
      routedWorkerClaim = route.claim;
    } else {
      const [membership] = await transaction
        .select({ role: organizationMembers.role })
        .from(organizationMembers)
        .where(and(
          eq(organizationMembers.organizationId, bundle.organizationId),
          eq(organizationMembers.principalId, input.principal.principalId),
          isNull(organizationMembers.revokedAt),
        ))
        .limit(1);
      if (!membership || !["admin", "operator"].includes(membership.role)) {
        throw new ApiError(403, "You cannot relay this exception proof.", "ORG_FORBIDDEN");
      }
    }
    if (bundle.proofType === "wage_remediation" && metadata.proofVersion === "7") {
      const [remediation] = await transaction.select().from(wageRemediations)
        .where(and(
          eq(wageRemediations.id, bundle.subjectRecordId),
          eq(wageRemediations.proofBundleId, bundle.id),
        ))
        .limit(1)
        .for("update");
      if (
        !remediation
        || remediation.organizationId !== bundle.organizationId
        || remediation.runId !== bundle.runId
        || !["proved", "authorization_pending", "authorized", "failed"].includes(
          remediation.state,
        )
        || BigInt(remediation.remediationSubjectNullifier) !== publicCommitment(
          metadata.publicInputs.subjectNullifierHigh,
          metadata.publicInputs.subjectNullifierLow,
        )
        || BigInt(remediation.remediationFactCommitment) !== publicCommitment(
          metadata.publicInputs.factCommitmentHigh,
          metadata.publicInputs.factCommitmentLow,
        )
        || BigInt(remediation.claimSubjectNullifier) !== publicCommitment(
          metadata.publicInputs.parentNullifierHigh,
          metadata.publicInputs.parentNullifierLow,
        )
        || BigInt(remediation.claimFactCommitment) !== publicCommitment(
          metadata.publicInputs.parentFactCommitmentHigh,
          metadata.publicInputs.parentFactCommitmentLow,
        )
        || BigInt(remediation.actionCommitment) !== publicCommitment(
          metadata.publicInputs.manifestRootHigh,
          metadata.publicInputs.manifestRootLow,
        )
        || Math.floor(remediation.validityExpiresAt.getTime() / 1_000)
          !== Number(metadata.publicInputs.validityExpiry)
      ) {
        throw new ApiError(
          409,
          "Remediation authorization differs from its exact durable v7 attempt.",
          "REMEDIATION_BINDING_MISMATCH",
        );
      }
      routedWageRemediation = remediation;
    }
    const [existing] = await transaction
      .select()
      .from(exceptionAuthorizationJobs)
      .where(and(
        eq(exceptionAuthorizationJobs.organizationId, bundle.organizationId),
        eq(exceptionAuthorizationJobs.workflowType, bundle.proofType),
        eq(exceptionAuthorizationJobs.subjectRecordId, bundle.subjectRecordId),
      ))
      .limit(1)
      .for("update");
    if (existing) {
      if (existing.proofBundleId !== bundle.id) {
        throw new ApiError(409, "This exception subject already uses another proof bundle.", "PROOF_JOB_CONFLICT");
      }
      if (existing.state === "dead") {
        const now = new Date();
        const [requeued] = await transaction.update(exceptionAuthorizationJobs).set({
          proofCalldata,
          state: "pending",
          transactionHash: null,
          attempts: 0,
          availableAt: now,
          leaseOwner: null,
          leaseExpiresAt: null,
          lastErrorCode: null,
          lastErrorMessage: null,
          updatedAt: now,
        }).where(eq(exceptionAuthorizationJobs.id, existing.id)).returning();
        if (routedWorkerClaim) {
          await transaction.update(workerClaims).set({
            state: "authorization_pending",
            updatedAt: now,
          }).where(eq(workerClaims.id, routedWorkerClaim.id));
        }
        if (routedWageRemediation) {
          await transaction.update(wageRemediations).set({
            state: "authorization_pending",
            lastErrorCode: null,
            lastErrorMessage: null,
            updatedAt: now,
          }).where(eq(wageRemediations.id, routedWageRemediation.id));
        }
        return { ...requeued, proofCalldata: undefined, replayed: false, requeued: true };
      }
      if (routedWorkerClaim && existing.state !== "complete") {
        await transaction.update(workerClaims).set({
          state: "authorization_pending",
          updatedAt: new Date(),
        }).where(eq(workerClaims.id, routedWorkerClaim.id));
      }
      if (routedWageRemediation && existing.state !== "complete") {
        await transaction.update(wageRemediations).set({
          state: "authorization_pending",
          updatedAt: new Date(),
        }).where(eq(wageRemediations.id, routedWageRemediation.id));
      }
      return { ...existing, proofCalldata: undefined, replayed: true, requeued: false };
    }
    const id = generateUuidV7();
    const [job] = await transaction.insert(exceptionAuthorizationJobs).values({
      id,
      organizationId: bundle.organizationId,
      runId: bundle.runId,
      proofBundleId: bundle.id,
      workflowType: bundle.proofType,
      subjectRecordId: bundle.subjectRecordId,
      proofCalldata,
    }).returning();
    if (routedWorkerClaim) {
      await transaction.update(workerClaims).set({
        state: "authorization_pending",
        updatedAt: new Date(),
      }).where(eq(workerClaims.id, routedWorkerClaim.id));
    }
    if (routedWageRemediation) {
      await transaction.update(wageRemediations).set({
        state: "authorization_pending",
        updatedAt: new Date(),
      }).where(eq(wageRemediations.id, routedWageRemediation.id));
    }
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: bundle.organizationId,
      actorId: input.principal.principalId,
      action: "exception_authorization.queued",
      subjectId: id,
      metadata: {
        runId: bundle.runId,
        proofBundleId: bundle.id,
        workflowType: bundle.proofType,
        subjectRecordId: bundle.subjectRecordId,
        calldataHash: calculatedHash,
      },
    });
    return { ...job, proofCalldata: undefined, replayed: false, requeued: false };
  });
}

export type LeasedExceptionAuthorizationJob = {
  id: string;
  organizationId: string;
  runId: string;
  proofBundleId: string;
  workflowType: "wage_claim" | "wage_remediation";
  subjectRecordId: string;
  attempts: number;
  transactionHash: string | null;
  proofCalldata: string[];
  publicInputs: ReturnType<typeof exceptionProofBundleMetadataSchema.parse>["publicInputs"];
  leaseOwner: string;
};

export async function leaseExceptionAuthorizationJobs(
  workerId: string,
  limit = 2,
  now = new Date(),
): Promise<LeasedExceptionAuthorizationJob[]> {
  if (!workerId.trim()) throw new Error("An exception relayer worker ID is required.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 10) {
    throw new Error("Exception relayer job limit must be 1–10.");
  }
  const database = getDatabase();
  const leaseExpiresAt = new Date(now.getTime() + LEASE_MS);
  return database.transaction(async (transaction) => {
    const leased = await transaction.update(exceptionAuthorizationJobs).set({
      state: "leased",
      leaseOwner: workerId,
      leaseExpiresAt,
      updatedAt: now,
    }).where(sql`${exceptionAuthorizationJobs.id} IN (
      SELECT jobs.id
      FROM exception_authorization_jobs AS jobs
      WHERE (
        (jobs.state = 'pending' AND jobs.available_at <= ${now.toISOString()}::timestamptz)
        OR (jobs.state = 'leased' AND jobs.lease_expires_at <= ${now.toISOString()}::timestamptz)
      )
      ORDER BY jobs.available_at, jobs.created_at
      FOR UPDATE OF jobs SKIP LOCKED
      LIMIT ${limit}
    )`).returning();
    const output: LeasedExceptionAuthorizationJob[] = [];
    for (const job of leased) {
      try {
        if (job.workflowType !== "wage_claim" && job.workflowType !== "wage_remediation") {
          throw new Error("Stored exception authorization type is invalid.");
        }
        const [bundle] = await transaction.select({ proofPackage: proofBundles.proofPackage })
          .from(proofBundles)
          .where(eq(proofBundles.id, job.proofBundleId))
          .limit(1);
        if (!bundle) throw new Error("Exception authorization references a missing proof bundle.");
        const metadata = exceptionProofBundleMetadataSchema.parse(bundle.proofPackage);
        output.push({
          id: job.id,
          organizationId: job.organizationId,
          runId: job.runId,
          proofBundleId: job.proofBundleId,
          workflowType: job.workflowType,
          subjectRecordId: job.subjectRecordId,
          attempts: job.attempts,
          transactionHash: job.transactionHash,
          proofCalldata: exceptionProofCalldataSchema.parse(job.proofCalldata),
          publicInputs: metadata.publicInputs,
          leaseOwner: workerId,
        });
      } catch (error) {
        await transaction.update(exceptionAuthorizationJobs).set({
          state: "dead",
          leaseOwner: null,
          leaseExpiresAt: null,
          lastErrorCode: "EXCEPTION_JOB_DATA_INVALID",
          lastErrorMessage: safeErrorMessage(error instanceof Error ? error.message : "Stored exception job is invalid."),
          updatedAt: now,
        }).where(eq(exceptionAuthorizationJobs.id, job.id));
      }
    }
    return output;
  });
}

async function assertLease(
  transaction: Parameters<Parameters<ReturnType<typeof getDatabase>["transaction"]>[0]>[0],
  job: LeasedExceptionAuthorizationJob,
) {
  const [leased] = await transaction.select({ id: exceptionAuthorizationJobs.id })
    .from(exceptionAuthorizationJobs)
    .where(and(
      eq(exceptionAuthorizationJobs.id, job.id),
      eq(exceptionAuthorizationJobs.state, "leased"),
      eq(exceptionAuthorizationJobs.leaseOwner, job.leaseOwner),
    ))
    .limit(1)
    .for("update");
  if (!leased) throw new Error("Exception authorization lease is stale.");
}

export async function recordExceptionAuthorizationSubmission(
  job: LeasedExceptionAuthorizationJob,
  submittedTransactionHash: string,
  now = new Date(),
) {
  const hash = transactionHash(submittedTransactionHash);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(exceptionAuthorizationJobs).set({
      state: "pending",
      transactionHash: hash,
      attempts: job.attempts + 1,
      availableAt: new Date(now.getTime() + 1_500),
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      updatedAt: now,
    }).where(eq(exceptionAuthorizationJobs.id, job.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:exception-relayer",
      action: "exception_authorization.submitted",
      subjectId: job.id,
      metadata: { workflowType: job.workflowType, transactionHash: hash },
    });
    return updated;
  });
}

export async function deferExceptionAuthorizationJob(
  job: LeasedExceptionAuthorizationJob,
  input: {
    errorCode: string;
    errorMessage: string;
    clearTransaction?: boolean;
    permanent?: boolean;
  },
  now = new Date(),
) {
  const attempts = job.attempts + 1;
  const dead = input.permanent === true || attempts >= MAX_ATTEMPTS;
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(exceptionAuthorizationJobs).set({
      state: dead ? "dead" : "pending",
      ...(input.clearTransaction ? { transactionHash: null } : {}),
      attempts,
      availableAt: new Date(now.getTime() + retryDelayMs(attempts)),
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: dead && !input.permanent ? "EXCEPTION_AUTHORIZATION_TIMEOUT" : input.errorCode,
      lastErrorMessage: safeErrorMessage(input.errorMessage),
      updatedAt: now,
    }).where(eq(exceptionAuthorizationJobs.id, job.id)).returning();
    if (job.workflowType === "wage_claim") {
      await transaction.update(workerClaims).set({
        state: dead ? "rejected" : "authorization_pending",
        updatedAt: now,
      }).where(and(
        eq(workerClaims.id, job.subjectRecordId),
        eq(workerClaims.proofBundleId, job.proofBundleId),
      ));
    } else {
      const expired = BigInt(Math.floor(now.getTime() / 1_000))
        >= BigInt(job.publicInputs.validityExpiry);
      await transaction.update(wageRemediations).set({
        state: dead ? (expired ? "expired" : "failed") : "authorization_pending",
        lastErrorCode: dead && !input.permanent
          ? "EXCEPTION_AUTHORIZATION_TIMEOUT"
          : input.errorCode,
        lastErrorMessage: safeErrorMessage(input.errorMessage),
        updatedAt: now,
      }).where(and(
        eq(wageRemediations.id, job.subjectRecordId),
        eq(wageRemediations.proofBundleId, job.proofBundleId),
      ));
    }
    return { ...updated, state: dead ? "dead" as const : "pending" as const };
  });
}

export async function completeExceptionAuthorizationJob(
  job: LeasedExceptionAuthorizationJob,
  now = new Date(),
) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(exceptionAuthorizationJobs).set({
      state: "complete",
      authorizedAt: now,
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      updatedAt: now,
    }).where(eq(exceptionAuthorizationJobs.id, job.id)).returning();
    await transaction.update(proofBundles).set({
      verificationState: "onchain_verified",
      verificationTransactionHash: job.transactionHash,
    }).where(eq(proofBundles.id, job.proofBundleId));
    if (job.workflowType === "wage_claim") {
      await transaction.update(workerClaims).set({
        state: "accepted",
        updatedAt: now,
      }).where(and(
        eq(workerClaims.id, job.subjectRecordId),
        eq(workerClaims.proofBundleId, job.proofBundleId),
      ));
    } else {
      await transaction.update(wageRemediations).set({
        state: "authorized",
        authorizedAt: now,
        lastErrorCode: null,
        lastErrorMessage: null,
        updatedAt: now,
      }).where(and(
        eq(wageRemediations.id, job.subjectRecordId),
        eq(wageRemediations.proofBundleId, job.proofBundleId),
      ));
    }
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:exception-relayer",
      action: "exception_authorization.completed",
      subjectId: job.id,
      metadata: {
        workflowType: job.workflowType,
        proofBundleId: job.proofBundleId,
        transactionHash: job.transactionHash,
      },
    });
    return updated;
  });
}

export async function getExceptionAuthorizationJob(
  proofBundleId: string,
  principal: AuthenticatedPrincipal,
) {
  const database = getDatabase();
  const [job] = await database.select({
    id: exceptionAuthorizationJobs.id,
    organizationId: exceptionAuthorizationJobs.organizationId,
    runId: exceptionAuthorizationJobs.runId,
    proofBundleId: exceptionAuthorizationJobs.proofBundleId,
    workflowType: exceptionAuthorizationJobs.workflowType,
    subjectRecordId: exceptionAuthorizationJobs.subjectRecordId,
    state: exceptionAuthorizationJobs.state,
    transactionHash: exceptionAuthorizationJobs.transactionHash,
    attempts: exceptionAuthorizationJobs.attempts,
    lastErrorCode: exceptionAuthorizationJobs.lastErrorCode,
    lastErrorMessage: exceptionAuthorizationJobs.lastErrorMessage,
    authorizedAt: exceptionAuthorizationJobs.authorizedAt,
    createdAt: exceptionAuthorizationJobs.createdAt,
    updatedAt: exceptionAuthorizationJobs.updatedAt,
  }).from(exceptionAuthorizationJobs)
    .where(eq(exceptionAuthorizationJobs.proofBundleId, proofBundleId))
    .limit(1);
  if (!job) throw new ApiError(404, "Exception authorization job not found.", "EXCEPTION_JOB_NOT_FOUND");
  if (job.workflowType === "wage_claim") {
    const [workerClaim] = await database.select({
      claimantPrincipalId: workerClaims.claimantPrincipalId,
    }).from(workerClaims).where(and(
      eq(workerClaims.id, job.subjectRecordId),
      eq(workerClaims.proofBundleId, job.proofBundleId),
    )).limit(1);
    if (workerClaim?.claimantPrincipalId === principal.principalId) return job;
  } else {
    const [remediation] = await database.select({
      claimantPrincipalId: wageRemediations.claimantPrincipalId,
    }).from(wageRemediations).where(and(
      eq(wageRemediations.id, job.subjectRecordId),
      eq(wageRemediations.proofBundleId, job.proofBundleId),
    )).limit(1);
    if (remediation?.claimantPrincipalId === principal.principalId) return job;
  }
  await requireOrganizationRole(job.organizationId, principal, ["admin", "operator", "reviewer"]);
  return job;
}
