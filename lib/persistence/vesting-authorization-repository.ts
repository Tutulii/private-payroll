import "server-only";

import { and, eq, isNull, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  payrollIntegrityBundleMetadataSchema,
  payrollProofCalldataSchema,
  vestingAuthorizationRequestSchema,
  vestingBookProofSubmissionSchema,
  type VestingAuthorizationRequest,
} from "@/lib/domain/proof-bundle";
import { generateUuidV7 } from "@/lib/domain/records";
import type {
  PayrollIntegrityShardProof,
  VestingBookProof,
} from "@/lib/proof/protocol";
import {
  hashProofCalldata,
  parsePayrollPublicInputsFromGaragaCalldata,
  parseVestingTransitionPublicInputsFromGaragaCalldata,
} from "@/lib/proof/starknet-calldata";
import { buildBeginVestingAuthorizationCall } from "@/lib/starknet/payo-vesting-book";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  auditEvents,
  obligationSnapshotPlans,
  organizationMembers,
  payrollRuns,
  proofBundles,
  vestingAuthorizationJobs,
} from "./schema";

const LEASE_MS = 120_000;
const MAX_ATTEMPTS = 100;
const U128_LIMIT = 1n << 128n;

export type VestingAuthorizationStep =
  | "begin"
  | "payroll0"
  | "payroll1"
  | "transition0"
  | "transition1";

function safeErrorMessage(message: string): string {
  return message.replace(/[\r\n\t]+/g, " ").slice(0, 500);
}

function retryDelayMs(attempts: number): number {
  return Math.min(30_000, 1_500 * 2 ** Math.min(attempts, 4));
}

function canonicalTransactionHash(value: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
    throw new Error("Vesting authorization relayer returned an invalid transaction hash.");
  }
  return value.toLowerCase();
}

function combinedCommitment(high: string, low: string, label: string): `0x${string}` {
  const left = BigInt(high);
  const right = BigInt(low);
  if (left < 0n || left >= U128_LIMIT || right < 0n || right >= U128_LIMIT) {
    throw new ApiError(400, `${label} limbs exceed u128.`, "PROOF_PUBLIC_INPUT_INVALID");
  }
  return `0x${((left << 128n) | right).toString(16).padStart(64, "0")}`;
}

function asProofObjects(request: ReturnType<typeof vestingAuthorizationRequestSchema.parse>): {
  payrollShards: [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  vestingBook: VestingBookProof;
} {
  const payrollShards = request.payrollShards.map((proofCalldata, shardIndex) => ({
    shardIndex: shardIndex as 0 | 1,
    proof: new Uint8Array(),
    proofCalldata,
    calldataHash: hashProofCalldata(proofCalldata),
    publicInputs: parsePayrollPublicInputsFromGaragaCalldata(proofCalldata),
  })) as [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  const transitionShards = request.vestingBook.shards.map((shard) => {
    const publicInputs = parseVestingTransitionPublicInputsFromGaragaCalldata(shard.proofCalldata);
    const mismatch = (Object.keys(shard.publicInputs) as Array<keyof typeof shard.publicInputs>)
      .find((key) => BigInt(shard.publicInputs[key]) !== BigInt(publicInputs[key]));
    if (mismatch) {
      throw new ApiError(
        400,
        `Vesting shard ${shard.shardIndex} changed public input ${mismatch}.`,
        "PROOF_PUBLIC_INPUT_MISMATCH",
      );
    }
    return {
      shardIndex: shard.shardIndex,
      proof: new Uint8Array(),
      proofCalldata: shard.proofCalldata,
      calldataHash: shard.calldataHash,
      publicInputs,
    };
  }) as VestingBookProof["shards"];
  return {
    payrollShards,
    vestingBook: {
      ...request.vestingBook,
      scheduleId: request.vestingBook.scheduleId as `0x${string}`,
      previousStateCommitment: request.vestingBook.previousStateCommitment as `0x${string}`,
      nextStateCommitment: request.vestingBook.nextStateCommitment as `0x${string}`,
      releaseNullifier: request.vestingBook.releaseNullifier as `0x${string}`,
      bookEntryCommitment: request.vestingBook.bookEntryCommitment as `0x${string}`,
      provingTimeMs: 0,
      shards: transitionShards,
    },
  };
}

function assertPayrollBundle(
  metadata: ReturnType<typeof payrollIntegrityBundleMetadataSchema.parse>,
  shards: readonly [PayrollIntegrityShardProof, PayrollIntegrityShardProof],
): void {
  if (metadata.proofType !== "payroll_integrity" || metadata.proofVersion !== "2") {
    throw new ApiError(409, "State/book authorization requires Advanced PayrollIntegrity v2.", "VESTING_PAYROLL_VERSION_INVALID");
  }
  for (const index of [0, 1] as const) {
    if (BigInt(shards[index].calldataHash) !== BigInt(metadata.shardCalldataHashes[index])) {
      throw new ApiError(400, `Payroll shard ${index} differs from its durable proof bundle.`, "PROOF_CALLDATA_HASH_MISMATCH");
    }
    const publicInputs = shards[index].publicInputs;
    for (const key of Object.keys(metadata.commonInputs) as Array<keyof typeof metadata.commonInputs>) {
      if (BigInt(publicInputs[key]) !== BigInt(metadata.commonInputs[key])) {
        throw new ApiError(400, `Payroll shard ${index} changed public input ${key}.`, "PROOF_PUBLIC_INPUT_MISMATCH");
      }
    }
    if (BigInt(publicInputs.shardIndex) !== BigInt(index)) {
      throw new ApiError(400, `Payroll shard ${index} has the wrong index.`, "PROOF_SHARD_INDEX_MISMATCH");
    }
  }
  if (hashCanonicalJson([
    { ...metadata.commonInputs, shardIndex: "0" },
    { ...metadata.commonInputs, shardIndex: "1" },
  ]) !== metadata.publicInputsHash) {
    throw new ApiError(409, "The payroll proof bundle has an inconsistent public digest.", "PROOF_BUNDLE_INVALID");
  }
}

function publicJob(job: typeof vestingAuthorizationJobs.$inferSelect, replayed = false) {
  return {
    id: job.id,
    organizationId: job.organizationId,
    runId: job.runId,
    payrollProofBundleId: job.payrollProofBundleId,
    state: job.state,
    activeStep: job.activeStep,
    transactionHash: job.transactionHash,
    beginTransactionHash: job.beginTransactionHash,
    payrollShard0TransactionHash: job.payrollShard0TransactionHash,
    payrollShard1TransactionHash: job.payrollShard1TransactionHash,
    transitionShard0TransactionHash: job.transitionShard0TransactionHash,
    transitionShard1TransactionHash: job.transitionShard1TransactionHash,
    attempts: job.attempts,
    lastErrorCode: job.lastErrorCode,
    lastErrorMessage: job.lastErrorMessage,
    authorizedAt: job.authorizedAt?.toISOString() ?? null,
    createdAt: job.createdAt.toISOString(),
    updatedAt: job.updatedAt.toISOString(),
    replayed,
  };
}

export async function enqueueVestingAuthorization(input: {
  runId: string;
  request: VestingAuthorizationRequest;
  principal: AuthenticatedPrincipal;
  chainId: string;
  sealAddress: string;
}) {
  const request = vestingAuthorizationRequestSchema.parse(input.request);
  const proofs = asProofObjects(request);
  // This performs all deployment, cross-proof, book-entry and proof-hash
  // checks before anything reaches durable relay state.
  buildBeginVestingAuthorizationCall({
    sealAddress: input.sealAddress,
    chainId: input.chainId,
    ...proofs,
  });
  const requestCommitment = hashCanonicalJson(request);
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [run] = await transaction.select().from(payrollRuns)
      .where(eq(payrollRuns.id, input.runId)).limit(1).for("update");
    if (!run) throw new ApiError(404, "Payroll run not found.", "RUN_NOT_FOUND");
    const [membership] = await transaction.select({ role: organizationMembers.role })
      .from(organizationMembers).where(and(
        eq(organizationMembers.organizationId, run.organizationId),
        eq(organizationMembers.principalId, input.principal.principalId),
        isNull(organizationMembers.revokedAt),
      )).limit(1).for("update");
    if (!membership || !["admin", "operator"].includes(membership.role)) {
      throw new ApiError(403, "You cannot authorize this state/book payroll.", "ORG_FORBIDDEN");
    }
    if (run.state !== "proven") {
      throw new ApiError(409, "State/book authorization requires a proven payroll.", "RUN_NOT_PROVEN");
    }
    const [payrollBundle] = await transaction.select().from(proofBundles)
      .where(eq(proofBundles.id, request.payrollProofBundleId)).limit(1).for("update");
    if (!payrollBundle
      || payrollBundle.organizationId !== run.organizationId
      || payrollBundle.runId !== run.id
      || payrollBundle.proofType !== "payroll_integrity"
      || payrollBundle.subjectRecordId !== run.id
      || payrollBundle.verificationState !== "locally_verified") {
      throw new ApiError(404, "The Advanced v2 proof bundle does not belong to this run.", "PAYROLL_PROOF_BUNDLE_INVALID");
    }
    const payrollMetadata = payrollIntegrityBundleMetadataSchema.parse(payrollBundle.proofPackage);
    assertPayrollBundle(payrollMetadata, proofs.payrollShards);
    const agreementRoot = combinedCommitment(
      payrollMetadata.commonInputs.agreementRootHigh,
      payrollMetadata.commonInputs.agreementRootLow,
      "Agreement root",
    );
    const manifestRoot = combinedCommitment(
      payrollMetadata.commonInputs.manifestRootHigh,
      payrollMetadata.commonInputs.manifestRootLow,
      "Manifest root",
    );
    const policyRoot = combinedCommitment(
      payrollMetadata.commonInputs.policyRootHigh,
      payrollMetadata.commonInputs.policyRootLow,
      "Policy root",
    );
    const fxRoot = combinedCommitment(
      payrollMetadata.commonInputs.fxRootHigh,
      payrollMetadata.commonInputs.fxRootLow,
      "FX root",
    );
    const runNullifier = combinedCommitment(
      payrollMetadata.commonInputs.runNullifierHigh,
      payrollMetadata.commonInputs.runNullifierLow,
      "Run nullifier",
    );
    if (!run.agreementRoot || BigInt(run.agreementRoot) !== BigInt(agreementRoot)
      || !run.manifestRoot || BigInt(run.manifestRoot) !== BigInt(manifestRoot)
      || !run.policyRoot || BigInt(run.policyRoot) !== BigInt(policyRoot)
      || !run.fxRoot || BigInt(run.fxRoot) !== BigInt(fxRoot)
      || !run.runNullifier || BigInt(run.runNullifier) !== BigInt(runNullifier)) {
      throw new ApiError(409, "State/book authorization differs from the durable payroll run.", "PROOF_RUN_MISMATCH");
    }
    if (run.obligationSnapshotPlanId) {
      const [snapshot] = await transaction.select({ ownerAddress: obligationSnapshotPlans.ownerAddress })
        .from(obligationSnapshotPlans)
        .where(and(
          eq(obligationSnapshotPlans.id, run.obligationSnapshotPlanId),
          eq(obligationSnapshotPlans.runId, run.id),
        )).limit(1).for("update");
      if (!snapshot || BigInt(snapshot.ownerAddress) !== BigInt(request.vestingBook.bookEntry.ownerAddress)) {
        throw new ApiError(409, "The payroll-book owner differs from the protected payday owner.", "VESTING_BOOK_OWNER_MISMATCH");
      }
    }
    const nowSeconds = BigInt(Math.floor(Date.now() / 1_000));
    if (BigInt(payrollMetadata.commonInputs.validityExpiry) <= nowSeconds + 120n) {
      throw new ApiError(409, "The linked proofs have too little validity remaining.", "VESTING_PROOF_EXPIRED");
    }
    const [existing] = await transaction.select().from(vestingAuthorizationJobs)
      .where(eq(vestingAuthorizationJobs.runId, run.id)).limit(1).for("update");
    if (existing) {
      const stored = vestingBookProofSubmissionSchema.parse(existing.transitionMetadata);
      if (existing.payrollProofBundleId !== payrollBundle.id
        || hashCanonicalJson(stored) !== hashCanonicalJson(request.vestingBook)
        || hashCanonicalJson([
          existing.payrollShard0Calldata,
          existing.payrollShard1Calldata,
        ]) !== hashCanonicalJson(request.payrollShards)) {
        throw new ApiError(409, "This run already has a different state/book authorization.", "VESTING_AUTHORIZATION_CONFLICT");
      }
      return publicJob(existing, true);
    }
    const id = generateUuidV7();
    const [job] = await transaction.insert(vestingAuthorizationJobs).values({
      id,
      organizationId: run.organizationId,
      runId: run.id,
      payrollProofBundleId: payrollBundle.id,
      transitionMetadata: request.vestingBook,
      payrollShard0Calldata: request.payrollShards[0],
      payrollShard1Calldata: request.payrollShards[1],
      transitionShard0Calldata: request.vestingBook.shards[0].proofCalldata,
      transitionShard1Calldata: request.vestingBook.shards[1].proofCalldata,
    }).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: run.organizationId,
      actorId: input.principal.principalId,
      action: "vesting_authorization.queued",
      subjectId: id,
      metadata: {
        runId: run.id,
        payrollProofBundleId: payrollBundle.id,
        requestCommitment,
        entryKind: request.vestingBook.entryKind,
        bookEntryCommitment: request.vestingBook.bookEntryCommitment,
      },
    });
    return publicJob(job, false);
  });
}

export type LeasedVestingAuthorizationJob = {
  id: string;
  organizationId: string;
  runId: string;
  payrollProofBundleId: string;
  attempts: number;
  activeStep: VestingAuthorizationStep;
  transactionHash: string | null;
  beginTransactionHash: string | null;
  payrollShard0TransactionHash: string | null;
  payrollShard1TransactionHash: string | null;
  transitionShard0TransactionHash: string | null;
  transitionShard1TransactionHash: string | null;
  payrollShards: [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  vestingBook: VestingBookProof;
  leaseOwner: string;
};

function step(value: string): VestingAuthorizationStep {
  if (value === "begin" || value === "payroll0" || value === "payroll1"
    || value === "transition0" || value === "transition1") return value;
  throw new Error("Stored vesting authorization step is invalid.");
}

export async function leaseVestingAuthorizationJobs(
  workerId: string,
  limit = 1,
  now = new Date(),
): Promise<LeasedVestingAuthorizationJob[]> {
  if (!workerId.trim()) throw new Error("A vesting authorization worker ID is required.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 4) throw new Error("Vesting authorization lease limit must be 1–4.");
  const database = getDatabase();
  const leaseExpiresAt = new Date(now.getTime() + LEASE_MS);
  const leased = await database.update(vestingAuthorizationJobs).set({
    state: "leased", leaseOwner: workerId, leaseExpiresAt, updatedAt: now,
  }).where(sql`${vestingAuthorizationJobs.id} IN (
    SELECT jobs.id FROM vesting_authorization_jobs AS jobs
    WHERE (
      (jobs.state = 'pending' AND jobs.available_at <= ${now.toISOString()}::timestamptz)
      OR (jobs.state = 'leased' AND jobs.lease_expires_at <= ${now.toISOString()}::timestamptz)
    )
    ORDER BY jobs.available_at, jobs.created_at
    FOR UPDATE OF jobs SKIP LOCKED
    LIMIT ${limit}
  )`).returning();
  const output: LeasedVestingAuthorizationJob[] = [];
  for (const job of leased) {
    try {
      const request = vestingAuthorizationRequestSchema.parse({
        payrollProofBundleId: job.payrollProofBundleId,
        payrollShards: [
          payrollProofCalldataSchema.parse(job.payrollShard0Calldata),
          payrollProofCalldataSchema.parse(job.payrollShard1Calldata),
        ],
        vestingBook: job.transitionMetadata,
      });
      const proofs = asProofObjects(request);
      output.push({
        id: job.id,
        organizationId: job.organizationId,
        runId: job.runId,
        payrollProofBundleId: job.payrollProofBundleId,
        attempts: job.attempts,
        activeStep: step(job.activeStep),
        transactionHash: job.transactionHash,
        beginTransactionHash: job.beginTransactionHash,
        payrollShard0TransactionHash: job.payrollShard0TransactionHash,
        payrollShard1TransactionHash: job.payrollShard1TransactionHash,
        transitionShard0TransactionHash: job.transitionShard0TransactionHash,
        transitionShard1TransactionHash: job.transitionShard1TransactionHash,
        ...proofs,
        leaseOwner: workerId,
      });
    } catch (error) {
      await database.update(vestingAuthorizationJobs).set({
        state: "dead",
        leaseOwner: null,
        leaseExpiresAt: null,
        lastErrorCode: "VESTING_AUTHORIZATION_DATA_INVALID",
        lastErrorMessage: safeErrorMessage(error instanceof Error ? error.message : "Stored state/book authorization is invalid."),
        updatedAt: now,
      }).where(eq(vestingAuthorizationJobs.id, job.id));
    }
  }
  return output;
}

async function assertLease(
  transaction: Parameters<Parameters<ReturnType<typeof getDatabase>["transaction"]>[0]>[0],
  job: LeasedVestingAuthorizationJob,
): Promise<void> {
  const [leased] = await transaction.select({ id: vestingAuthorizationJobs.id })
    .from(vestingAuthorizationJobs).where(and(
      eq(vestingAuthorizationJobs.id, job.id),
      eq(vestingAuthorizationJobs.state, "leased"),
      eq(vestingAuthorizationJobs.leaseOwner, job.leaseOwner),
    )).limit(1).for("update");
  if (!leased) throw new Error("Vesting authorization lease is stale.");
}

export async function recordVestingAuthorizationSubmission(
  job: LeasedVestingAuthorizationJob,
  submittedStep: VestingAuthorizationStep,
  transactionHash: string,
  now = new Date(),
) {
  if (submittedStep !== job.activeStep) throw new Error("Vesting authorization submitted the wrong step.");
  const hash = canonicalTransactionHash(transactionHash);
  const receiptField = submittedStep === "begin"
    ? { beginTransactionHash: hash }
    : submittedStep === "payroll0"
      ? { payrollShard0TransactionHash: hash }
      : submittedStep === "payroll1"
        ? { payrollShard1TransactionHash: hash }
        : submittedStep === "transition0"
          ? { transitionShard0TransactionHash: hash }
          : { transitionShard1TransactionHash: hash };
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(vestingAuthorizationJobs).set({
      state: "pending",
      transactionHash: hash,
      ...receiptField,
      attempts: job.attempts + 1,
      availableAt: new Date(now.getTime() + 1_500),
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      updatedAt: now,
    }).where(eq(vestingAuthorizationJobs.id, job.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:vesting-authorization-relayer",
      action: "vesting_authorization.submitted",
      subjectId: job.id,
      metadata: { runId: job.runId, step: submittedStep, transactionHash: hash },
    });
    return updated;
  });
}

export async function advanceVestingAuthorizationJob(
  job: LeasedVestingAuthorizationJob,
  nextStep: VestingAuthorizationStep,
  now = new Date(),
) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(vestingAuthorizationJobs).set({
      state: "pending",
      activeStep: nextStep,
      transactionHash: null,
      availableAt: now,
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      updatedAt: now,
    }).where(eq(vestingAuthorizationJobs.id, job.id)).returning();
    return updated;
  });
}

export async function deferVestingAuthorizationJob(
  job: LeasedVestingAuthorizationJob,
  input: { errorCode: string; errorMessage: string; clearTransaction?: boolean; permanent?: boolean },
  now = new Date(),
) {
  const attempts = job.attempts + 1;
  const dead = input.permanent === true || attempts >= MAX_ATTEMPTS;
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(vestingAuthorizationJobs).set({
      state: dead ? "dead" : "pending",
      ...(input.clearTransaction ? { transactionHash: null } : {}),
      attempts,
      availableAt: new Date(now.getTime() + retryDelayMs(attempts)),
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: dead && !input.permanent ? "VESTING_AUTHORIZATION_TIMEOUT" : input.errorCode,
      lastErrorMessage: safeErrorMessage(input.errorMessage),
      updatedAt: now,
    }).where(eq(vestingAuthorizationJobs.id, job.id)).returning();
    return { ...updated, state: dead ? "dead" as const : "pending" as const };
  });
}

export async function completeVestingAuthorizationJob(
  job: LeasedVestingAuthorizationJob,
  now = new Date(),
) {
  const finalizedHash = job.transitionShard1TransactionHash ?? job.transactionHash;
  if (!finalizedHash) throw new Error("Vesting authorization lacks its final proof transaction.");
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(vestingAuthorizationJobs).set({
      state: "complete",
      transactionHash: finalizedHash,
      authorizedAt: now,
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      updatedAt: now,
    }).where(eq(vestingAuthorizationJobs.id, job.id)).returning();
    await transaction.update(proofBundles).set({
      verificationState: "onchain_verified",
      verificationTransactionHash: finalizedHash,
    }).where(eq(proofBundles.id, job.payrollProofBundleId));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:vesting-authorization-relayer",
      action: "vesting_authorization.completed",
      subjectId: job.id,
      metadata: {
        runId: job.runId,
        entryKind: job.vestingBook.entryKind,
        bookEntryCommitment: job.vestingBook.bookEntryCommitment,
        beginTransactionHash: job.beginTransactionHash,
        payrollShard0TransactionHash: job.payrollShard0TransactionHash,
        payrollShard1TransactionHash: job.payrollShard1TransactionHash,
        transitionShard0TransactionHash: job.transitionShard0TransactionHash,
        transitionShard1TransactionHash: finalizedHash,
      },
    });
    return updated;
  });
}

export async function getVestingAuthorizationJob(
  runId: string,
  principal: AuthenticatedPrincipal,
) {
  const database = getDatabase();
  const [job] = await database.select().from(vestingAuthorizationJobs)
    .where(eq(vestingAuthorizationJobs.runId, runId)).limit(1);
  if (!job) throw new ApiError(404, "State/book authorization job not found.", "VESTING_AUTHORIZATION_NOT_FOUND");
  await requireOrganizationRole(job.organizationId, principal, ["admin", "operator", "reviewer"]);
  return publicJob(job);
}
