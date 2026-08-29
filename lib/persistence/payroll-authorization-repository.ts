import "server-only";

import { and, eq, isNull, sql } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  exceptionProofBundleMetadataSchema,
  exceptionProofCalldataSchema,
  payrollAuthorizationRequestSchema,
  payrollIntegrityBundleMetadataSchema,
  payrollProofCalldataSchema,
  type PayrollAuthorizationRequest,
} from "@/lib/domain/proof-bundle";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  hashProofCalldata,
  parseExceptionPublicInputsFromGaragaCalldata,
  parsePayrollPublicInputsFromGaragaCalldata,
} from "@/lib/proof/starknet-calldata";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  auditEvents,
  organizationMembers,
  payrollAuthorizationJobs,
  payrollRuns,
  proofBundles,
} from "./schema";

const LEASE_MS = 120_000;
const MAX_ATTEMPTS = 80;
const U128_LIMIT = 1n << 128n;

export type PayrollAuthorizationStep = "begin" | "snapshot" | "shard0" | "shard1";

function safeErrorMessage(message: string): string {
  return message.replace(/[\r\n\t]+/g, " ").slice(0, 500);
}

function retryDelayMs(attempts: number): number {
  return Math.min(30_000, 1_500 * 2 ** Math.min(attempts, 4));
}

function canonicalTransactionHash(value: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
    throw new Error("Payroll authorization relayer returned an invalid transaction hash.");
  }
  return value.toLowerCase();
}

function combinedCommitment(highValue: string, lowValue: string, label: string): `0x${string}` {
  const high = BigInt(highValue);
  const low = BigInt(lowValue);
  if (high < 0n || high >= U128_LIMIT || low < 0n || low >= U128_LIMIT) {
    throw new ApiError(400, `${label} limbs exceed u128.`, "PROOF_PUBLIC_INPUT_INVALID");
  }
  return `0x${((high << 128n) | low).toString(16).padStart(64, "0")}`;
}

function assertPayrollInputs(
  expected: ReturnType<typeof payrollIntegrityBundleMetadataSchema.parse>["commonInputs"],
  actual: ReturnType<typeof parsePayrollPublicInputsFromGaragaCalldata>,
  shardIndex: 0 | 1,
) {
  for (const key of Object.keys(expected) as Array<keyof typeof expected>) {
    if (BigInt(expected[key]) !== BigInt(actual[key])) {
      throw new ApiError(400, `Payroll shard ${shardIndex} public input ${key} differs from its bundle.`, "PROOF_PUBLIC_INPUT_MISMATCH");
    }
  }
  if (BigInt(actual.shardIndex) !== BigInt(shardIndex)) {
    throw new ApiError(400, `Payroll shard ${shardIndex} has the wrong public index.`, "PROOF_SHARD_INDEX_MISMATCH");
  }
}

function assertSnapshotInputs(
  expected: ReturnType<typeof exceptionProofBundleMetadataSchema.parse>["publicInputs"],
  actual: ReturnType<typeof parseExceptionPublicInputsFromGaragaCalldata>,
) {
  for (const key of Object.keys(expected) as Array<keyof typeof expected>) {
    if (BigInt(expected[key]) !== BigInt(actual[key])) {
      throw new ApiError(400, `Snapshot public input ${key} differs from its bundle.`, "PROOF_PUBLIC_INPUT_MISMATCH");
    }
  }
}

function assertCrossBindings(input: {
  payroll: ReturnType<typeof payrollIntegrityBundleMetadataSchema.parse>["commonInputs"];
  snapshot: ReturnType<typeof exceptionProofBundleMetadataSchema.parse>["publicInputs"];
}) {
  const payroll = input.payroll;
  const snapshot = input.snapshot;
  if (
    payroll.proofVersion !== "2"
    || payroll.schemaVersion !== "1"
    || snapshot.proofVersion !== "5"
    || snapshot.schemaVersion !== "2"
    || snapshot.shardIndex !== "0"
  ) throw new ApiError(409, "The staged payroll requires PayrollIntegrity v2 and snapshot v5.", "PAYROLL_AUTHORIZATION_VERSION_INVALID");
  const pairs: Array<[string, string, string]> = [
    [payroll.chainId, snapshot.chainId, "chain"],
    [payroll.sealAddress, snapshot.sealAddress, "seal"],
    [payroll.agreementRootHigh, snapshot.agreementRootHigh, "agreement root high"],
    [payroll.agreementRootLow, snapshot.agreementRootLow, "agreement root low"],
    [payroll.policyRootHigh, snapshot.policyRootHigh, "policy root high"],
    [payroll.policyRootLow, snapshot.policyRootLow, "policy root low"],
    [payroll.runNullifierHigh, snapshot.subjectNullifierHigh, "run nullifier high"],
    [payroll.runNullifierLow, snapshot.subjectNullifierLow, "run nullifier low"],
  ];
  const mismatch = pairs.find(([left, right]) => BigInt(left) !== BigInt(right));
  if (mismatch) {
    throw new ApiError(409, `Payroll and snapshot differ at ${mismatch[2]}.`, "PAYROLL_SNAPSHOT_BINDING_MISMATCH");
  }
  if (
    BigInt(snapshot.parentNullifierHigh) !== 0n
    || BigInt(snapshot.parentNullifierLow) !== 0n
    || BigInt(snapshot.parentFactCommitmentHigh) !== 0n
    || BigInt(snapshot.parentFactCommitmentLow) !== 0n
    || BigInt(snapshot.fxRootHigh) !== 0n
    || BigInt(snapshot.fxRootLow) !== 0n
  ) throw new ApiError(409, "The pre-payday snapshot has non-canonical parent or FX bindings.", "PAYROLL_SNAPSHOT_BINDING_MISMATCH");
}

export async function enqueuePayrollAuthorization(input: {
  runId: string;
  request: PayrollAuthorizationRequest;
  principal: AuthenticatedPrincipal;
}) {
  const request = payrollAuthorizationRequestSchema.parse(input.request);
  const payrollHashes = request.payrollShards.map(hashProofCalldata) as [string, string];
  const snapshotHash = hashProofCalldata(request.snapshotProof);
  const payrollInputs = request.payrollShards.map(parsePayrollPublicInputsFromGaragaCalldata) as [
    ReturnType<typeof parsePayrollPublicInputsFromGaragaCalldata>,
    ReturnType<typeof parsePayrollPublicInputsFromGaragaCalldata>,
  ];
  const snapshotInputs = parseExceptionPublicInputsFromGaragaCalldata(request.snapshotProof);
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
      throw new ApiError(403, "You cannot authorize this payroll.", "ORG_FORBIDDEN");
    }
    if (run.state !== "proven") {
      throw new ApiError(409, "A staged payroll authorization requires a locally proven run.", "RUN_NOT_PROVEN");
    }
    // Keep statements on the transaction connection strictly sequential. Some
    // PostgreSQL drivers do not permit concurrent queries on one transaction,
    // and these row locks must be acquired deterministically.
    const [payrollBundle] = await transaction.select().from(proofBundles)
      .where(eq(proofBundles.id, request.payrollProofBundleId)).limit(1).for("update");
    const [snapshotBundle] = await transaction.select().from(proofBundles)
      .where(eq(proofBundles.id, request.snapshotProofBundleId)).limit(1).for("update");
    if (
      !payrollBundle
      || payrollBundle.organizationId !== run.organizationId
      || payrollBundle.runId !== run.id
      || payrollBundle.proofType !== "payroll_integrity"
      || payrollBundle.subjectRecordId !== run.id
      || payrollBundle.verificationState !== "locally_verified"
    ) throw new ApiError(404, "The PayrollIntegrity bundle does not belong to this run.", "PAYROLL_PROOF_BUNDLE_INVALID");
    if (
      !snapshotBundle
      || snapshotBundle.organizationId !== run.organizationId
      || snapshotBundle.runId !== run.id
      || snapshotBundle.proofType !== "obligation_snapshot"
      || snapshotBundle.subjectRecordId !== run.id
      || snapshotBundle.verificationState !== "locally_verified"
    ) throw new ApiError(404, "The obligation snapshot bundle does not belong to this run.", "SNAPSHOT_PROOF_BUNDLE_INVALID");
    const payrollMetadata = payrollIntegrityBundleMetadataSchema.parse(payrollBundle.proofPackage);
    const snapshotMetadata = exceptionProofBundleMetadataSchema.parse(snapshotBundle.proofPackage);
    for (const index of [0, 1] as const) {
      if (BigInt(payrollHashes[index]) !== BigInt(payrollMetadata.shardCalldataHashes[index])) {
        throw new ApiError(400, `Payroll shard ${index} differs from its committed hash.`, "PROOF_CALLDATA_HASH_MISMATCH");
      }
      assertPayrollInputs(payrollMetadata.commonInputs, payrollInputs[index], index);
    }
    if (BigInt(snapshotHash) !== BigInt(snapshotMetadata.proofCalldataHash)) {
      throw new ApiError(400, "Snapshot proof differs from its committed hash.", "PROOF_CALLDATA_HASH_MISMATCH");
    }
    assertSnapshotInputs(snapshotMetadata.publicInputs, snapshotInputs);
    if (hashCanonicalJson([
      { ...payrollMetadata.commonInputs, shardIndex: "0" },
      { ...payrollMetadata.commonInputs, shardIndex: "1" },
    ]) !== payrollMetadata.publicInputsHash
      || hashCanonicalJson(snapshotMetadata.publicInputs) !== snapshotMetadata.publicInputsHash) {
      throw new ApiError(409, "A staged proof bundle has an inconsistent public-input digest.", "PROOF_BUNDLE_INVALID");
    }
    assertCrossBindings({ payroll: payrollMetadata.commonInputs, snapshot: snapshotMetadata.publicInputs });
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
    if (
      !run.agreementRoot || BigInt(run.agreementRoot) !== BigInt(agreementRoot)
      || !run.manifestRoot || BigInt(run.manifestRoot) !== BigInt(manifestRoot)
      || !run.policyRoot || BigInt(run.policyRoot) !== BigInt(policyRoot)
      || !run.fxRoot || BigInt(run.fxRoot) !== BigInt(fxRoot)
      || !run.runNullifier || BigInt(run.runNullifier) !== BigInt(runNullifier)
    ) throw new ApiError(409, "The staged authorization does not match the durable payroll run.", "PROOF_RUN_MISMATCH");
    const nowSeconds = BigInt(Math.floor(Date.now() / 1_000));
    if (BigInt(snapshotMetadata.publicInputs.validityExpiry) <= nowSeconds + 120n) {
      throw new ApiError(409, "The snapshot proof has too little validity remaining.", "SNAPSHOT_PROOF_EXPIRED");
    }
    if (BigInt(payrollMetadata.commonInputs.validityExpiry) <= nowSeconds + 120n) {
      throw new ApiError(409, "The payroll proof has too little validity remaining.", "PAYROLL_PROOF_EXPIRED");
    }
    const [existing] = await transaction.select().from(payrollAuthorizationJobs)
      .where(eq(payrollAuthorizationJobs.runId, run.id)).limit(1).for("update");
    if (existing) {
      if (
        existing.payrollProofBundleId !== payrollBundle.id
        || existing.snapshotProofBundleId !== snapshotBundle.id
      ) throw new ApiError(409, "This run already uses another staged proof pair.", "PAYROLL_AUTHORIZATION_CONFLICT");
      return { ...existing, payrollShard0Calldata: undefined, payrollShard1Calldata: undefined, snapshotProofCalldata: undefined, replayed: true };
    }
    const id = generateUuidV7();
    const [job] = await transaction.insert(payrollAuthorizationJobs).values({
      id,
      organizationId: run.organizationId,
      runId: run.id,
      payrollProofBundleId: payrollBundle.id,
      snapshotProofBundleId: snapshotBundle.id,
      payrollShard0Calldata: request.payrollShards[0],
      payrollShard1Calldata: request.payrollShards[1],
      snapshotProofCalldata: request.snapshotProof,
    }).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: run.organizationId,
      actorId: input.principal.principalId,
      action: "payroll_authorization.queued",
      subjectId: id,
      metadata: {
        runId: run.id,
        payrollProofBundleId: payrollBundle.id,
        snapshotProofBundleId: snapshotBundle.id,
        payrollShardHashes: payrollHashes,
        snapshotProofHash: snapshotHash,
      },
    });
    return { ...job, payrollShard0Calldata: undefined, payrollShard1Calldata: undefined, snapshotProofCalldata: undefined, replayed: false };
  });
}

export type LeasedPayrollAuthorizationJob = {
  id: string;
  organizationId: string;
  runId: string;
  payrollProofBundleId: string;
  snapshotProofBundleId: string;
  attempts: number;
  activeStep: PayrollAuthorizationStep;
  transactionHash: string | null;
  beginTransactionHash: string | null;
  snapshotTransactionHash: string | null;
  shard0TransactionHash: string | null;
  shard1TransactionHash: string | null;
  payrollShards: readonly [string[], string[]];
  snapshotProof: string[];
  payrollPublicInputs: ReturnType<typeof payrollIntegrityBundleMetadataSchema.parse>["commonInputs"];
  snapshotPublicInputs: ReturnType<typeof exceptionProofBundleMetadataSchema.parse>["publicInputs"];
  payrollShardHashes: readonly [string, string];
  snapshotProofHash: string;
  leaseOwner: string;
};

function payrollStep(value: string): PayrollAuthorizationStep {
  if (value === "begin" || value === "snapshot" || value === "shard0" || value === "shard1") return value;
  throw new Error("Stored payroll authorization step is invalid.");
}

export async function leasePayrollAuthorizationJobs(
  workerId: string,
  limit = 1,
  now = new Date(),
): Promise<LeasedPayrollAuthorizationJob[]> {
  if (!workerId.trim()) throw new Error("A payroll authorization worker ID is required.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 4) throw new Error("Payroll authorization lease limit must be 1–4.");
  const database = getDatabase();
  const leaseExpiresAt = new Date(now.getTime() + LEASE_MS);
  return database.transaction(async (transaction) => {
    const leased = await transaction.update(payrollAuthorizationJobs).set({
      state: "leased", leaseOwner: workerId, leaseExpiresAt, updatedAt: now,
    }).where(sql`${payrollAuthorizationJobs.id} IN (
      SELECT jobs.id FROM payroll_authorization_jobs AS jobs
      WHERE (
        (jobs.state = 'pending' AND jobs.available_at <= ${now.toISOString()}::timestamptz)
        OR (jobs.state = 'leased' AND jobs.lease_expires_at <= ${now.toISOString()}::timestamptz)
      )
      ORDER BY jobs.available_at, jobs.created_at
      FOR UPDATE OF jobs SKIP LOCKED
      LIMIT ${limit}
    )`).returning();
    const output: LeasedPayrollAuthorizationJob[] = [];
    for (const job of leased) {
      try {
        const [payrollBundle] = await transaction.select({ proofPackage: proofBundles.proofPackage })
          .from(proofBundles).where(eq(proofBundles.id, job.payrollProofBundleId)).limit(1);
        const [snapshotBundle] = await transaction.select({ proofPackage: proofBundles.proofPackage })
          .from(proofBundles).where(eq(proofBundles.id, job.snapshotProofBundleId)).limit(1);
        if (!payrollBundle || !snapshotBundle) throw new Error("Staged authorization references a missing proof bundle.");
        const payrollMetadata = payrollIntegrityBundleMetadataSchema.parse(payrollBundle.proofPackage);
        const snapshotMetadata = exceptionProofBundleMetadataSchema.parse(snapshotBundle.proofPackage);
        output.push({
          id: job.id,
          organizationId: job.organizationId,
          runId: job.runId,
          payrollProofBundleId: job.payrollProofBundleId,
          snapshotProofBundleId: job.snapshotProofBundleId,
          attempts: job.attempts,
          activeStep: payrollStep(job.activeStep),
          transactionHash: job.transactionHash,
          beginTransactionHash: job.beginTransactionHash,
          snapshotTransactionHash: job.snapshotTransactionHash,
          shard0TransactionHash: job.shard0TransactionHash,
          shard1TransactionHash: job.shard1TransactionHash,
          payrollShards: [
            payrollProofCalldataSchema.parse(job.payrollShard0Calldata),
            payrollProofCalldataSchema.parse(job.payrollShard1Calldata),
          ],
          snapshotProof: exceptionProofCalldataSchema.parse(job.snapshotProofCalldata),
          payrollPublicInputs: payrollMetadata.commonInputs,
          snapshotPublicInputs: snapshotMetadata.publicInputs,
          payrollShardHashes: payrollMetadata.shardCalldataHashes,
          snapshotProofHash: snapshotMetadata.proofCalldataHash,
          leaseOwner: workerId,
        });
      } catch (error) {
        await transaction.update(payrollAuthorizationJobs).set({
          state: "dead",
          leaseOwner: null,
          leaseExpiresAt: null,
          lastErrorCode: "PAYROLL_AUTHORIZATION_DATA_INVALID",
          lastErrorMessage: safeErrorMessage(error instanceof Error ? error.message : "Stored staged authorization is invalid."),
          updatedAt: now,
        }).where(eq(payrollAuthorizationJobs.id, job.id));
      }
    }
    return output;
  });
}

async function assertLease(
  transaction: Parameters<Parameters<ReturnType<typeof getDatabase>["transaction"]>[0]>[0],
  job: LeasedPayrollAuthorizationJob,
) {
  const [leased] = await transaction.select({ id: payrollAuthorizationJobs.id })
    .from(payrollAuthorizationJobs).where(and(
      eq(payrollAuthorizationJobs.id, job.id),
      eq(payrollAuthorizationJobs.state, "leased"),
      eq(payrollAuthorizationJobs.leaseOwner, job.leaseOwner),
    )).limit(1).for("update");
  if (!leased) throw new Error("Payroll authorization lease is stale.");
}

export async function recordPayrollAuthorizationSubmission(
  job: LeasedPayrollAuthorizationJob,
  step: PayrollAuthorizationStep,
  submittedTransactionHash: string,
  now = new Date(),
) {
  if (step !== job.activeStep) throw new Error("Payroll authorization submitted the wrong step.");
  const hash = canonicalTransactionHash(submittedTransactionHash);
  const receiptField = step === "begin"
    ? { beginTransactionHash: hash }
    : step === "snapshot"
      ? { snapshotTransactionHash: hash }
      : step === "shard0"
        ? { shard0TransactionHash: hash }
        : { shard1TransactionHash: hash };
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(payrollAuthorizationJobs).set({
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
    }).where(eq(payrollAuthorizationJobs.id, job.id)).returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:payroll-authorization-relayer",
      action: "payroll_authorization.submitted",
      subjectId: job.id,
      metadata: { runId: job.runId, step, transactionHash: hash },
    });
    return updated;
  });
}

export async function advancePayrollAuthorizationJob(
  job: LeasedPayrollAuthorizationJob,
  nextStep: PayrollAuthorizationStep,
  now = new Date(),
) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(payrollAuthorizationJobs).set({
      state: "pending",
      activeStep: nextStep,
      transactionHash: null,
      availableAt: now,
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      updatedAt: now,
    }).where(eq(payrollAuthorizationJobs.id, job.id)).returning();
    return updated;
  });
}

export async function deferPayrollAuthorizationJob(
  job: LeasedPayrollAuthorizationJob,
  input: { errorCode: string; errorMessage: string; clearTransaction?: boolean; permanent?: boolean },
  now = new Date(),
) {
  const attempts = job.attempts + 1;
  const dead = input.permanent === true || attempts >= MAX_ATTEMPTS;
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(payrollAuthorizationJobs).set({
      state: dead ? "dead" : "pending",
      ...(input.clearTransaction ? { transactionHash: null } : {}),
      attempts,
      availableAt: new Date(now.getTime() + retryDelayMs(attempts)),
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: dead && !input.permanent ? "PAYROLL_AUTHORIZATION_TIMEOUT" : input.errorCode,
      lastErrorMessage: safeErrorMessage(input.errorMessage),
      updatedAt: now,
    }).where(eq(payrollAuthorizationJobs.id, job.id)).returning();
    return { ...updated, state: dead ? "dead" as const : "pending" as const };
  });
}

export async function completePayrollAuthorizationJob(
  job: LeasedPayrollAuthorizationJob,
  now = new Date(),
) {
  const finalizedTransactionHash = job.shard1TransactionHash ?? job.transactionHash;
  if (!finalizedTransactionHash) {
    throw new Error("Payroll authorization cannot complete without the finalized shard-one transaction.");
  }
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await assertLease(transaction, job);
    const [updated] = await transaction.update(payrollAuthorizationJobs).set({
      state: "complete",
      // Retain the terminal receipt on the public status row. The browser must
      // see canonical chain evidence before it is allowed to open Ready.
      transactionHash: finalizedTransactionHash,
      authorizedAt: now,
      leaseOwner: null,
      leaseExpiresAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      updatedAt: now,
    }).where(eq(payrollAuthorizationJobs.id, job.id)).returning();
    await transaction.update(proofBundles).set({
      verificationState: "onchain_verified",
      verificationTransactionHash: finalizedTransactionHash,
    }).where(eq(proofBundles.id, job.payrollProofBundleId));
    await transaction.update(proofBundles).set({
      verificationState: "onchain_verified",
      verificationTransactionHash: job.snapshotTransactionHash,
    }).where(eq(proofBundles.id, job.snapshotProofBundleId));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: job.organizationId,
      actorId: "system:payroll-authorization-relayer",
      action: "payroll_authorization.completed",
      subjectId: job.id,
      metadata: {
        runId: job.runId,
        beginTransactionHash: job.beginTransactionHash,
        snapshotTransactionHash: job.snapshotTransactionHash,
        shard0TransactionHash: job.shard0TransactionHash,
        shard1TransactionHash: job.shard1TransactionHash ?? job.transactionHash,
      },
    });
    return updated;
  });
}

export async function getPayrollAuthorizationJob(runId: string, principal: AuthenticatedPrincipal) {
  const database = getDatabase();
  const [job] = await database.select({
    id: payrollAuthorizationJobs.id,
    organizationId: payrollAuthorizationJobs.organizationId,
    runId: payrollAuthorizationJobs.runId,
    payrollProofBundleId: payrollAuthorizationJobs.payrollProofBundleId,
    snapshotProofBundleId: payrollAuthorizationJobs.snapshotProofBundleId,
    state: payrollAuthorizationJobs.state,
    activeStep: payrollAuthorizationJobs.activeStep,
    transactionHash: payrollAuthorizationJobs.transactionHash,
    beginTransactionHash: payrollAuthorizationJobs.beginTransactionHash,
    snapshotTransactionHash: payrollAuthorizationJobs.snapshotTransactionHash,
    shard0TransactionHash: payrollAuthorizationJobs.shard0TransactionHash,
    shard1TransactionHash: payrollAuthorizationJobs.shard1TransactionHash,
    attempts: payrollAuthorizationJobs.attempts,
    lastErrorCode: payrollAuthorizationJobs.lastErrorCode,
    lastErrorMessage: payrollAuthorizationJobs.lastErrorMessage,
    authorizedAt: payrollAuthorizationJobs.authorizedAt,
    createdAt: payrollAuthorizationJobs.createdAt,
    updatedAt: payrollAuthorizationJobs.updatedAt,
  }).from(payrollAuthorizationJobs).where(eq(payrollAuthorizationJobs.runId, runId)).limit(1);
  if (!job) throw new ApiError(404, "Payroll authorization job not found.", "PAYROLL_AUTHORIZATION_NOT_FOUND");
  await requireOrganizationRole(job.organizationId, principal, ["admin", "operator", "reviewer"]);
  return job;
}
