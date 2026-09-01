import "server-only";

import { and, eq, or } from "drizzle-orm";
import {
  commitDirectPrivacyProofDraft,
  commitDirectPrivacyFinalizationSubmission,
  commitDirectPrivacyReconciliationProof,
  directPrivacyProofDraftSchema,
  directPrivacyFinalizationSubmissionSchema,
  directPrivacyReconciliationProofSchema,
  type DirectPrivacyFinalizationSubmission,
  type DirectPrivacyProofDraft,
  type DirectPrivacyReconciliationProof,
} from "@/lib/domain/direct-privacy";
import { generateUuidV7 } from "@/lib/domain/records";
import type { SettlementMatchProofWorkerSuccess } from "@/lib/proof/protocol";
import {
  decryptDirectPrivacyPayload,
  encryptDirectPrivacyPayload,
} from "@/lib/server/direct-privacy-crypto";
import { getDatabase } from "./db";
import {
  auditEvents,
  directPrivacyAccounts,
  directPrivacyReconciliations,
  directPrivacyTreasuries,
  directPrivacySubmissions,
} from "./schema";

const DIGEST_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const HASH_PATTERN = /^0x[0-9a-fA-F]{1,64}$/;

type ReconciliationRow = typeof directPrivacyReconciliations.$inferSelect;
type DirectAccountRow = typeof directPrivacyAccounts.$inferSelect;

function decryptDraft(
  row: ReconciliationRow,
  account: DirectAccountRow,
): DirectPrivacyProofDraft | null {
  if (!row.draftCommitment || !row.encryptedDraft) return null;
  const draft = decryptDirectPrivacyPayload(row.encryptedDraft, {
    accountId: account.id,
    organizationId: account.organizationId,
    capabilityId: account.capabilityId,
    purpose: "proof-draft",
    executionId: row.executionId,
    draftCommitment: row.draftCommitment,
  });
  if (commitDirectPrivacyProofDraft(draft) !== row.draftCommitment) {
    throw new Error("DIRECT_PROOF_DRAFT_TAMPERED");
  }
  return draft;
}

function decryptProof(
  row: ReconciliationRow,
  account: DirectAccountRow,
): DirectPrivacyReconciliationProof | null {
  if (!row.proofCommitment || !row.encryptedProof) return null;
  const proof = decryptDirectPrivacyPayload(row.encryptedProof, {
    accountId: account.id,
    organizationId: account.organizationId,
    capabilityId: account.capabilityId,
    purpose: "reconciliation",
    executionId: row.executionId,
    proofCommitment: row.proofCommitment,
  });
  if (commitDirectPrivacyReconciliationProof(proof) !== row.proofCommitment) {
    throw new Error("DIRECT_RECONCILIATION_PROOF_TAMPERED");
  }
  return proof;
}

function decryptFinalization(
  row: ReconciliationRow,
  account: DirectAccountRow,
): DirectPrivacyFinalizationSubmission | null {
  if (
    row.activeChunkIndex === null
    || !row.activeFinalizationCommitment
    || !row.encryptedActiveFinalization
  ) return null;
  const submission = decryptDirectPrivacyPayload(row.encryptedActiveFinalization, {
    accountId: account.id,
    organizationId: account.organizationId,
    capabilityId: account.capabilityId,
    purpose: "finalization",
    executionId: row.executionId,
    chunkIndex: row.activeChunkIndex,
    finalizationCommitment: row.activeFinalizationCommitment,
  });
  if (
    commitDirectPrivacyFinalizationSubmission(submission)
      !== row.activeFinalizationCommitment
  ) {
    throw new Error("DIRECT_FINALIZATION_TAMPERED");
  }
  return submission;
}

export type LoadedDirectPrivacyReconciliation = {
  row: ReconciliationRow;
  account: DirectAccountRow;
  draft: DirectPrivacyProofDraft | null;
  proof: DirectPrivacyReconciliationProof | null;
  activeFinalization: DirectPrivacyFinalizationSubmission | null;
};

export async function ensureDirectPrivacyReconciliation(input: {
  executionId: string;
  accountId: string;
  organizationId: string;
  settlementRoot: string;
  transactionReference: string;
  now?: Date;
}): Promise<void> {
  if (
    !DIGEST_PATTERN.test(input.settlementRoot)
    || !DIGEST_PATTERN.test(input.transactionReference)
  ) throw new Error("DIRECT_RECONCILIATION_BINDING_INVALID");
  const now = input.now ?? new Date();
  await getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts).where(and(
      eq(directPrivacyAccounts.id, input.accountId),
      eq(directPrivacyAccounts.organizationId, input.organizationId),
    )).limit(1).for("update");
    // Revocation blocks new spends, but must never prevent proving and
    // finalizing a transfer that was already irreversibly submitted.
    if (!account) throw new Error("DIRECT_RECONCILIATION_ACCOUNT_INVALID");
    const [existing] = await transaction.select().from(directPrivacyReconciliations).where(
      eq(directPrivacyReconciliations.executionId, input.executionId),
    ).limit(1).for("update");
    if (existing) {
      if (
        existing.accountId !== input.accountId
        || existing.organizationId !== input.organizationId
        || existing.settlementRoot.toLowerCase() !== input.settlementRoot.toLowerCase()
        || existing.transactionReference.toLowerCase()
          !== input.transactionReference.toLowerCase()
      ) throw new Error("DIRECT_RECONCILIATION_REPLAY_CONFLICT");
      return;
    }
    await transaction.insert(directPrivacyReconciliations).values({
      executionId: input.executionId,
      accountId: input.accountId,
      organizationId: input.organizationId,
      state: "proving",
      settlementRoot: input.settlementRoot.toLowerCase(),
      transactionReference: input.transactionReference.toLowerCase(),
      createdAt: now,
      updatedAt: now,
    });
  });
}

export async function storeDirectPrivacyProofDraft(input: {
  executionId: string;
  requestCommitment: string;
  draft: DirectPrivacyProofDraft;
  now?: Date;
}): Promise<{ draftCommitment: `0x${string}` }> {
  const draft = directPrivacyProofDraftSchema.parse(input.draft);
  if (
    draft.executionId !== input.executionId
    || draft.requestCommitment.toLowerCase() !== input.requestCommitment.toLowerCase()
  ) throw new Error("DIRECT_PROOF_DRAFT_BINDING_INVALID");
  const draftCommitment = commitDirectPrivacyProofDraft(draft);
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    const [joined] = await transaction.select({
      row: directPrivacyReconciliations,
      account: directPrivacyAccounts,
      treasury: directPrivacyTreasuries,
    }).from(directPrivacyReconciliations).innerJoin(
      directPrivacyAccounts,
      eq(directPrivacyAccounts.id, directPrivacyReconciliations.accountId),
    ).innerJoin(
      directPrivacyTreasuries,
      eq(directPrivacyTreasuries.policyAccountAddress, directPrivacyAccounts.treasuryAddress),
    ).where(eq(directPrivacyReconciliations.executionId, input.executionId))
      .limit(1).for("update");
    if (
      !joined
      || joined.account.revokedAt
      || joined.treasury.organizationId !== joined.account.organizationId
      || joined.treasury.activeAccountId !== joined.account.id
      || joined.treasury.activeExecutionId !== input.executionId
      || joined.treasury.stateVersion !== draft.expectedStateVersion
    ) throw new Error("DIRECT_PROOF_DRAFT_ACCOUNT_STALE");
    if (
      draft.settlement.settlementRoot.toLowerCase() !== joined.row.settlementRoot
      || draft.settlement.transactionReference.toLowerCase()
        !== joined.row.transactionReference
    ) throw new Error("DIRECT_PROOF_DRAFT_SETTLEMENT_SUBSTITUTED");
    if (joined.row.draftCommitment) {
      if (joined.row.draftCommitment !== draftCommitment) {
        throw new Error("DIRECT_PROOF_DRAFT_REPLAY_CONFLICT");
      }
      return { draftCommitment };
    }
    const encryptedDraft = encryptDirectPrivacyPayload(draft, {
      accountId: joined.account.id,
      organizationId: joined.account.organizationId,
      capabilityId: joined.account.capabilityId,
      purpose: "proof-draft",
      executionId: input.executionId,
      draftCommitment,
    });
    await transaction.update(directPrivacyReconciliations).set({
      draftCommitment,
      encryptedDraft,
      updatedAt: now,
    }).where(eq(directPrivacyReconciliations.executionId, input.executionId));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: joined.account.organizationId,
      actorId: "system:direct-privacy-driver",
      action: "direct_privacy_proof_draft.stored",
      subjectId: input.executionId,
      metadata: {
        draftCommitment,
        pinnedBlock: draft.pinnedBlock.number,
      },
    });
    return { draftCommitment };
  });
}

export async function loadDirectPrivacyReconciliation(
  executionId: string,
): Promise<LoadedDirectPrivacyReconciliation | null> {
  const [joined] = await getDatabase().select({
    row: directPrivacyReconciliations,
    account: directPrivacyAccounts,
  }).from(directPrivacyReconciliations).innerJoin(
    directPrivacyAccounts,
    eq(directPrivacyAccounts.id, directPrivacyReconciliations.accountId),
  ).where(eq(directPrivacyReconciliations.executionId, executionId)).limit(1);
  if (!joined) return null;
  return {
    ...joined,
    draft: decryptDraft(joined.row, joined.account),
    proof: decryptProof(joined.row, joined.account),
    activeFinalization: decryptFinalization(joined.row, joined.account),
  };
}

export async function storeDirectPrivacyReconciliationProof(input: {
  executionId: string;
  requestCommitment: string;
  proof: SettlementMatchProofWorkerSuccess;
  now?: Date;
}): Promise<void> {
  const payload = directPrivacyReconciliationProofSchema.parse({
    version: "payo-direct-privacy-reconciliation-proof-v1",
    executionId: input.executionId,
    requestCommitment: input.requestCommitment,
    proof: input.proof,
  });
  const proofCommitment = commitDirectPrivacyReconciliationProof(payload);
  const now = input.now ?? new Date();
  await getDatabase().transaction(async (transaction) => {
    const [joined] = await transaction.select({
      row: directPrivacyReconciliations,
      account: directPrivacyAccounts,
    }).from(directPrivacyReconciliations).innerJoin(
      directPrivacyAccounts,
      eq(directPrivacyAccounts.id, directPrivacyReconciliations.accountId),
    ).where(eq(directPrivacyReconciliations.executionId, input.executionId))
      .limit(1).for("update");
    if (!joined) {
      throw new Error("DIRECT_RECONCILIATION_NOT_FOUND");
    }
    if (
      payload.proof.settlementRoot.toLowerCase() !== joined.row.settlementRoot
      || payload.proof.transactionReference.toLowerCase()
        !== joined.row.transactionReference
    ) throw new Error("DIRECT_RECONCILIATION_PROOF_SUBSTITUTED");
    if (joined.row.proofCommitment) {
      if (joined.row.proofCommitment !== proofCommitment) {
        throw new Error("DIRECT_RECONCILIATION_PROOF_REPLAY_CONFLICT");
      }
      return;
    }
    const encryptedProof = encryptDirectPrivacyPayload(payload, {
      accountId: joined.account.id,
      organizationId: joined.account.organizationId,
      capabilityId: joined.account.capabilityId,
      purpose: "reconciliation",
      executionId: input.executionId,
      proofCommitment,
    });
    await transaction.update(directPrivacyReconciliations).set({
      state: "ready",
      proofCommitment,
      encryptedProof,
      chunkCount: payload.proof.chunks.length,
      updatedAt: now,
    }).where(eq(directPrivacyReconciliations.executionId, input.executionId));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: joined.account.organizationId,
      actorId: "system:direct-privacy-driver",
      action: "direct_privacy_reconciliation.proved",
      subjectId: input.executionId,
      metadata: {
        proofCommitment,
        settlementRoot: joined.row.settlementRoot,
        transactionReference: joined.row.transactionReference,
        chunkCount: payload.proof.chunks.length,
      },
    });
  });
}

export async function storeDirectPrivacyFinalization(input: {
  submission: DirectPrivacyFinalizationSubmission;
  now?: Date;
}): Promise<{
  finalizationCommitment: string;
  expectedTransactionHash: string;
}> {
  const submission = directPrivacyFinalizationSubmissionSchema.parse(input.submission);
  const finalizationCommitment = commitDirectPrivacyFinalizationSubmission(submission);
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    const [joined] = await transaction.select({
      row: directPrivacyReconciliations,
      account: directPrivacyAccounts,
    }).from(directPrivacyReconciliations).innerJoin(
      directPrivacyAccounts,
      eq(directPrivacyAccounts.id, directPrivacyReconciliations.accountId),
    ).where(eq(directPrivacyReconciliations.executionId, submission.executionId))
      .limit(1).for("update");
    if (!joined || !["ready", "finalizing"].includes(joined.row.state)) {
      throw new Error("DIRECT_RECONCILIATION_NOT_READY");
    }
    const proof = decryptProof(joined.row, joined.account);
    const chunk = proof?.proof.chunks[submission.chunkIndex];
    if (
      !proof
      || proof.requestCommitment !== submission.requestCommitment
      || submission.chunkCount !== proof.proof.chunks.length
      || !chunk
      || chunk.calldataHash.toLowerCase() !== submission.calldataHash.toLowerCase()
    ) throw new Error("DIRECT_FINALIZATION_PROOF_BINDING_INVALID");
    if (joined.row.activeFinalizationCommitment) {
      if (
        joined.row.activeFinalizationCommitment !== finalizationCommitment
        || BigInt(joined.row.activeExpectedTransactionHash!)
          !== BigInt(submission.expectedTransactionHash)
      ) throw new Error("DIRECT_FINALIZATION_ACTIVE_CONFLICT");
      return {
        finalizationCommitment,
        expectedTransactionHash: joined.row.activeExpectedTransactionHash!,
      };
    }
    const encryptedActiveFinalization = encryptDirectPrivacyPayload(submission, {
      accountId: joined.account.id,
      organizationId: joined.account.organizationId,
      capabilityId: joined.account.capabilityId,
      purpose: "finalization",
      executionId: submission.executionId,
      chunkIndex: submission.chunkIndex,
      finalizationCommitment,
    });
    await transaction.update(directPrivacyReconciliations).set({
      state: "finalizing",
      activeChunkIndex: submission.chunkIndex,
      activeCalldataHash: submission.calldataHash.toLowerCase(),
      activeFinalizationCommitment: finalizationCommitment,
      encryptedActiveFinalization,
      activeExpectedTransactionHash: submission.expectedTransactionHash.toLowerCase(),
      activeTransactionHash: null,
      updatedAt: now,
    }).where(eq(directPrivacyReconciliations.executionId, submission.executionId));
    return {
      finalizationCommitment,
      expectedTransactionHash: submission.expectedTransactionHash,
    };
  });
}

export async function recordDirectPrivacyFinalizationBroadcast(input: {
  executionId: string;
  expectedTransactionHash: string;
  transactionHash: string;
  now?: Date;
}): Promise<void> {
  if (
    !HASH_PATTERN.test(input.expectedTransactionHash)
    || !HASH_PATTERN.test(input.transactionHash)
    || BigInt(input.expectedTransactionHash) !== BigInt(input.transactionHash)
  ) throw new Error("DIRECT_FINALIZATION_HASH_MISMATCH");
  const [updated] = await getDatabase().update(directPrivacyReconciliations).set({
    activeTransactionHash: input.transactionHash.toLowerCase(),
    updatedAt: input.now ?? new Date(),
  }).where(and(
    eq(directPrivacyReconciliations.executionId, input.executionId),
    eq(
      directPrivacyReconciliations.activeExpectedTransactionHash,
      input.expectedTransactionHash.toLowerCase(),
    ),
    eq(directPrivacyReconciliations.state, "finalizing"),
  )).returning();
  if (!updated) throw new Error("DIRECT_FINALIZATION_NOT_ACTIVE");
}

export async function completeDirectPrivacyFinalizationChunk(
  transactionHash: string,
  now = new Date(),
): Promise<void> {
  if (!HASH_PATTERN.test(transactionHash)) throw new Error("DIRECT_FINALIZATION_HASH_INVALID");
  await getDatabase().transaction(async (transaction) => {
    const [row] = await transaction.select().from(directPrivacyReconciliations).where(or(
      eq(
        directPrivacyReconciliations.activeExpectedTransactionHash,
        transactionHash.toLowerCase(),
      ),
      eq(directPrivacyReconciliations.activeTransactionHash, transactionHash.toLowerCase()),
    )).limit(1).for("update");
    if (!row || row.activeChunkIndex === null || row.chunkCount === null) {
      throw new Error("DIRECT_FINALIZATION_NOT_FOUND");
    }
    if (
      !row.activeTransactionHash
      || BigInt(row.activeTransactionHash) !== BigInt(transactionHash)
    ) throw new Error("DIRECT_FINALIZATION_HASH_UNRECORDED");
    await transaction.update(directPrivacyReconciliations).set({
      state: "ready",
      verifiedCount: Math.min(row.chunkCount, row.verifiedCount + 1),
      activeChunkIndex: null,
      activeCalldataHash: null,
      activeFinalizationCommitment: null,
      encryptedActiveFinalization: null,
      activeExpectedTransactionHash: null,
      activeTransactionHash: null,
      updatedAt: now,
    }).where(eq(directPrivacyReconciliations.executionId, row.executionId));
  });
}

export async function markDirectPrivacyReconciled(input: {
  executionId: string;
  verifiedCount: number;
  /** Required when all chunks were verified inside the confirmed payment tx. */
  atomicTransactionHash?: string;
  now?: Date;
}): Promise<void> {
  const now = input.now ?? new Date();
  await getDatabase().transaction(async (transaction) => {
    const [row] = await transaction.select().from(directPrivacyReconciliations).where(
      eq(directPrivacyReconciliations.executionId, input.executionId),
    ).limit(1).for("update");
    if (!row || !row.proofCommitment || row.chunkCount === null) {
      throw new Error("DIRECT_RECONCILIATION_NOT_PROVED");
    }
    if (row.activeChunkIndex !== null || input.verifiedCount !== row.chunkCount) {
      throw new Error("DIRECT_RECONCILIATION_INCOMPLETE");
    }
    if (row.verifiedCount !== row.chunkCount) {
      if (!input.atomicTransactionHash || !HASH_PATTERN.test(input.atomicTransactionHash)) {
        throw new Error("DIRECT_RECONCILIATION_INCOMPLETE");
      }
      const [submission] = await transaction.select().from(directPrivacySubmissions).where(
        eq(directPrivacySubmissions.executionId, input.executionId),
      ).limit(1).for("update");
      if (
        !submission
        || submission.state !== "confirmed"
        || !submission.transactionHash
        || BigInt(submission.transactionHash) !== BigInt(input.atomicTransactionHash)
        || BigInt(submission.expectedTransactionHash) !== BigInt(input.atomicTransactionHash)
      ) throw new Error("DIRECT_ATOMIC_FINALIZATION_UNCONFIRMED");
    }
    if (row.state === "reconciled") return;
    await transaction.update(directPrivacyReconciliations).set({
      state: "reconciled",
      verifiedCount: input.verifiedCount,
      updatedAt: now,
    }).where(eq(directPrivacyReconciliations.executionId, input.executionId));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: row.organizationId,
      actorId: "system:direct-privacy-driver",
      action: "direct_privacy_reconciliation.finalized",
      subjectId: input.executionId,
      metadata: {
        settlementRoot: row.settlementRoot,
        transactionReference: row.transactionReference,
        chunkCount: row.chunkCount,
      },
    });
  });
}
