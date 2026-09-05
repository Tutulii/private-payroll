import "server-only";

import { and, eq, or } from "drizzle-orm";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { vestingBookProofSubmissionSchema } from "@/lib/domain/proof-bundle";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole } from "./repository";
import {
  payrollRuns,
  settlements,
  vaultRecords,
  vestingAuthorizationJobs,
} from "./schema";

function sameFelt(left: string, right: string): boolean {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

/**
 * Returns ciphertext and public proof/settlement bindings needed to reconstruct
 * a complete payroll book locally. Salary facts never leave the vault envelope.
 */
export async function listPayrollBookReportSources(input: {
  organizationId: string;
  ownerAddress: string;
  periodStart: string;
  periodEnd: string;
  principal: AuthenticatedPrincipal;
}) {
  await requireOrganizationRole(
    input.organizationId,
    input.principal,
    ["admin", "operator", "reviewer"],
  );
  const rows = await getDatabase()
    .select({
      runId: payrollRuns.id,
      runRevision: payrollRuns.revision,
      runEnvelope: vaultRecords.envelope,
      transitionMetadata: vestingAuthorizationJobs.transitionMetadata,
      integrityVerificationTransactionHash: vestingAuthorizationJobs.transactionHash,
      settlementTransactionHash: settlements.transactionHash,
    })
    .from(vestingAuthorizationJobs)
    .innerJoin(payrollRuns, and(
      eq(payrollRuns.id, vestingAuthorizationJobs.runId),
      eq(payrollRuns.organizationId, vestingAuthorizationJobs.organizationId),
    ))
    .innerJoin(vaultRecords, and(
      eq(vaultRecords.organizationId, payrollRuns.organizationId),
      eq(vaultRecords.id, payrollRuns.id),
      eq(vaultRecords.recordType, "payroll-run"),
      eq(vaultRecords.revision, payrollRuns.revision),
    ))
    .innerJoin(settlements, and(
      eq(settlements.organizationId, payrollRuns.organizationId),
      eq(settlements.runId, payrollRuns.id),
      eq(settlements.workflowType, "payroll"),
      or(
        eq(settlements.state, "confirmed"),
        eq(settlements.state, "finalized"),
        eq(settlements.state, "reconciled"),
      ),
    ))
    .where(and(
      eq(vestingAuthorizationJobs.organizationId, input.organizationId),
      eq(vestingAuthorizationJobs.state, "complete"),
    ));

  const sources = rows.flatMap((row) => {
    const vestingBook = vestingBookProofSubmissionSchema.parse(row.transitionMetadata);
    if (
      !sameFelt(vestingBook.bookEntry.ownerAddress, input.ownerAddress)
      || vestingBook.bookEntry.periodStart !== input.periodStart
      || vestingBook.bookEntry.periodEnd !== input.periodEnd
    ) return [];
    if (!row.integrityVerificationTransactionHash || !row.settlementTransactionHash) {
      throw new ApiError(
        409,
        `Payroll-book source ${row.runId} is missing final on-chain evidence.`,
        "PAYROLL_BOOK_SOURCE_INCOMPLETE",
      );
    }
    return [{
      runId: row.runId,
      runRevision: row.runRevision,
      runEnvelope: encryptedVaultRecordSchema.parse(row.runEnvelope),
      entryKind: vestingBook.entryKind,
      bookEntry: vestingBook.bookEntry,
      bookEntryCommitment: vestingBook.bookEntryCommitment,
      integrityVerificationTransactionHash: row.integrityVerificationTransactionHash,
      settlementTransactionHash: row.settlementTransactionHash,
    }];
  });

  const seenRuns = new Set<string>();
  const seenEntries = new Set<string>();
  for (const source of sources) {
    const entryKey = BigInt(source.bookEntryCommitment).toString();
    if (seenRuns.has(source.runId) || seenEntries.has(entryKey)) {
      throw new ApiError(
        409,
        "The payroll book contains duplicate durable report sources.",
        "PAYROLL_BOOK_SOURCE_DUPLICATE",
      );
    }
    seenRuns.add(source.runId);
    seenEntries.add(entryKey);
  }
  return sources;
}
