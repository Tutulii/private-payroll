import { ed25519 } from "@noble/curves/ed25519.js";
import { readFileSync } from "node:fs";
import { sql } from "drizzle-orm";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import {
  decryptVaultRecord,
  generateVaultPrincipal,
  encryptVaultRecord,
  rewrapVaultRecord,
} from "@/lib/crypto/vault";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { signCapability, type AgentCapability, type PaymentIntent } from "@/lib/domain/capability";
import { generateUuidV7 } from "@/lib/domain/records";
import { prepareEncryptedAgentCapability } from "@/lib/client/agent-capabilities";
import { commitTokenTotals, type TokenTotals } from "@/lib/domain/settlement";
import {
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import {
  hashProofCalldata,
  parsePayrollPublicInputsFromGaragaCalldata,
} from "@/lib/proof/starknet-calldata";
import { ApiError, type AuthenticatedPrincipal } from "@/lib/server/auth";
import {
  reserveCapabilityPayment,
  transitionCapabilityReservation,
} from "./capability-reservations";
import {
  createEncryptedRun,
  getEncryptedRun,
  registerAgentCapability,
  revokeAgentCapability,
} from "./repository";
import {
  getChainCursor,
  getIndexedBlock,
  persistIndexedBlock,
  rollbackIndexedChain,
} from "./chain-indexer-repository";
import { closeDatabase, getDatabase } from "./db";
import { storeEncryptedPayrollIntegrityBundle } from "./proof-bundle-repository";
import {
  enqueueProofVerification,
  leaseProofVerificationJobs,
  recordProofVerificationProgress,
  recordProofVerificationSubmission,
} from "./proof-verification-repository";
import {
  applySettlementObservation,
  createSettlementIntent,
  leaseConfirmationJobs,
  recordSettlementSubmission,
} from "./settlement-repository";
import {
  createDisclosureGrant,
  createEncryptedReceipt,
  revokeDisclosureGrant,
} from "./receipt-repository";
import {
  addSecondAdministrator,
  getCurrentVaultKeyGrant,
  rotateOrganizationVault,
  storeEncryptedVaultRevision,
  storeEncryptedVaultRevisions,
} from "./vault-repository";
import {
  agentCapabilities,
  confirmationJobs,
  disclosureGrants,
  organizationMembers,
  organizations,
  payrollRuns,
  proofBundles,
  proofVerificationJobs,
  receipts,
  settlements,
  vaultRecords,
  vaultKeyGrants,
} from "./schema";

const testDatabaseUrl = process.env.PAYO_TEST_DATABASE_URL;
const databaseSuite = testDatabaseUrl ? describe : describe.skip;
const admin: AuthenticatedPrincipal = { principalId: "admin:test", sessionId: "session:admin" };
const agent: AuthenticatedPrincipal = { principalId: "agent:test", sessionId: "session:agent" };

async function resetDatabase() {
  await getDatabase().execute(sql`
    TRUNCATE TABLE
      audit_events,
      capability_reservations,
      agent_capabilities,
      receipts,
      disclosure_grants,
      indexed_chain_events,
      indexed_chain_blocks,
      chain_cursors,
      idempotency_requests,
      proof_verification_jobs,
      confirmation_jobs,
      settlements,
      proof_bundles,
      payroll_runs,
      vault_key_grants,
      vault_records,
      organization_members,
      organizations
    RESTART IDENTITY CASCADE
  `);
}

async function seedOrganization(principal = admin, role: "admin" | "operator" = "admin") {
  const id = generateUuidV7();
  await getDatabase().insert(organizations).values({
    id,
    encryptedProfile: { ciphertext: "client-only" },
    recoveryState: "package_downloaded",
  });
  await getDatabase().insert(organizationMembers).values({
    organizationId: id,
    principalId: principal.principalId,
    role,
    vaultPublicKey: "database-integration-public-key",
  });
  return id;
}

function prepareSettlementIntent(input: {
  organizationId: string;
  runId: string;
  principal?: AuthenticatedPrincipal;
  totals?: TokenTotals;
}) {
  const principal = input.principal ?? admin;
  const totals = input.totals ?? {
    STRK: "98765432109876543210",
    USDC: "123456789012345",
  };
  const id = generateUuidV7();
  const vaultPrincipal = generateVaultPrincipal(principal.principalId);
  const tokenTotalsCommitment = commitTokenTotals({
    organizationId: input.organizationId,
    runId: input.runId,
    totals,
  });
  const envelope = encryptVaultRecord(
    { tokenTotals: totals, tokenTotalsCommitment },
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "settlement",
      recordId: id,
      revision: 1,
    },
    [vaultPrincipal],
  );
  return {
    request: {
      id,
      organizationId: input.organizationId,
      runId: input.runId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: `settlement:${id}`,
      tokenTotalsCommitment,
      envelope,
      principal,
    },
    totals,
    vaultPrincipal,
  };
}

databaseSuite("PostgreSQL durability integration", () => {
  beforeEach(async () => {
    process.env.DATABASE_URL = testDatabaseUrl;
    process.env.PAYO_DB_POOL_SIZE = "8";
    await resetDatabase();
  });

  afterAll(async () => {
    await closeDatabase();
  });

  it("isolates encrypted tenants and enforces immutable sequential revisions", async () => {
    const organizationId = await seedOrganization();
    const otherOrganizationId = await seedOrganization({ principalId: "admin:other", sessionId: "other" });
    const vaultPrincipal = generateVaultPrincipal(admin.principalId);
    const recordId = generateUuidV7();
    const envelope = encryptVaultRecord(
      { salaryAtomic: "1000000000000000000" },
      { schemaVersion: 1, organizationId, recordType: "payee", recordId, revision: 1 },
      [vaultPrincipal],
    );
    const first = await storeEncryptedVaultRevision({
      organizationId,
      recordId,
      recordType: "payee",
      revision: 1,
      envelope,
      principal: admin,
    });
    expect(first.replayed).toBe(false);
    await expect(storeEncryptedVaultRevision({
      organizationId,
      recordId,
      recordType: "payee",
      revision: 1,
      envelope,
      principal: admin,
    })).resolves.toMatchObject({ replayed: true });
    const revisionThree = encryptVaultRecord(
      { salaryAtomic: "3" },
      { schemaVersion: 1, organizationId, recordType: "payee", recordId, revision: 3 },
      [vaultPrincipal],
    );
    await expect(storeEncryptedVaultRevision({
      organizationId,
      recordId,
      recordType: "payee",
      revision: 3,
      envelope: revisionThree,
      principal: admin,
    })).rejects.toMatchObject({ code: "RECORD_REVISION_GAP" });
    await expect(storeEncryptedVaultRevision({
      organizationId: otherOrganizationId,
      recordId,
      recordType: "payee",
      revision: 1,
      envelope,
      principal: admin,
    })).rejects.toMatchObject({ code: "ORG_FORBIDDEN" });
  });

  it("stores multi-record encrypted identity batches atomically", async () => {
    const organizationId = await seedOrganization();
    const vaultPrincipal = generateVaultPrincipal(admin.principalId);
    const principalId = generateUuidV7();
    const payeeId = generateUuidV7();
    const principalEnvelope = encryptVaultRecord(
      { displayName: "Private principal" },
      { schemaVersion: 1, organizationId, recordType: "principal", recordId: principalId, revision: 1 },
      [vaultPrincipal],
    );
    const payeeEnvelope = encryptVaultRecord(
      { principalId, salaryAtomic: "999" },
      { schemaVersion: 1, organizationId, recordType: "payee", recordId: payeeId, revision: 1 },
      [vaultPrincipal],
    );
    const batch = {
      organizationId,
      records: [
        { recordId: principalId, recordType: "principal" as const, revision: 1, envelope: principalEnvelope },
        { recordId: payeeId, recordType: "payee" as const, revision: 1, envelope: payeeEnvelope },
      ],
      principal: admin,
    };
    await expect(storeEncryptedVaultRevisions(batch)).resolves.toEqual([
      expect.objectContaining({ id: principalId, replayed: false }),
      expect.objectContaining({ id: payeeId, replayed: false }),
    ]);
    await expect(storeEncryptedVaultRevisions(batch)).resolves.toEqual([
      expect.objectContaining({ id: principalId, replayed: true }),
      expect.objectContaining({ id: payeeId, replayed: true }),
    ]);

    const rolledBackId = generateUuidV7();
    const rolledBackEnvelope = encryptVaultRecord(
      { shouldPersist: false },
      { schemaVersion: 1, organizationId, recordType: "principal", recordId: rolledBackId, revision: 1 },
      [vaultPrincipal],
    );
    const invalidRevision = encryptVaultRecord(
      { principalId, salaryAtomic: "1000" },
      { schemaVersion: 1, organizationId, recordType: "payee", recordId: payeeId, revision: 3 },
      [vaultPrincipal],
    );
    await expect(storeEncryptedVaultRevisions({
      organizationId,
      records: [
        { recordId: rolledBackId, recordType: "principal", revision: 1, envelope: rolledBackEnvelope },
        { recordId: payeeId, recordType: "payee", revision: 3, envelope: invalidRevision },
      ],
      principal: admin,
    })).rejects.toMatchObject({ code: "RECORD_REVISION_GAP" });
    expect((await getDatabase().select().from(vaultRecords)).some(({ id }) => id === rolledBackId)).toBe(false);
  });

  it("stores an encrypted payroll run and all encrypted lines in one transaction", async () => {
    const organizationId = await seedOrganization();
    const vaultPrincipal = generateVaultPrincipal(admin.principalId);
    const runId = generateUuidV7();
    const lineId = generateUuidV7();
    const runEnvelope = encryptVaultRecord(
      { cycleId: "cycle:atomic-lines", manifest: { lineCount: 1 } },
      { schemaVersion: 1, organizationId, recordType: "payroll-run", recordId: runId, revision: 1 },
      [vaultPrincipal],
    );
    const lineEnvelope = encryptVaultRecord(
      { agreementId: generateUuidV7(), netAtomic: "123456789" },
      { schemaVersion: 1, organizationId, recordType: "payroll-line", recordId: lineId, revision: 1 },
      [vaultPrincipal],
    );
    await expect(createEncryptedRun({
      id: runId,
      organizationId,
      cycleId: "cycle:atomic-lines",
      revision: 1,
      dueAt: "2026-08-24T00:00:00.000Z",
      ciphertext: runEnvelope.ciphertext,
      envelope: runEnvelope,
      agreementRoot: `0x${"11".repeat(32)}`,
      manifestRoot: `0x${"22".repeat(32)}`,
      policyRoot: `0x${"33".repeat(32)}`,
      fxRoot: `0x${"44".repeat(32)}`,
      runNullifier: `0x${"55".repeat(32)}`,
      lineRecords: [{ id: lineId, revision: 1, envelope: lineEnvelope }],
    }, admin)).resolves.toMatchObject({ id: runId });

    const records = await getDatabase().select().from(vaultRecords);
    expect(records.map(({ recordType }) => recordType).sort()).toEqual(["payroll-line", "payroll-run"]);
    const storedLine = records.find(({ id }) => id === lineId);
    expect(decryptVaultRecord(storedLine!.envelope as typeof lineEnvelope, vaultPrincipal))
      .toMatchObject({ netAtomic: "123456789" });
  });

  it("serves the latest re-encrypted run envelope after a vault key rotation", async () => {
    const organizationId = await seedOrganization();
    const vaultPrincipal = generateVaultPrincipal(admin.principalId);
    const runId = generateUuidV7();
    const revisionOne = encryptVaultRecord(
      { cycleId: "2026-08", secret: "old-key" },
      { schemaVersion: 1, organizationId, recordType: "payroll-run", recordId: runId, revision: 1 },
      [vaultPrincipal],
    );
    const revisionTwo = encryptVaultRecord(
      { cycleId: "2026-08", secret: "rotated-key" },
      { schemaVersion: 1, organizationId, recordType: "payroll-run", recordId: runId, revision: 2 },
      [vaultPrincipal],
    );
    await storeEncryptedVaultRevision({
      organizationId,
      recordId: runId,
      recordType: "payroll-run",
      revision: 1,
      envelope: revisionOne,
      principal: admin,
    });
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "2026-08",
      revision: 1,
      state: "draft",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
    });
    await storeEncryptedVaultRevision({
      organizationId,
      recordId: runId,
      recordType: "payroll-run",
      revision: 2,
      envelope: revisionTwo,
      principal: admin,
    });

    const run = await getEncryptedRun(runId, admin);
    expect(run.revision).toBe(1);
    expect(run.vaultRevision).toBe(2);
    expect(decryptVaultRecord(run.envelope as typeof revisionTwo, vaultPrincipal))
      .toMatchObject({ secret: "rotated-key" });
  });

  it("adds a second administrator and exposes only their encrypted current-key grant", async () => {
    const organizationId = await seedOrganization();
    const firstVaultAdmin = generateVaultPrincipal(admin.principalId);
    const secondPrincipal: AuthenticatedPrincipal = {
      principalId: "admin:recovery",
      sessionId: "session:recovery",
    };
    const secondVaultAdmin = generateVaultPrincipal(secondPrincipal.principalId);
    const encryptedProfile = encryptVaultRecord(
      { id: organizationId, name: "Encrypted tenant" },
      { schemaVersion: 1, organizationId, recordType: "organization-profile", recordId: organizationId, revision: 1 },
      [firstVaultAdmin],
    );
    await getDatabase().update(organizations).set({ encryptedProfile }).where(sql`${organizations.id} = ${organizationId}`);
    await getDatabase().update(organizationMembers).set({ vaultPublicKey: firstVaultAdmin.publicKey }).where(sql`${organizationMembers.organizationId} = ${organizationId}`);
    const grantId = generateUuidV7();
    const organizationSecret = `0x${"77".repeat(32)}`;
    const envelope = encryptVaultRecord(
      { organizationSecret, keyVersion: 1 },
      { schemaVersion: 1, organizationId, recordType: "vault-key-grant", recordId: grantId, revision: 1 },
      [secondVaultAdmin],
    );
    await expect(addSecondAdministrator({
      organizationId,
      grantId,
      granteePrincipalId: secondPrincipal.principalId,
      vaultPublicKey: secondVaultAdmin.publicKey,
      keyVersion: 1,
      envelope,
      encryptedProfile: rewrapVaultRecord(encryptedProfile, firstVaultAdmin, [firstVaultAdmin, secondVaultAdmin]),
      principal: admin,
    })).resolves.toMatchObject({ id: grantId, keyVersion: 1 });
    const grant = await getCurrentVaultKeyGrant({ organizationId, principal: secondPrincipal });
    expect(JSON.stringify(grant)).not.toContain(organizationSecret);
    expect(await getDatabase().select().from(vaultKeyGrants)).toHaveLength(1);
    expect(await getDatabase().select().from(organizationMembers)).toHaveLength(2);
    expect((await getDatabase().select().from(organizations))[0].recoveryState).toBe("second_admin");
  });

  it("rotates every latest DEK and revokes a second administrator atomically", async () => {
    const organizationId = await seedOrganization();
    const first = generateVaultPrincipal(admin.principalId);
    const secondPrincipal: AuthenticatedPrincipal = { principalId: "admin:revoked", sessionId: "session:revoked" };
    const second = generateVaultPrincipal(secondPrincipal.principalId);
    const profile = encryptVaultRecord(
      { name: "Rotation tenant" },
      { schemaVersion: 1, organizationId, recordType: "organization-profile", recordId: organizationId, revision: 1 },
      [first, second],
    );
    await getDatabase().update(organizations).set({ encryptedProfile: profile, recoveryState: "second_admin" }).where(sql`${organizations.id} = ${organizationId}`);
    await getDatabase().update(organizationMembers).set({ vaultPublicKey: first.publicKey }).where(sql`${organizationMembers.organizationId} = ${organizationId}`);
    await getDatabase().insert(organizationMembers).values({
      organizationId,
      principalId: second.principalId,
      role: "admin",
      vaultPublicKey: second.publicKey,
    });
    const recordId = generateUuidV7();
    const oldRecord = encryptVaultRecord(
      { salaryAtomic: "123" },
      { schemaVersion: 1, organizationId, recordType: "payee", recordId, revision: 1 },
      [first, second],
    );
    await getDatabase().insert(vaultRecords).values({
      id: recordId,
      organizationId,
      recordType: "payee",
      revision: 1,
      ciphertext: oldRecord.ciphertext,
      envelope: oldRecord,
      envelopeHash: hashCanonicalJson(oldRecord),
      createdBy: admin.principalId,
    });
    const rotatedRecord = encryptVaultRecord(
      { salaryAtomic: "123" },
      { schemaVersion: 1, organizationId, recordType: "payee", recordId, revision: 2 },
      [first],
    );
    const rotatedProfile = encryptVaultRecord(
      { name: "Rotation tenant" },
      { schemaVersion: 1, organizationId, recordType: "organization-profile", recordId: organizationId, revision: 2 },
      [first],
    );
    await expect(rotateOrganizationVault({
      organizationId,
      principal: admin,
      rotation: {
        expectedKeyVersion: 1,
        recoveryPackageHash: `0x${"88".repeat(32)}`,
        encryptedProfile: rotatedProfile,
        records: [{ recordId, recordType: "payee", revision: 2, envelope: rotatedRecord }],
        grants: [],
        revokePrincipalIds: [second.principalId],
      },
    })).resolves.toMatchObject({ keyVersion: 2, recoveryState: "package_downloaded" });
    const members = await getDatabase().select().from(organizationMembers);
    expect(members.find(({ principalId }) => principalId === second.principalId)?.revokedAt).not.toBeNull();
    const latest = (await getDatabase().select().from(vaultRecords).where(sql`${vaultRecords.id} = ${recordId}`))
      .sort((left, right) => right.revision - left.revision)[0];
    expect(decryptVaultRecord(latest.envelope as typeof rotatedRecord, first)).toMatchObject({ salaryAtomic: "123" });
    expect(() => decryptVaultRecord(latest.envelope as typeof rotatedRecord, second)).toThrow(/not authorized/i);
    await expect(getCurrentVaultKeyGrant({ organizationId, principal: secondPrincipal }))
      .rejects.toMatchObject({ code: "ORG_FORBIDDEN" });
  });

  it("deduplicates concurrent settlement intents and resumes confirmation after restart", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "2026-08",
      revision: 1,
      state: "proven",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
    });
    const prepared = prepareSettlementIntent({ organizationId, runId });
    const request = prepared.request;
    const [first, replay] = await Promise.all([
      createSettlementIntent(request),
      createSettlementIntent(request),
    ]);
    expect(new Set([first.id, replay.id]).size).toBe(1);
    expect([first.replayed, replay.replayed].sort()).toEqual([false, true]);
    const [storedSettlement] = await getDatabase().select().from(settlements);
    const [storedEnvelope] = await getDatabase().select().from(vaultRecords)
      .where(sql`${vaultRecords.id} = ${request.id}`);
    expect(JSON.stringify(storedSettlement)).not.toContain(prepared.totals.STRK);
    expect(JSON.stringify(storedSettlement)).not.toContain(prepared.totals.USDC);
    expect(JSON.stringify(storedEnvelope)).not.toContain(prepared.totals.STRK);
    expect(JSON.stringify(storedEnvelope)).not.toContain(prepared.totals.USDC);
    expect(decryptVaultRecord(storedEnvelope.envelope as typeof request.envelope, prepared.vaultPrincipal))
      .toMatchObject({ tokenTotals: prepared.totals });
    const settlementId = first.id;
    await recordSettlementSubmission({ settlementId, transactionHash: "0xabc", principal: admin });

    const [leased] = await leaseConfirmationJobs("worker-before-restart", 10, new Date("2030-08-24T12:00:00Z"));
    expect(leased.transactionHash).toBe("0xabc");
    await applySettlementObservation(leased, {
      state: "confirmed",
      confirmationDepth: 1,
      blockNumber: 100n,
      blockHash: "0x100",
    }, new Date("2030-08-24T12:00:01Z"));

    const [resumed] = await leaseConfirmationJobs("worker-after-restart", 10, new Date("2030-08-24T12:01:00Z"));
    expect(resumed.settlementId).toBe(settlementId);
    await applySettlementObservation(resumed, {
      state: "finalized",
      confirmationDepth: 3,
      blockNumber: 100n,
      blockHash: "0x100",
    }, new Date("2030-08-24T12:01:01Z"));
    const [run] = await getDatabase().select().from(payrollRuns);
    expect(run.state).toBe("confirmed");
  });

  it("stores receipts and revocable disclosure grants atomically with encrypted envelopes", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "receipt-cycle",
      revision: 1,
      state: "confirmed",
      dueAt: new Date("2030-08-31T00:00:00.000Z"),
      transactionHash: "0xabc",
    });
    const settlementId = generateUuidV7();
    await getDatabase().insert(settlements).values({
      id: settlementId,
      organizationId,
      runId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: `receipt-settlement:${settlementId}`,
      state: "confirmed",
      tokenTotalsCommitment: `0x${"33".repeat(32)}`,
      transactionHash: "0xabc",
      confirmedAt: new Date("2030-08-24T12:00:00Z"),
    });
    const principal = generateVaultPrincipal(admin.principalId);
    const receiptId = generateUuidV7();
    const privateAmount = "9876543210123456789";
    const receiptEnvelope = encryptVaultRecord(
      { privateAmount },
      { schemaVersion: 1, organizationId, recordType: "receipt", recordId: receiptId, revision: 1 },
      [principal],
    );
    const receiptInput = {
      id: receiptId,
      organizationId,
      runId,
      settlementId,
      scope: "employer" as const,
      granteePrincipalId: organizationId,
      packageCommitment: `0x${"44".repeat(32)}`,
      envelope: receiptEnvelope,
      principal: admin,
    };
    await expect(createEncryptedReceipt(receiptInput)).resolves.toMatchObject({ replayed: false });
    await expect(createEncryptedReceipt(receiptInput)).resolves.toMatchObject({ replayed: true });
    const [storedReceipt] = await getDatabase().select().from(receipts);
    const [storedReceiptEnvelope] = await getDatabase().select().from(vaultRecords)
      .where(sql`${vaultRecords.id} = ${receiptId}`);
    expect(JSON.stringify(storedReceipt)).not.toContain(privateAmount);
    expect(JSON.stringify(storedReceiptEnvelope)).not.toContain(privateAmount);

    const grantId = generateUuidV7();
    const grantEnvelope = encryptVaultRecord(
      { fieldScope: ["settlement"], recipientEncryptionKey: "private-grantee-key-material" },
      { schemaVersion: 1, organizationId, recordType: "disclosure-grant", recordId: grantId, revision: 1 },
      [principal],
    );
    await expect(createDisclosureGrant({
      id: grantId,
      organizationId,
      runId,
      granteePrincipalId: generateUuidV7(),
      fieldScope: ["settlement"],
      validAfter: new Date("2030-08-24T12:00:00Z"),
      expiresAt: new Date("2030-08-25T12:00:00Z"),
      envelope: grantEnvelope,
      principal: admin,
    })).resolves.toMatchObject({ replayed: false });
    await expect(revokeDisclosureGrant({ organizationId, grantId, principal: admin }))
      .resolves.toMatchObject({ id: grantId });
    expect((await getDatabase().select().from(disclosureGrants))[0].revokedAt).not.toBeNull();
  });

  it("keeps an unresolved submitted hash durable instead of classifying timeout as failure", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "confirmation-delay",
      revision: 1,
      state: "submitted",
      dueAt: new Date("2030-01-01T00:00:00.000Z"),
      transactionHash: "0xabc123",
    });
    const settlementId = generateUuidV7();
    await getDatabase().insert(settlements).values({
      id: settlementId,
      organizationId,
      runId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: "confirmation-delay-idempotency",
      state: "submitted",
      tokenTotalsCommitment: `0x${"11".repeat(32)}`,
      transactionHash: "0xabc123",
    });
    const jobId = generateUuidV7();
    await getDatabase().insert(confirmationJobs).values({
      id: jobId,
      settlementId,
      state: "leased",
      attempts: 79,
      leaseOwner: "worker-timeout",
    });
    await expect(applySettlementObservation({
      id: jobId,
      settlementId,
      attempts: 79,
      transactionHash: "0xabc123",
    }, { state: "pending", confirmationDepth: 0 }, new Date("2030-01-01T00:00:00.000Z")))
      .resolves.toMatchObject({ state: "pending", delayed: true });
    expect((await getDatabase().select().from(confirmationJobs))[0]).toMatchObject({
      state: "pending",
      attempts: 80,
      lastErrorCode: "CONFIRMATION_DELAYED",
    });
    expect((await getDatabase().select().from(settlements))[0]).toMatchObject({
      state: "submitted",
      transactionHash: "0xabc123",
      lastErrorCode: "CONFIRMATION_DELAYED",
    });
    expect((await getDatabase().select().from(payrollRuns))[0].state).toBe("submitted");
  });

  it("stores a locally verified proof only as ciphertext and atomically advances its run", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "2026-08-proof",
      revision: 1,
      state: "calculated",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
    });
    const proofBundleId = generateUuidV7();
    const vaultPrincipal = generateVaultPrincipal(admin.principalId);
    const secretProofPayload = {
      proofBase64: "this-proof-must-not-appear-outside-ciphertext",
      proofCalldata: ["0x123", "0x456"],
    };
    const envelope = encryptVaultRecord(
      secretProofPayload,
      {
        schemaVersion: 1,
        organizationId,
        recordType: "proof-bundle",
        recordId: proofBundleId,
        revision: 1,
      },
      [vaultPrincipal],
    );
    const shardCalldata = ([0, 1] as const).map((shard) => readFileSync(
      new URL(
        `../../contracts/integrity_verifier/tests/proof_calldata-shard-${shard}.txt`,
        import.meta.url,
      ),
      "utf8",
    ).trim().split(/\s+/)) as [string[], string[]];
    const parsedInputs = parsePayrollPublicInputsFromGaragaCalldata(shardCalldata[0]);
    const commonInputs = {
      chainId: `0x${BigInt(parsedInputs.chainId).toString(16)}`,
      sealAddress: `0x${BigInt(parsedInputs.sealAddress).toString(16)}`,
      proofVersion: BigInt(parsedInputs.proofVersion).toString(),
      schemaVersion: BigInt(parsedInputs.schemaVersion).toString(),
      agreementRootHigh: BigInt(parsedInputs.agreementRootHigh).toString(),
      agreementRootLow: BigInt(parsedInputs.agreementRootLow).toString(),
      manifestRootHigh: BigInt(parsedInputs.manifestRootHigh).toString(),
      manifestRootLow: BigInt(parsedInputs.manifestRootLow).toString(),
      policyRootHigh: BigInt(parsedInputs.policyRootHigh).toString(),
      policyRootLow: BigInt(parsedInputs.policyRootLow).toString(),
      fxRootHigh: BigInt(parsedInputs.fxRootHigh).toString(),
      fxRootLow: BigInt(parsedInputs.fxRootLow).toString(),
      runNullifierHigh: BigInt(parsedInputs.runNullifierHigh).toString(),
      runNullifierLow: BigInt(parsedInputs.runNullifierLow).toString(),
      validityStart: BigInt(parsedInputs.validityStart).toString(),
      validityExpiry: BigInt(parsedInputs.validityExpiry).toString(),
    };
    const shardCalldataHashes = [
      hashProofCalldata(shardCalldata[0]),
      hashProofCalldata(shardCalldata[1]),
    ] as [string, string];
    const bundle = {
      id: proofBundleId,
      organizationId,
      runId,
      revision: 1,
      proofType: "payroll_integrity" as const,
      proofVersion: "1",
      circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
      verificationKeySha256: PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
      publicInputsHash: hashCanonicalJson([
        { ...commonInputs, shardIndex: "0" },
        { ...commonInputs, shardIndex: "1" },
      ]),
      commonInputs,
      shardCalldataHashes,
      envelope,
    };
    const deployment = { chainId: "0x1", sealAddress: "0x12345" };
    await expect(storeEncryptedPayrollIntegrityBundle({ bundle, deployment, principal: admin }))
      .resolves.toMatchObject({ id: proofBundleId, replayed: false });
    await expect(storeEncryptedPayrollIntegrityBundle({ bundle, deployment, principal: admin }))
      .resolves.toMatchObject({ id: proofBundleId, replayed: true });

    const [storedProof] = await getDatabase().select().from(proofBundles);
    const [storedVault] = await getDatabase().select().from(vaultRecords);
    const [run] = await getDatabase().select().from(payrollRuns).where(sql`${payrollRuns.id} = ${runId}`);
    expect(storedProof.verificationState).toBe("locally_verified");
    expect(JSON.stringify(storedProof.proofPackage)).not.toContain(secretProofPayload.proofBase64);
    expect(JSON.stringify(storedVault.envelope)).not.toContain(secretProofPayload.proofBase64);
    expect(run).toMatchObject({
      state: "proven",
      agreementRoot: `0x${BigInt(commonInputs.agreementRootHigh).toString(16).padStart(32, "0")}${BigInt(commonInputs.agreementRootLow).toString(16).padStart(32, "0")}`,
      manifestRoot: `0x${BigInt(commonInputs.manifestRootHigh).toString(16).padStart(32, "0")}${BigInt(commonInputs.manifestRootLow).toString(16).padStart(32, "0")}`,
      runNullifier: `0x${BigInt(commonInputs.runNullifierHigh).toString(16).padStart(32, "0")}${BigInt(commonInputs.runNullifierLow).toString(16).padStart(32, "0")}`,
    });

    const settlementId = generateUuidV7();
    await getDatabase().insert(settlements).values({
      id: settlementId,
      organizationId,
      runId,
      walletRequestId: "proof-relay-wallet-request",
      idempotencyKey: "proof-relay-idempotency-key",
      state: "submitted",
      tokenTotalsCommitment: `0x${"22".repeat(32)}`,
      transactionHash: "0xabc",
    });
    await expect(enqueueProofVerification({
      settlementId,
      request: { proofBundleId, shards: shardCalldata },
      principal: admin,
    })).resolves.toMatchObject({ proofBundleId, replayed: false });
    await expect(enqueueProofVerification({
      settlementId,
      request: { proofBundleId, shards: shardCalldata },
      principal: admin,
    })).resolves.toMatchObject({ proofBundleId, replayed: true });
    const [proofJob] = await getDatabase().select().from(proofVerificationJobs);
    expect(proofJob).toMatchObject({ state: "pending", nextShard: 0 });
    expect(proofJob.shard0Calldata).toHaveLength(3_187);

    const modified = [[...shardCalldata[0]], shardCalldata[1]] as [string[], string[]];
    modified[0][100] = "0x1";
    await expect(enqueueProofVerification({
      settlementId,
      request: { proofBundleId, shards: modified },
      principal: admin,
    })).rejects.toMatchObject({ code: "PROOF_CALLDATA_HASH_MISMATCH" });

    await expect(leaseProofVerificationJobs(
      "proof-worker-too-early",
      2,
      new Date("2030-01-01T00:25:00.000Z"),
    )).resolves.toEqual([]);
    await getDatabase()
      .update(settlements)
      .set({ state: "finalized" })
      .where(sql`${settlements.id} = ${settlementId}`);

    const [shardZeroLease] = await leaseProofVerificationJobs(
      "proof-worker-before-restart",
      2,
      new Date("2030-01-01T00:25:00.000Z"),
    );
    expect(shardZeroLease).toMatchObject({ nextShard: 0, activeTransactionHash: null });
    await recordProofVerificationSubmission(
      shardZeroLease,
      0,
      "0x1000",
      new Date("2030-01-01T00:25:00.000Z"),
    );

    const [resumedShardZero] = await leaseProofVerificationJobs(
      "proof-worker-after-restart",
      2,
      new Date("2030-01-01T00:25:02.000Z"),
    );
    expect(resumedShardZero).toMatchObject({ nextShard: 0, activeTransactionHash: "0x1000" });
    await recordProofVerificationProgress(
      resumedShardZero,
      { nextShard: 1 },
      new Date("2030-01-01T00:25:02.000Z"),
    );

    const [shardOneLease] = await leaseProofVerificationJobs(
      "proof-worker-shard-one",
      2,
      new Date("2030-01-01T00:25:02.001Z"),
    );
    await recordProofVerificationSubmission(
      shardOneLease,
      1,
      "0x1001",
      new Date("2030-01-01T00:25:02.001Z"),
    );
    const [completeLease] = await leaseProofVerificationJobs(
      "proof-worker-completer",
      2,
      new Date("2030-01-01T00:25:04.000Z"),
    );
    await recordProofVerificationProgress(
      completeLease,
      { complete: true, verificationTransactionHash: "0x1001" },
      new Date("2030-01-01T00:25:04.000Z"),
    );
    const [completedJob] = await getDatabase().select().from(proofVerificationJobs);
    const [verifiedBundle] = await getDatabase().select().from(proofBundles);
    expect(completedJob).toMatchObject({ state: "complete", nextShard: 1 });
    expect(verifiedBundle).toMatchObject({
      verificationState: "onchain_verified",
      verificationTransactionHash: "0x1001",
    });
  }, 30_000);

  it("serializes concurrent capability reservations so period limits cannot race", async () => {
    const organizationId = await seedOrganization(agent, "operator");
    const capability: AgentCapability = {
      capabilityVersion: "payo-agent-capability-v1",
      id: "capability-race-0001",
      organizationId,
      principalId: agent.principalId,
      allowedActions: ["request_execution"],
      allowedTokens: ["STRK"],
      recipientScope: { mode: "allowlist", addresses: ["0x123"] },
      purposeCodes: ["monthly-payroll"],
      limits: [{
        token: "STRK",
        maxPerPaymentAtomic: "3000",
        maxPerPeriodAtomic: "3000",
        spentThisPeriodAtomic: "0",
        periodStartsAt: "2026-08-01T00:00:00.000Z",
        periodEndsAt: "2026-09-01T00:00:00.000Z",
        approvalThresholdAtomic: "3000",
      }],
      executionMode: "autonomous_bounded",
      validAfter: "2026-08-01T00:00:00.000Z",
      expiresAt: "2026-09-01T00:00:00.000Z",
      nonce: "capability-race-nonce-0001",
    };
    const signed = signCapability(capability, ed25519.keygen().secretKey);
    await getDatabase().insert(agentCapabilities).values({
      id: capability.id,
      organizationId,
      principalId: agent.principalId,
      capabilityHash: "0x1234",
      policy: signed,
      expiresAt: new Date(capability.expiresAt),
    });
    const intent = (id: string): PaymentIntent => ({
      intentId: id,
      organizationId,
      action: "request_execution",
      token: "STRK",
      recipientAddress: "0x123",
      amountAtomic: "2000",
      purposeCode: "monthly-payroll",
      capabilityNonce: capability.nonce,
      createdAt: "2026-08-24T10:00:00.000Z",
    });
    const results = await Promise.allSettled([
      reserveCapabilityPayment({
        capabilityId: capability.id,
        idempotencyKey: "capability-reserve-0001",
        intents: [intent("intent-race-0001")],
        principal: agent,
        now: new Date("2026-08-24T10:00:00.000Z"),
      }),
      reserveCapabilityPayment({
        capabilityId: capability.id,
        idempotencyKey: "capability-reserve-0002",
        intents: [intent("intent-race-0002")],
        principal: agent,
        now: new Date("2026-08-24T10:00:00.000Z"),
      }),
    ]);
    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    const denied = results.find(({ status }) => status === "rejected");
    expect(denied).toMatchObject({ reason: expect.objectContaining({ code: "PERIOD_LIMIT_EXCEEDED" }) });
    const accepted = results.find((result) => result.status === "fulfilled");
    if (!accepted || accepted.status !== "fulfilled") throw new Error("Expected one accepted reservation.");
    await expect(transitionCapabilityReservation({
      capabilityId: capability.id,
      reservationId: accepted.value.id,
      state: "committed",
      principal: agent,
      now: new Date("2026-08-24T10:01:00.000Z"),
    })).resolves.toMatchObject({ state: "committed", replayed: false });
  });

  it("registers and revokes a signed capability with its encrypted vault revisions atomically", async () => {
    const organizationId = await seedOrganization();
    const vaultPrincipal = generateVaultPrincipal(admin.principalId);
    const capabilityPrincipalId = generateUuidV7();
    const prepared = prepareEncryptedAgentCapability({
      organizationId,
      organizationSecret: `0x${"42".repeat(32)}`,
      principalId: capabilityPrincipalId,
      recipientAddresses: ["0x123"],
      limits: [{
        token: "USDC",
        maxPerPaymentAtomic: "2000000",
        maxPerPeriodAtomic: "8000000",
        approvalThresholdAtomic: "2000000",
      }],
      vaultPrincipal,
      now: new Date("2026-08-24T10:00:00.000Z"),
      expiresAt: new Date("2026-09-24T10:00:00.000Z"),
    });
    await expect(registerAgentCapability({
      signedCapability: prepared.signedCapability,
      recordId: prepared.record.id,
      revision: 1,
      envelope: prepared.envelope,
    }, admin)).resolves.toMatchObject({
      id: prepared.record.id,
      capabilityHash: prepared.record.capabilityHash,
      replayed: false,
    });
    await expect(registerAgentCapability({
      signedCapability: prepared.signedCapability,
      recordId: prepared.record.id,
      revision: 1,
      envelope: prepared.envelope,
    }, admin)).resolves.toMatchObject({ replayed: true });

    const [storedCapability] = await getDatabase().select().from(agentCapabilities);
    const [storedRevision] = await getDatabase().select().from(vaultRecords);
    expect(storedCapability).toMatchObject({
      id: prepared.record.id,
      principalId: capabilityPrincipalId,
      capabilityHash: prepared.record.capabilityHash,
    });
    expect(decryptVaultRecord(storedRevision.envelope as never, vaultPrincipal)).toEqual(prepared.record);

    const revokedAt = "2026-08-25T10:00:00.000Z";
    const revokedRecord = { ...prepared.record, revision: 2, updatedAt: revokedAt, revokedAt };
    const revocationEnvelope = encryptVaultRecord(
      revokedRecord,
      {
        schemaVersion: 1,
        organizationId,
        recordType: "agent-capability",
        recordId: prepared.record.id,
        revision: 2,
      },
      [vaultPrincipal],
    );
    await expect(revokeAgentCapability({
      capabilityId: prepared.record.id,
      organizationId,
      revision: 2,
      envelope: revocationEnvelope,
    }, admin)).resolves.toMatchObject({ id: prepared.record.id, replayed: false });
    const revisions = await getDatabase()
      .select()
      .from(vaultRecords)
      .where(sql`${vaultRecords.id} = ${prepared.record.id}`);
    expect(revisions).toHaveLength(2);
    expect(revisions.find(({ revision }) => revision === 1)?.supersededAt).toBeInstanceOf(Date);
    expect(decryptVaultRecord(
      revisions.find(({ revision }) => revision === 2)?.envelope as never,
      vaultPrincipal,
    )).toEqual(revokedRecord);
  });

  it("rolls indexed blocks back and accepts the canonical replacement", async () => {
    await persistIndexedBlock({
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      blockNumber: 10n,
      blockHash: "0x10",
      parentHash: "0x9",
      events: [],
    });
    await persistIndexedBlock({
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      blockNumber: 11n,
      blockHash: "0x11",
      parentHash: "0x10",
      events: [{
        transactionHash: "0xabc",
        eventIndex: 0,
        contractAddress: "0x123",
        eventName: "0x456",
        payload: { keys: ["0x456"], data: [] },
      }],
    });
    await rollbackIndexedChain({
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      ancestorBlockNumber: 10n,
      ancestorBlockHash: "0x10",
    });
    await persistIndexedBlock({
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      blockNumber: 11n,
      blockHash: "0x21",
      parentHash: "0x10",
      events: [],
    });
    await expect(getChainCursor("SN_MAIN", "payo-seal")).resolves.toMatchObject({
      blockNumber: 11n,
      blockHash: "0x21",
    });
    await expect(getIndexedBlock("SN_MAIN", 11n)).resolves.toMatchObject({ blockHash: "0x21", canonical: true });
  });

  it("surfaces typed database errors rather than mislabelling conflicts", async () => {
    expect(new ApiError(409, "conflict", "CONFLICT")).toMatchObject({ status: 409, code: "CONFLICT" });
  });
});
