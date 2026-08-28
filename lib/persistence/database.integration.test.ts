import { ed25519 } from "@noble/curves/ed25519.js";
import { readFileSync } from "node:fs";
import { sql } from "drizzle-orm";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
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
import {
  commitPayoActionTokenTotals,
  commitTokenTotals,
  type TokenTotals,
} from "@/lib/domain/settlement";
import {
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import {
  hashProofCalldata,
  parsePayrollPublicInputsFromGaragaCalldata,
} from "@/lib/proof/starknet-calldata";
import { ApiError, requirePrincipal, type AuthenticatedPrincipal } from "@/lib/server/auth";
import { READY_AUTH_CHAIN_ID } from "@/lib/auth/ready-session";
import {
  completeReadyRecoveryLink,
  createReadyAuthenticationChallenge,
  createReadyRecoveryLink,
  verifyReadyAuthenticationChallenge,
} from "@/lib/server/ready-auth";
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
  listDueObligationSchedules,
  materializeDueObligationSchedules,
  registerObligationSchedules,
} from "./obligation-schedule-repository";
import {
  getChainCursor,
  getIndexedBlock,
  persistIndexedBlock,
  rollbackIndexedChain,
} from "./chain-indexer-repository";
import { closeDatabase, getDatabase } from "./db";
import { storeEncryptedPayrollIntegrityBundle } from "./proof-bundle-repository";
import {
  enqueueFxPublication,
  enqueueHistoricalFxRenewal,
  getHistoricalFxRenewalEvidence,
} from "./fx-publication-repository";
import {
  enqueueProofVerification,
  leaseProofVerificationJobs,
  recordProofVerificationProgress,
  recordProofVerificationSubmission,
} from "./proof-verification-repository";
import {
  applySettlementObservation,
  cancelSettlementApproval,
  createSettlementIntent,
  leaseConfirmationJobs,
  recordSettlementSubmission,
  recoverApprovalSubmissionsFromSealEvents,
  getSealedRunRecoveryEvidence,
} from "./settlement-repository";
import {
  createDisclosureGrant,
  createEncryptedReceipt,
  listDisclosureGrants,
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
  auditEvents,
  confirmationJobs,
  disclosureGrants,
  fxPublicationJobs,
  organizationMembers,
  obligationSchedules,
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
      fx_publication_jobs,
      indexed_chain_events,
      indexed_chain_blocks,
      chain_cursors,
      idempotency_requests,
      ready_recovery_link_challenges,
      ready_auth_sessions,
      ready_principal_links,
      ready_auth_challenges,
      proof_verification_jobs,
      confirmation_jobs,
      settlements,
      proof_bundles,
      payroll_runs,
      obligation_schedules,
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
      workflowType: "payroll" as const,
      subjectRecordId: input.runId,
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

function preparePhase3ExceptionProof(input: {
  profile: "claim" | "remediation";
  organizationId: string;
  runId: string;
  subjectRecordId: string;
  proofBundleId: string;
}) {
  const shards = ([0, 1] as const).map((shard) => readFileSync(
    new URL(`../../evidence/phase3-devnet-fixtures/${input.profile}-shard-${shard}.txt`, import.meta.url),
    "utf8",
  ).trim().split(/\s+/)) as [string[], string[]];
  const parsed = parsePayrollPublicInputsFromGaragaCalldata(shards[0]);
  const commonInputs = {
    chainId: `0x${BigInt(parsed.chainId).toString(16)}`,
    sealAddress: `0x${BigInt(parsed.sealAddress).toString(16)}`,
    proofVersion: BigInt(parsed.proofVersion).toString(),
    schemaVersion: BigInt(parsed.schemaVersion).toString(),
    agreementRootHigh: BigInt(parsed.agreementRootHigh).toString(),
    agreementRootLow: BigInt(parsed.agreementRootLow).toString(),
    manifestRootHigh: BigInt(parsed.manifestRootHigh).toString(),
    manifestRootLow: BigInt(parsed.manifestRootLow).toString(),
    policyRootHigh: BigInt(parsed.policyRootHigh).toString(),
    policyRootLow: BigInt(parsed.policyRootLow).toString(),
    fxRootHigh: BigInt(parsed.fxRootHigh).toString(),
    fxRootLow: BigInt(parsed.fxRootLow).toString(),
    runNullifierHigh: BigInt(parsed.runNullifierHigh).toString(),
    runNullifierLow: BigInt(parsed.runNullifierLow).toString(),
    validityStart: BigInt(parsed.validityStart).toString(),
    validityExpiry: BigInt(parsed.validityExpiry).toString(),
  };
  const profile = input.profile === "claim" ? {
    proofType: "wage_claim" as const,
    proofVersion: "3",
    circuitSha256: WAGE_CLAIM_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  } : {
    proofType: "wage_remediation" as const,
    proofVersion: "4",
    circuitSha256: WAGE_REMEDIATION_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  };
  const envelope = encryptVaultRecord(
    { profile: input.profile, shards },
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "proof-bundle",
      recordId: input.proofBundleId,
      revision: 1,
    },
    [generateVaultPrincipal(admin.principalId)],
  );
  return {
    shards,
    commonInputs,
    bundle: {
      id: input.proofBundleId,
      organizationId: input.organizationId,
      runId: input.runId,
      revision: 1,
      proofType: profile.proofType,
      subjectRecordId: input.subjectRecordId,
      proofVersion: profile.proofVersion,
      circuitSha256: profile.circuitSha256,
      verificationKeySha256: profile.verificationKeySha256,
      publicInputsHash: hashCanonicalJson([
        { ...commonInputs, shardIndex: "0" },
        { ...commonInputs, shardIndex: "1" },
      ]),
      commonInputs,
      shardCalldataHashes: [hashProofCalldata(shards[0]), hashProofCalldata(shards[1])] as [string, string],
      envelope,
    },
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

  it("cancels only an approval that has no submitted transaction hash", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "cancel-before-wallet-hash",
      revision: 1,
      state: "proven",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
    });
    const prepared = prepareSettlementIntent({ organizationId, runId });
    const settlement = await createSettlementIntent(prepared.request);

    await expect(cancelSettlementApproval({ settlementId: settlement.id, principal: admin }))
      .resolves.toMatchObject({ state: "failed", transactionHash: null });
    const [run] = await getDatabase().select().from(payrollRuns);
    expect(run.state).toBe("cancelled");
    await expect(recordSettlementSubmission({
      settlementId: settlement.id,
      transactionHash: "0xabc",
      principal: admin,
    })).rejects.toThrow(/invalid settlement transition/i);
  });

  it("keeps a confirmed payroll immutable while a wage-claim settlement confirms", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    const claimId = generateUuidV7();
    const proofBundleId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "wage-claim-exception",
      revision: 1,
      state: "confirmed",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
    });
    await getDatabase().insert(vaultRecords).values({
      id: claimId,
      organizationId,
      recordType: "wage-claim",
      revision: 1,
      ciphertext: "encrypted-claim",
      envelope: { ciphertext: "encrypted-claim" },
      envelopeHash: `0x${"51".repeat(32)}`,
      createdBy: admin.principalId,
    });
    await getDatabase().insert(proofBundles).values({
      id: proofBundleId,
      runId,
      organizationId,
      proofType: "wage_claim",
      proofVersion: "3",
      subjectRecordId: claimId,
      proofPackage: {},
      proofHash: `0x${"52".repeat(32)}`,
      verificationState: "locally_verified",
    });
    const settlementId = generateUuidV7();
    const totals = { STRK: "0", USDC: "0" };
    const tokenTotalsCommitment = commitPayoActionTokenTotals({
      organizationId,
      runId,
      workflowType: "wage_claim",
      subjectRecordId: claimId,
      totals,
    });
    const vaultPrincipal = generateVaultPrincipal(admin.principalId);
    const envelope = encryptVaultRecord(
      { workflowType: "wage_claim", subjectRecordId: claimId, tokenTotals: totals, tokenTotalsCommitment },
      {
        schemaVersion: 1,
        organizationId,
        recordType: "settlement",
        recordId: settlementId,
        revision: 1,
      },
      [vaultPrincipal],
    );
    const settlement = await createSettlementIntent({
      id: settlementId,
      organizationId,
      runId,
      workflowType: "wage_claim",
      subjectRecordId: claimId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: `wage-claim:${settlementId}`,
      tokenTotalsCommitment,
      envelope,
      principal: admin,
    });
    expect(settlement).toMatchObject({ workflowType: "wage_claim", subjectRecordId: claimId });
    expect((await getDatabase().select().from(payrollRuns))[0].state).toBe("confirmed");

    await recordSettlementSubmission({ settlementId, transactionHash: "0xc1a1", principal: admin });
    const [leased] = await leaseConfirmationJobs("claim-confirmation", 10, new Date("2099-08-25T12:00:00Z"));
    await applySettlementObservation(leased, {
      state: "finalized",
      confirmationDepth: 3,
      blockNumber: 321n,
      blockHash: "0x321",
    }, new Date("2099-08-25T12:00:01Z"));
    expect((await getDatabase().select().from(payrollRuns))[0].state).toBe("confirmed");

    const replay = await recordSettlementSubmission({
      settlementId,
      transactionHash: "0xc1a1",
      principal: admin,
    });
    expect(replay).toMatchObject({
      state: "finalized",
      blockNumber: "321",
      replayed: true,
    });
    expect(() => JSON.stringify({ settlement: replay })).not.toThrow();
  });

  it("finalizes a submitted settlement when the first receipt already has final depth", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "finalized-receipt-fast-forward",
      revision: 1,
      state: "proven",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
    });
    const prepared = prepareSettlementIntent({ organizationId, runId });
    const settlement = await createSettlementIntent(prepared.request);
    await recordSettlementSubmission({ settlementId: settlement.id, transactionHash: "0xf1", principal: admin });
    // The durable job's default available_at is the real insertion time. Use a
    // deliberately future worker clock so this remains deterministic no matter
    // when the integration suite is executed.
    const [leased] = await leaseConfirmationJobs("fast-forward-worker", 10, new Date("2099-08-25T12:00:00Z"));
    expect(leased).toBeDefined();

    await expect(applySettlementObservation(leased, {
      state: "finalized",
      confirmationDepth: 12,
      blockNumber: 123n,
      blockHash: "0x123",
    }, new Date("2099-08-25T12:00:01Z"))).resolves.toMatchObject({ state: "finalized" });

    const [storedSettlement] = await getDatabase().select().from(settlements);
    const [storedRun] = await getDatabase().select().from(payrollRuns);
    const [job] = await getDatabase().select().from(confirmationJobs);
    const storedAudit = await getDatabase().select({ action: auditEvents.action }).from(auditEvents)
      .where(sql`${auditEvents.subjectId} = ${settlement.id}`);
    expect(storedSettlement).toMatchObject({ state: "finalized", confirmationDepth: 12 });
    expect(storedRun.state).toBe("confirmed");
    expect(job.state).toBe("complete");
    expect(storedAudit.map(({ action }) => action)).toEqual(expect.arrayContaining([
      "settlement.confirmed",
      "settlement.finalized",
    ]));
  });

  it("recovers a missing Ready hash only from the matching canonical PayrollSealed event", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    const runNullifier = `0x${"11".repeat(32)}`;
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "wallet-promise-recovery",
      revision: 1,
      state: "proven",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
      runNullifier,
    });
    const proofBundleId = generateUuidV7();
    const nullifier = BigInt(runNullifier);
    const high = nullifier >> 128n;
    const low = nullifier & ((1n << 128n) - 1n);
    const shardCalldataHashes = ["0xabc", "0xdef"] as const;
    await getDatabase().insert(proofBundles).values({
      id: proofBundleId,
      runId,
      organizationId,
      proofType: "payroll_integrity",
      proofVersion: "1",
      subjectRecordId: runId,
      proofPackage: {
        proofType: "payroll_integrity",
        proofVersion: "1",
        subjectRecordId: runId,
        commonInputs: {
          proofVersion: "1",
          runNullifierHigh: high.toString(),
          runNullifierLow: low.toString(),
        },
        shardCalldataHashes,
      },
      proofHash: `0x${"22".repeat(32)}`,
    });
    const sealAddress = "0x123";
    await persistIndexedBlock({
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      blockNumber: 12n,
      blockHash: "0x12",
      parentHash: "0x11",
      events: [{
        transactionHash: "0xfeed",
        eventIndex: 0,
        contractAddress: sealAddress,
        eventName: "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea",
        payload: {
          keys: [
            "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea",
            `0x${high.toString(16)}`,
            `0x${low.toString(16)}`,
          ],
          data: ["0x0", ...shardCalldataHashes, "0x1"],
        },
      }],
    });

    await expect(getSealedRunRecoveryEvidence({
      runId,
      chainId: "SN_MAIN",
      sealAddress,
      principal: admin,
    })).resolves.toMatchObject({ proofBundleId, transactionHash: "0xfeed", blockNumber: "12" });
    const prepared = prepareSettlementIntent({ organizationId, runId });
    const settlement = await createSettlementIntent(prepared.request);

    await expect(recoverApprovalSubmissionsFromSealEvents({
      chainId: "SN_MAIN",
      sealAddress,
    })).resolves.toEqual({ recovered: 1 });
    const [storedSettlement] = await getDatabase().select().from(settlements);
    const [storedRun] = await getDatabase().select().from(payrollRuns);
    const [confirmation] = await getDatabase().select().from(confirmationJobs);
    expect(storedSettlement).toMatchObject({ id: settlement.id, state: "submitted", transactionHash: "0xfeed" });
    expect(storedRun).toMatchObject({ state: "submitted", transactionHash: "0xfeed" });
    expect(confirmation.settlementId).toBe(settlement.id);
    await expect(recoverApprovalSubmissionsFromSealEvents({
      chainId: "SN_MAIN",
      sealAddress,
    })).resolves.toEqual({ recovered: 0 });
  });

  it("recovers wage-claim and remediation approvals from their exact proof-bound seal events", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "exception-wallet-promise-recovery",
      revision: 1,
      state: "confirmed",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
    });
    const sealAddress = "0x123";
    const profiles = [
      { workflowType: "wage_claim" as const, proofVersion: "3", mode: "0x2", base: 0x31n },
      { workflowType: "wage_remediation" as const, proofVersion: "4", mode: "0x3", base: 0x41n },
    ];
    const expected = [] as Array<{ settlementId: string; transactionHash: string }>;
    const events = [] as Array<{
      transactionHash: string;
      eventIndex: number;
      contractAddress: string;
      eventName: string;
      payload: { keys: string[]; data: string[] };
    }>;
    for (const [index, profile] of profiles.entries()) {
      const subjectRecordId = generateUuidV7();
      const proofBundleId = generateUuidV7();
      const settlementId = generateUuidV7();
      const shardCalldataHashes = [
        `0x${(profile.base + 2n).toString(16)}`,
        `0x${(profile.base + 3n).toString(16)}`,
      ] as const;
      await getDatabase().insert(proofBundles).values({
        id: proofBundleId,
        runId,
        organizationId,
        proofType: profile.workflowType,
        proofVersion: profile.proofVersion,
        subjectRecordId,
        proofPackage: {
          proofType: profile.workflowType,
          proofVersion: profile.proofVersion,
          subjectRecordId,
          commonInputs: {
            proofVersion: profile.proofVersion,
            runNullifierHigh: profile.base.toString(),
            runNullifierLow: (profile.base + 1n).toString(),
          },
          shardCalldataHashes,
        },
        proofHash: `0x${(profile.base + 4n).toString(16)}`,
        verificationState: "locally_verified",
      });
      await getDatabase().insert(settlements).values({
        id: settlementId,
        organizationId,
        runId,
        workflowType: profile.workflowType,
        subjectRecordId,
        walletRequestId: generateUuidV7(),
        idempotencyKey: `exception-recovery:${settlementId}`,
        tokenTotalsCommitment: `0x${(profile.base + 5n).toString(16).padStart(64, "0")}`,
      });
      const transactionHash = `0x${(profile.base + 6n).toString(16)}`;
      expected.push({ settlementId, transactionHash });
      events.push({
        transactionHash,
        eventIndex: index,
        contractAddress: sealAddress,
        eventName: "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea",
        payload: {
          keys: [
            "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea",
            `0x${profile.base.toString(16)}`,
            `0x${(profile.base + 1n).toString(16)}`,
          ],
          data: [profile.mode, ...shardCalldataHashes, `0x${BigInt(profile.proofVersion).toString(16)}`],
        },
      });
    }
    await persistIndexedBlock({
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      blockNumber: 20n,
      blockHash: "0x20",
      parentHash: "0x19",
      events,
    });

    await expect(recoverApprovalSubmissionsFromSealEvents({
      chainId: "SN_MAIN",
      sealAddress,
    })).resolves.toEqual({ recovered: 2 });
    const storedSettlements = await getDatabase().select().from(settlements);
    for (const item of expected) {
      expect(storedSettlements.find(({ id }) => id === item.settlementId)).toMatchObject({
        state: "submitted",
        transactionHash: item.transactionHash,
      });
    }
    expect(await getDatabase().select().from(confirmationJobs)).toHaveLength(2);
    expect((await getDatabase().select().from(payrollRuns))[0]).toMatchObject({
      state: "confirmed",
      transactionHash: null,
    });
  });

  it("fails closed when a seal event mismatches proof hashes or matches more than one approval", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "ambiguous-exception-recovery",
      revision: 1,
      state: "confirmed",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
    });
    const sealAddress = "0x123";
    const sharedHashes = ["0x61", "0x62"] as const;
    const addPendingClaim = async (input: {
      high: string;
      low: string;
      hashes: readonly [string, string];
    }) => {
      const subjectRecordId = generateUuidV7();
      const settlementId = generateUuidV7();
      await getDatabase().insert(proofBundles).values({
        id: generateUuidV7(),
        runId,
        organizationId,
        proofType: "wage_claim",
        proofVersion: "3",
        subjectRecordId,
        proofPackage: {
          proofType: "wage_claim",
          proofVersion: "3",
          subjectRecordId,
          commonInputs: { proofVersion: "3", runNullifierHigh: input.high, runNullifierLow: input.low },
          shardCalldataHashes: input.hashes,
        },
        proofHash: `0x${settlementId.replaceAll("-", "").slice(0, 63)}`,
      });
      await getDatabase().insert(settlements).values({
        id: settlementId,
        organizationId,
        runId,
        workflowType: "wage_claim",
        subjectRecordId,
        walletRequestId: generateUuidV7(),
        idempotencyKey: `ambiguous-recovery:${settlementId}`,
        tokenTotalsCommitment: `0x${"63".repeat(32)}`,
      });
      return settlementId;
    };
    const mismatchId = await addPendingClaim({ high: "81", low: "82", hashes: ["0x51", "0x52"] });
    const ambiguousIds = await Promise.all([
      addPendingClaim({ high: "97", low: "98", hashes: sharedHashes }),
      addPendingClaim({ high: "97", low: "98", hashes: sharedHashes }),
    ]);
    await persistIndexedBlock({
      chainId: "SN_MAIN",
      consumer: "payo-seal",
      blockNumber: 21n,
      blockHash: "0x21",
      parentHash: "0x20",
      events: [{
        transactionHash: "0x7001",
        eventIndex: 0,
        contractAddress: sealAddress,
        eventName: "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea",
        payload: {
          keys: [
            "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea",
            "0x51",
            "0x52",
          ],
          data: ["0x2", "0x51", "0x99", "0x3"],
        },
      }, {
        transactionHash: "0x7002",
        eventIndex: 1,
        contractAddress: sealAddress,
        eventName: "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea",
        payload: {
          keys: [
            "0x1b9fd7bf429246efa243b5f4b5eb036c1ab31a548ec13cc42f97a03b34f38ea",
            "0x61",
            "0x62",
          ],
          data: ["0x2", ...sharedHashes, "0x3"],
        },
      }],
    });

    await expect(recoverApprovalSubmissionsFromSealEvents({
      chainId: "SN_MAIN",
      sealAddress,
    })).resolves.toEqual({ recovered: 0 });
    const stored = await getDatabase().select().from(settlements);
    for (const settlementId of [mismatchId, ...ambiguousIds]) {
      expect(stored.find(({ id }) => id === settlementId)).toMatchObject({
        state: "approval_pending",
        transactionHash: null,
      });
    }
    expect(await getDatabase().select().from(confirmationJobs)).toHaveLength(0);
  });

  it("returns encrypted-proof recovery bindings for a confirmed payroll missing its verification job", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    const transactionHash = "0xc0ffee";
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "confirmed-proof-recovery",
      revision: 1,
      state: "confirmed",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
      runNullifier: `0x${"33".repeat(32)}`,
      transactionHash,
    });
    const proofBundleId = generateUuidV7();
    await getDatabase().insert(proofBundles).values({
      id: proofBundleId,
      runId,
      organizationId,
      proofType: "payroll_integrity",
      proofVersion: "2",
      subjectRecordId: runId,
      proofPackage: {},
      proofHash: `0x${"44".repeat(32)}`,
    });
    await getDatabase().insert(proofBundles).values({
      id: generateUuidV7(),
      runId,
      organizationId,
      proofType: "wage_claim",
      proofVersion: "3",
      subjectRecordId: generateUuidV7(),
      proofPackage: {},
      proofHash: `0x${"45".repeat(32)}`,
      createdAt: new Date(Date.now() + 1_000),
    });
    const settlementId = generateUuidV7();
    await getDatabase().insert(settlements).values({
      id: settlementId,
      organizationId,
      runId,
      workflowType: "payroll",
      subjectRecordId: runId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: `confirmed-proof-recovery:${settlementId}`,
      state: "finalized",
      tokenTotalsCommitment: `0x${"55".repeat(32)}`,
      transactionHash,
      blockNumber: 123n,
    });

    await expect(getSealedRunRecoveryEvidence({
      runId,
      chainId: "SN_MAIN",
      sealAddress: "0x123",
      principal: admin,
    })).resolves.toMatchObject({
      recoveryKind: "verification",
      proofBundleId,
      settlementId,
      transactionHash,
      blockNumber: "123",
    });
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
      subjectRecordId: runId,
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
    await expect(listDisclosureGrants(organizationId, admin)).resolves.toEqual([
      expect.objectContaining({
        id: grantId,
        runId,
        fieldScope: ["settlement"],
        revokedAt: null,
      }),
    ]);
    await expect(revokeDisclosureGrant({ organizationId, grantId, principal: admin }))
      .resolves.toMatchObject({ id: grantId });
    expect((await getDatabase().select().from(disclosureGrants))[0].revokedAt).not.toBeNull();
    await expect(listDisclosureGrants(organizationId, admin)).resolves.toEqual([
      expect.objectContaining({ id: grantId, revokedAt: expect.any(Date) }),
    ]);
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
      subjectRecordId: runId,
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

  it("prepares encrypted proof delivery before Ready and leases it only after finalization", async () => {
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
      subjectRecordId: runId,
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
      subjectRecordId: runId,
      walletRequestId: "proof-relay-wallet-request",
      idempotencyKey: "proof-relay-idempotency-key",
      state: "approval_pending",
      tokenTotalsCommitment: `0x${"22".repeat(32)}`,
    });
    const dateNow = vi.spyOn(Date, "now").mockReturnValue(
      (Number(commonInputs.validityExpiry) - 600) * 1_000,
    );
    try {
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

    const lateSettlementId = generateUuidV7();
    await getDatabase().insert(settlements).values({
      id: lateSettlementId,
      organizationId,
      runId,
      subjectRecordId: runId,
      walletRequestId: "proof-relay-expired-wallet-request",
      idempotencyKey: "proof-relay-expired-idempotency-key",
      state: "submitted",
      tokenTotalsCommitment: `0x${"23".repeat(32)}`,
      transactionHash: "0xabd",
    });
    dateNow.mockReturnValue((Number(commonInputs.validityExpiry) - 119) * 1_000);
      await expect(enqueueProofVerification({
        settlementId: lateSettlementId,
        request: { proofBundleId, shards: shardCalldata },
        principal: admin,
      })).rejects.toMatchObject({ code: "PROOF_VALIDITY_EXPIRED" });
      await expect(enqueueProofVerification({
        settlementId,
        request: { proofBundleId, shards: shardCalldata },
        principal: admin,
      })).resolves.toMatchObject({ proofBundleId, replayed: true });

    const [proofJob] = await getDatabase().select().from(proofVerificationJobs);
    expect(proofJob).toMatchObject({ state: "pending", nextShard: 0 });
    expect(proofJob.shard0Calldata).toHaveLength(3_187);
    expect((await getDatabase().select({ action: auditEvents.action }).from(auditEvents))
      .map(({ action }) => action)).toContain("proof_verification.prepared");

    const modified = [[...shardCalldata[0]], shardCalldata[1]] as [string[], string[]];
    modified[0][100] = "0x1";
      await expect(enqueueProofVerification({
        settlementId,
        request: { proofBundleId, shards: modified },
        principal: admin,
      })).rejects.toMatchObject({ code: "PROOF_CALLDATA_HASH_MISMATCH" });
    } finally {
      dateNow.mockRestore();
    }

    await expect(leaseProofVerificationJobs(
      "proof-worker-too-early",
      2,
      new Date("2030-01-01T00:25:00.000Z"),
    )).resolves.toEqual([]);
    await getDatabase()
      .update(settlements)
      .set({ state: "finalized", transactionHash: "0xabc" })
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

  it("renews an expired FX root only from finalized and on-chain-verified payroll evidence", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    const proofBundleId = generateUuidV7();
    const fxRoot = `0x${"71".repeat(32)}`;
    const runNullifier = `0x${"72".repeat(32)}`;
    const payrollTransactionHash = "0x7100";
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "historical-fx-renewal",
      revision: 1,
      state: "confirmed",
      dueAt: new Date("2026-08-26T00:00:00.000Z"),
      fxRoot,
      runNullifier,
      transactionHash: payrollTransactionHash,
    });
    await getDatabase().insert(proofBundles).values({
      id: proofBundleId,
      runId,
      organizationId,
      proofType: "payroll_integrity",
      proofVersion: "2",
      subjectRecordId: runId,
      proofPackage: { commonInputs: { fxRoot } },
      proofHash: `0x${"73".repeat(32)}`,
      verificationState: "onchain_verified",
      verificationTransactionHash: "0x7101",
    });
    await getDatabase().insert(settlements).values({
      id: generateUuidV7(),
      organizationId,
      runId,
      workflowType: "payroll",
      subjectRecordId: runId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: "historical-fx-payroll",
      state: "finalized",
      tokenTotalsCommitment: `0x${"74".repeat(32)}`,
      transactionHash: payrollTransactionHash,
    });
    await enqueueFxPublication({
      organizationId,
      catalogRoot: fxRoot,
      proofVersion: 2,
      shards: [
        Array.from({ length: 35 }, (_, index) => `0x${(index + 1).toString(16)}`),
        Array.from({ length: 35 }, (_, index) => `0x${(index + 36).toString(16)}`),
      ],
      observedAt: 1_000,
      maximumAgeSeconds: 3_600,
      principal: admin,
    });
    await getDatabase().update(fxPublicationJobs).set({
      state: "complete",
      transactionHash: "0x7102",
    });
    const evidence = await getHistoricalFxRenewalEvidence({ runId, principal: admin });
    const renewed = await enqueueHistoricalFxRenewal({
      evidence,
      observedAt: 2_000,
      principal: admin,
    });
    expect(renewed).toMatchObject({
      state: "pending",
      historicalRenewal: true,
      renewalRunId: runId,
      renewalCount: 1,
      observedAt: 2_000,
      transactionHash: null,
      replayed: false,
    });
    await expect(getHistoricalFxRenewalEvidence({
      runId,
      principal: { principalId: "admin:other", sessionId: "other" },
    })).rejects.toMatchObject({ code: "ORG_FORBIDDEN" });
    const claimId = generateUuidV7();
    const claimNullifierHigh = 0x81n;
    const claimNullifierLow = 0x82n;
    await getDatabase().insert(proofBundles).values({
      id: generateUuidV7(),
      runId,
      organizationId,
      proofType: "wage_claim",
      proofVersion: "3",
      subjectRecordId: claimId,
      proofPackage: {
        proofType: "wage_claim",
        proofVersion: "3",
        subjectRecordId: claimId,
        commonInputs: {
          proofVersion: "3",
          runNullifierHigh: claimNullifierHigh.toString(),
          runNullifierLow: claimNullifierLow.toString(),
        },
      },
      proofHash: `0x${"75".repeat(32)}`,
      verificationState: "onchain_verified",
      verificationTransactionHash: "0x7103",
    });
    await getDatabase().insert(settlements).values({
      id: generateUuidV7(),
      organizationId,
      runId,
      workflowType: "wage_claim",
      subjectRecordId: claimId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: "historical-fx-verified-claim",
      state: "finalized",
      tokenTotalsCommitment: `0x${"76".repeat(32)}`,
      transactionHash: "0x7104",
    });
    const remediationEvidence = await getHistoricalFxRenewalEvidence({
      runId,
      principal: admin,
      workflowType: "wage_remediation",
      claimId,
    });
    expect(remediationEvidence.authorizationNullifier).toBe(
      `0x${((claimNullifierHigh << 128n) | claimNullifierLow).toString(16).padStart(64, "0")}`,
    );
    expect(remediationEvidence.authorizationNullifier).not.toBe(runNullifier);
    await expect(getHistoricalFxRenewalEvidence({
      runId,
      principal: admin,
      workflowType: "wage_remediation",
      claimId: generateUuidV7(),
    })).rejects.toMatchObject({ code: "FX_RENEWAL_CLAIM_NOT_VERIFIED" });
    const [audit] = await getDatabase().select().from(auditEvents)
      .where(sql`${auditEvents.action} = ${"fx_publication.historical_renewal_queued"}`);
    expect(audit?.metadata).toMatchObject({ runId, renewalCount: 1 });
  });

  it("atomically refreshes only an unsigned expired exception proof with stable bindings", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    const claimId = generateUuidV7();
    const proofBundleId = generateUuidV7();
    const fixture = preparePhase3ExceptionProof({
      profile: "claim",
      organizationId,
      runId,
      subjectRecordId: claimId,
      proofBundleId,
    });
    const root = (high: string, low: string) =>
      `0x${BigInt(high).toString(16).padStart(32, "0")}${BigInt(low).toString(16).padStart(32, "0")}`;
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "exception-proof-refresh",
      revision: 1,
      state: "confirmed",
      dueAt: new Date("2026-08-26T00:00:00.000Z"),
      agreementRoot: root(fixture.commonInputs.agreementRootHigh, fixture.commonInputs.agreementRootLow),
      policyRoot: root(fixture.commonInputs.policyRootHigh, fixture.commonInputs.policyRootLow),
      fxRoot: root(fixture.commonInputs.fxRootHigh, fixture.commonInputs.fxRootLow),
    });
    await getDatabase().insert(vaultRecords).values({
      id: claimId,
      organizationId,
      recordType: "wage-claim",
      revision: 1,
      ciphertext: "encrypted-refresh-claim",
      envelope: { ciphertext: "encrypted-refresh-claim" },
      envelopeHash: `0x${"75".repeat(32)}`,
      createdBy: admin.principalId,
    });
    const deployment = {
      chainId: fixture.commonInputs.chainId,
      sealAddress: fixture.commonInputs.sealAddress,
    };
    await storeEncryptedPayrollIntegrityBundle({ bundle: fixture.bundle, deployment, principal: admin });
    await getDatabase().insert(settlements).values({
      id: generateUuidV7(),
      organizationId,
      runId,
      workflowType: "wage_claim",
      subjectRecordId: claimId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: "exception-proof-refresh",
      state: "approval_pending",
      tokenTotalsCommitment: `0x${"76".repeat(32)}`,
    });
    const nowSeconds = Math.floor(Date.now() / 1_000);
    const commonInputs = {
      ...fixture.commonInputs,
      validityStart: String(nowSeconds - 30),
      validityExpiry: String(nowSeconds + 3_500),
    };
    const envelope = encryptVaultRecord(
      { profile: "claim", refreshed: true, shards: fixture.shards },
      {
        schemaVersion: 1,
        organizationId,
        recordType: "proof-bundle",
        recordId: proofBundleId,
        revision: 2,
      },
      [generateVaultPrincipal(admin.principalId)],
    );
    const refreshedBundle = {
      ...fixture.bundle,
      revision: 2,
      commonInputs,
      publicInputsHash: hashCanonicalJson([
        { ...commonInputs, shardIndex: "0" },
        { ...commonInputs, shardIndex: "1" },
      ]),
      envelope,
    };
    await expect(storeEncryptedPayrollIntegrityBundle({
      bundle: refreshedBundle,
      deployment,
      principal: admin,
    })).resolves.toMatchObject({ replayed: false, refreshed: true });
    const proofVaults = await getDatabase().select().from(vaultRecords)
      .where(sql`${vaultRecords.id} = ${proofBundleId}`);
    expect(proofVaults.map(({ revision, supersededAt }) => ({ revision, active: supersededAt === null })))
      .toEqual([{ revision: 1, active: false }, { revision: 2, active: true }]);
    const changedBindings = {
      ...refreshedBundle,
      revision: 3,
      commonInputs: { ...commonInputs, fxRootLow: String(BigInt(commonInputs.fxRootLow) + 1n) },
      envelope: encryptVaultRecord(
        { changed: true },
        {
          schemaVersion: 1,
          organizationId,
          recordType: "proof-bundle",
          recordId: proofBundleId,
          revision: 3,
        },
        [generateVaultPrincipal(admin.principalId)],
      ),
    };
    await expect(storeEncryptedPayrollIntegrityBundle({
      bundle: changedBindings,
      deployment,
      principal: admin,
    })).rejects.toMatchObject({ code: "EXCEPTION_PROOF_BINDING_CHANGED" });
  });

  it("drives confirmed -> disputed -> reconciled only after v3/v4 proof jobs complete", async () => {
    const organizationId = await seedOrganization();
    const runId = generateUuidV7();
    const claimId = generateUuidV7();
    const claimProofBundleId = generateUuidV7();
    const claimFixture = preparePhase3ExceptionProof({
      profile: "claim",
      organizationId,
      runId,
      subjectRecordId: claimId,
      proofBundleId: claimProofBundleId,
    });
    const combinedRoot = (high: string, low: string) =>
      `0x${BigInt(high).toString(16).padStart(32, "0")}${BigInt(low).toString(16).padStart(32, "0")}`;
    await getDatabase().insert(payrollRuns).values({
      id: runId,
      organizationId,
      cycleId: "phase3-claim-remediation",
      revision: 1,
      state: "confirmed",
      dueAt: new Date("2026-08-31T00:00:00.000Z"),
      agreementRoot: combinedRoot(claimFixture.commonInputs.agreementRootHigh, claimFixture.commonInputs.agreementRootLow),
      policyRoot: combinedRoot(claimFixture.commonInputs.policyRootHigh, claimFixture.commonInputs.policyRootLow),
      fxRoot: combinedRoot(claimFixture.commonInputs.fxRootHigh, claimFixture.commonInputs.fxRootLow),
    });
    await getDatabase().insert(vaultRecords).values({
      id: claimId,
      organizationId,
      recordType: "wage-claim",
      revision: 1,
      ciphertext: "encrypted-claim-subject",
      envelope: { ciphertext: "encrypted-claim-subject" },
      envelopeHash: `0x${"61".repeat(32)}`,
      createdBy: admin.principalId,
    });
    const deployment = {
      chainId: claimFixture.commonInputs.chainId,
      sealAddress: claimFixture.commonInputs.sealAddress,
    };
    await storeEncryptedPayrollIntegrityBundle({ bundle: claimFixture.bundle, deployment, principal: admin });
    const claimSettlementId = generateUuidV7();
    await getDatabase().insert(settlements).values({
      id: claimSettlementId,
      organizationId,
      runId,
      workflowType: "wage_claim",
      subjectRecordId: claimId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: `claim-proof-job:${claimSettlementId}`,
      state: "finalized",
      tokenTotalsCommitment: `0x${"62".repeat(32)}`,
      transactionHash: "0xc100",
    });
    const claimDateNow = vi.spyOn(Date, "now").mockReturnValue(
      (Number(claimFixture.commonInputs.validityExpiry) - 600) * 1_000,
    );
    try {
      await enqueueProofVerification({
        settlementId: claimSettlementId,
        request: { proofBundleId: claimProofBundleId, shards: claimFixture.shards },
        principal: admin,
      });
    } finally {
      claimDateNow.mockRestore();
    }
    expect((await getDatabase().select().from(payrollRuns))[0].state).toBe("confirmed");
    const [claimJob] = await leaseProofVerificationJobs(
      "phase3-claim-completer",
      2,
      new Date("2099-01-01T00:00:00.000Z"),
    );
    await recordProofVerificationProgress(
      claimJob,
      { complete: true, verificationTransactionHash: "0xc101" },
      new Date("2099-01-01T00:00:01.000Z"),
    );
    expect((await getDatabase().select().from(payrollRuns))[0].state).toBe("disputed");

    const remediationId = generateUuidV7();
    const remediationProofBundleId = generateUuidV7();
    const remediationFixture = preparePhase3ExceptionProof({
      profile: "remediation",
      organizationId,
      runId,
      subjectRecordId: remediationId,
      proofBundleId: remediationProofBundleId,
    });
    await getDatabase().insert(vaultRecords).values({
      id: remediationId,
      organizationId,
      recordType: "remediation",
      revision: 1,
      ciphertext: "encrypted-remediation-subject",
      envelope: { ciphertext: "encrypted-remediation-subject" },
      envelopeHash: `0x${"63".repeat(32)}`,
      createdBy: admin.principalId,
    });
    await storeEncryptedPayrollIntegrityBundle({ bundle: remediationFixture.bundle, deployment, principal: admin });
    const remediationSettlementId = generateUuidV7();
    await getDatabase().insert(settlements).values({
      id: remediationSettlementId,
      organizationId,
      runId,
      workflowType: "wage_remediation",
      subjectRecordId: remediationId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: `remediation-proof-job:${remediationSettlementId}`,
      state: "finalized",
      tokenTotalsCommitment: `0x${"64".repeat(32)}`,
      transactionHash: "0xc200",
    });
    const remediationDateNow = vi.spyOn(Date, "now").mockReturnValue(
      (Number(remediationFixture.commonInputs.validityExpiry) - 600) * 1_000,
    );
    try {
      await enqueueProofVerification({
        settlementId: remediationSettlementId,
        request: { proofBundleId: remediationProofBundleId, shards: remediationFixture.shards },
        principal: admin,
      });
    } finally {
      remediationDateNow.mockRestore();
    }
    const [remediationJob] = await leaseProofVerificationJobs(
      "phase3-remediation-completer",
      2,
      new Date("2099-01-01T00:01:00.000Z"),
    );
    await recordProofVerificationProgress(
      remediationJob,
      { complete: true, verificationTransactionHash: "0xc201" },
      new Date("2099-01-01T00:01:01.000Z"),
    );
    expect((await getDatabase().select().from(payrollRuns))[0].state).toBe("reconciled");
    expect((await getDatabase().select().from(proofBundles)).map(({ verificationState }) => verificationState))
      .toEqual(["onchain_verified", "onchain_verified"]);
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

  it("materializes encrypted obligation schedules idempotently and supersedes stale revisions", async () => {
    const organizationId = await seedOrganization();
    const vaultRecordId = generateUuidV7();
    const agreementId = generateUuidV7();
    const dueAt = new Date(Date.now() - 60_000).toISOString();
    const firstCommitment = `0x${"11".repeat(32)}`;
    await getDatabase().insert(vaultRecords).values({
      id: vaultRecordId,
      organizationId,
      recordType: "pay-agreement",
      revision: 1,
      ciphertext: "encrypted-agreement-v1",
      envelope: { encrypted: true },
      envelopeHash: `0x${"aa".repeat(32)}`,
      createdBy: admin.principalId,
    });

    const request = {
      organizationId,
      schedules: [{
        vaultRecordId,
        agreementId,
        agreementRevision: 1,
        scheduleCommitment: firstCommitment,
        dueAt,
      }],
      principal: admin,
    };
    await expect(registerObligationSchedules({
      ...request,
      schedules: [{ ...request.schedules[0], vaultRecordId: generateUuidV7() }],
    })).rejects.toMatchObject({ code: "SCHEDULE_AGREEMENT_REVISION_STALE" });
    await expect(Promise.all([
      registerObligationSchedules(request),
      registerObligationSchedules(request),
    ])).resolves.toEqual(expect.arrayContaining([
      [expect.objectContaining({ replayed: false, materializedAt: expect.any(String) })],
      [expect.objectContaining({ replayed: true, materializedAt: expect.any(String) })],
    ]));
    await expect(listDueObligationSchedules({ organizationId, principal: admin })).resolves.toEqual([
      expect.objectContaining({ agreementId, agreementRevision: 1, scheduleCommitment: firstCommitment }),
    ]);
    await expect(registerObligationSchedules({
      ...request,
      schedules: [{ ...request.schedules[0], scheduleCommitment: `0x${"22".repeat(32)}` }],
    })).rejects.toMatchObject({ code: "SCHEDULE_REVISION_CONFLICT" });

    const revisionTime = new Date();
    await getDatabase().update(vaultRecords)
      .set({ supersededAt: revisionTime })
      .where(sql`${vaultRecords.organizationId} = ${organizationId} and ${vaultRecords.id} = ${vaultRecordId}`);
    await getDatabase().insert(vaultRecords).values({
      id: vaultRecordId,
      organizationId,
      recordType: "pay-agreement",
      revision: 2,
      ciphertext: "encrypted-agreement-v2",
      envelope: { encrypted: true },
      envelopeHash: `0x${"bb".repeat(32)}`,
      createdBy: admin.principalId,
    });
    const futureDueAt = new Date(Date.now() + 60_000).toISOString();
    const secondCommitment = `0x${"33".repeat(32)}`;
    await expect(registerObligationSchedules({
      organizationId,
      schedules: [{
        vaultRecordId,
        agreementId,
        agreementRevision: 2,
        scheduleCommitment: secondCommitment,
        dueAt: futureDueAt,
      }],
      principal: admin,
    })).resolves.toEqual([
      expect.objectContaining({ agreementRevision: 2, replayed: false, materializedAt: null }),
    ]);
    await expect(materializeDueObligationSchedules({
      now: new Date(Date.now() + 120_000),
    })).resolves.toMatchObject({ materialized: 1 });
    const stored = await getDatabase().select().from(obligationSchedules)
      .where(sql`${obligationSchedules.organizationId} = ${organizationId}`);
    expect(stored.find(({ agreementRevision }) => agreementRevision === 1)?.state).toBe("superseded");
    expect(stored.find(({ agreementRevision }) => agreementRevision === 2)?.materializedAt).toBeInstanceOf(Date);
  });

  it("surfaces typed database errors rather than mislabelling conflicts", async () => {
    expect(new ApiError(409, "conflict", "CONFLICT")).toMatchObject({ status: 409, code: "CONFLICT" });
  });

  it("issues one-time Ready sessions and links a legacy encrypted workspace by recovery-key proof", async () => {
    const walletAddress = "0x0126a7a572cf8935d069af937e9f7b27a24949e271e1fbccfe4de0c0d8dc8ea9";
    const request = new Request("https://payo.test/api/v1/auth/challenge");
    const challenge = await createReadyAuthenticationChallenge(request, {
      walletAddress,
      chainId: READY_AUTH_CHAIN_ID,
    });
    const firstSession = await verifyReadyAuthenticationChallenge({
      challengeId: challenge.challengeId,
      signature: ["0x1", "0x2"],
    }, async ({ walletAddress: verifiedWallet }) => verifiedWallet === walletAddress);
    const authenticatedRequest = new Request("https://payo.test/api", {
      headers: { authorization: `Bearer ${firstSession.accessToken}` },
    });
    const walletPrincipal = await requirePrincipal(authenticatedRequest);
    expect(walletPrincipal.principalId).toMatch(/^starknet:/);
    await expect(verifyReadyAuthenticationChallenge({
      challengeId: challenge.challengeId,
      signature: ["0x1", "0x2"],
    }, async () => true)).rejects.toMatchObject({ code: "AUTH_CHALLENGE_INVALID" });

    const organizationId = await seedOrganization(admin);
    const legacyVaultPrincipal = generateVaultPrincipal(admin.principalId);
    await getDatabase().update(organizationMembers)
      .set({ vaultPublicKey: legacyVaultPrincipal.publicKey })
      .where(sql`${organizationMembers.organizationId} = ${organizationId} and ${organizationMembers.principalId} = ${admin.principalId}`);
    const recoveryLink = await createReadyRecoveryLink(walletPrincipal, {
      organizationId,
      legacyPrincipalId: admin.principalId,
    });
    const recovered = decryptVaultRecord<{ proof: string }>(recoveryLink.envelope, legacyVaultPrincipal);
    const linkedSession = await completeReadyRecoveryLink(walletPrincipal, {
      challengeId: recoveryLink.challengeId,
      proof: recovered.proof,
    });
    expect(linkedSession.principalId).toBe(admin.principalId);
    await expect(requirePrincipal(authenticatedRequest)).rejects.toMatchObject({ code: "AUTH_INVALID" });
    await expect(requirePrincipal(new Request("https://payo.test/api", {
      headers: { authorization: `Bearer ${linkedSession.accessToken}` },
    }))).resolves.toMatchObject({ principalId: admin.principalId, walletAddress });

    const nextChallenge = await createReadyAuthenticationChallenge(request, {
      walletAddress,
      chainId: READY_AUTH_CHAIN_ID,
    });
    await expect(verifyReadyAuthenticationChallenge({
      challengeId: nextChallenge.challengeId,
      signature: ["0x3", "0x4"],
    }, async () => true)).resolves.toMatchObject({ principalId: admin.principalId });
  });
});
