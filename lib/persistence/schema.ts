import {
  bigint,
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const organizationRole = pgEnum("organization_role", ["admin", "operator", "reviewer"]);
export const payrollRunState = pgEnum("payroll_run_state", [
  "draft",
  "calculated",
  "proven",
  "approval_pending",
  "submitted",
  "confirmed",
  "reconciled",
  "cancelled",
  "failed",
  "disputed",
]);
export const recoveryState = pgEnum("recovery_state", ["required", "package_downloaded", "second_admin"]);
export const settlementState = pgEnum("settlement_state", [
  "approval_pending",
  "submitted",
  "confirmed",
  "finalized",
  "reorged",
  "failed",
  "reconciled",
]);
export const durableJobState = pgEnum("durable_job_state", ["pending", "leased", "complete", "dead"]);
export const obligationScheduleState = pgEnum("obligation_schedule_state", ["active", "superseded"]);
export const obligationSnapshotPlanState = pgEnum("obligation_snapshot_plan_state", [
  "prepared",
  "submitted",
  "registered",
  "consumed",
  "cancelled",
  "expired",
]);
export const idempotencyState = pgEnum("idempotency_state", ["started", "succeeded", "failed"]);
export const capabilityReservationState = pgEnum("capability_reservation_state", [
  "reserved",
  "approval_linked",
  "committed",
  "released",
  "expired",
]);
export const agentExecutionState = pgEnum("agent_execution_state", [
  "reserved",
  "approval_pending",
  "preparing",
  "submitting",
  "submitted",
  "confirmed",
  "reconciled",
  "failed",
  "released",
]);
export const workerClaimState = pgEnum("worker_claim_state", [
  "prepared",
  "proved",
  "authorization_pending",
  "accepted",
  "rejected",
]);
export const employerStatementState = pgEnum("employer_statement_state", [
  "prepared",
  "submitted",
  "registered",
  "failed",
]);
export const wageRemediationState = pgEnum("wage_remediation_state", [
  "prepared",
  "proved",
  "authorization_pending",
  "authorized",
  "payment_pending",
  "payment_confirmed",
  "reconciled",
  "expired",
  "failed",
]);

export const organizations = pgTable("organizations", {
  id: text("id").primaryKey(),
  encryptedProfile: jsonb("encrypted_profile").notNull(),
  recoveryState: recoveryState("recovery_state").default("required").notNull(),
  recoveryPackageHash: text("recovery_package_hash"),
  recoveryConfiguredAt: timestamp("recovery_configured_at", { withTimezone: true }),
  keyVersion: integer("key_version").default(1).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const organizationMembers = pgTable(
  "organization_members",
  {
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    principalId: text("principal_id").notNull(),
    role: organizationRole("role").notNull(),
    vaultPublicKey: text("vault_public_key").notNull(),
    keyVersion: integer("key_version").default(1).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.organizationId, table.principalId] }),
    index("organization_members_principal_idx").on(table.principalId),
  ],
);

export const readyAuthChallenges = pgTable(
  "ready_auth_challenges",
  {
    id: text("id").primaryKey(),
    walletAddress: text("wallet_address").notNull(),
    chainId: text("chain_id").notNull(),
    audience: text("audience").notNull(),
    nonce: text("nonce").notNull(),
    issuedAt: timestamp("issued_at", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    attempts: integer("attempts").default(0).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("ready_auth_challenges_wallet_idx").on(table.chainId, table.walletAddress, table.expiresAt),
    index("ready_auth_challenges_expiry_idx").on(table.expiresAt),
  ],
);

export const readyPrincipalLinks = pgTable(
  "ready_principal_links",
  {
    chainId: text("chain_id").notNull(),
    walletAddress: text("wallet_address").notNull(),
    principalId: text("principal_id").notNull(),
    linkMethod: text("link_method").default("vault_recovery").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.chainId, table.walletAddress] }),
    index("ready_principal_links_principal_idx").on(table.principalId),
  ],
);

export const readyAuthSessions = pgTable(
  "ready_auth_sessions",
  {
    id: text("id").primaryKey(),
    tokenHash: text("token_hash").notNull(),
    walletAddress: text("wallet_address").notNull(),
    chainId: text("chain_id").notNull(),
    principalId: text("principal_id").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("ready_auth_sessions_token_hash_idx").on(table.tokenHash),
    index("ready_auth_sessions_wallet_idx").on(table.chainId, table.walletAddress, table.expiresAt),
    index("ready_auth_sessions_principal_idx").on(table.principalId, table.expiresAt),
  ],
);

export const readyRecoveryLinkChallenges = pgTable(
  "ready_recovery_link_challenges",
  {
    id: text("id").primaryKey(),
    walletAddress: text("wallet_address").notNull(),
    chainId: text("chain_id").notNull(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    legacyPrincipalId: text("legacy_principal_id").notNull(),
    proofHash: text("proof_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    attempts: integer("attempts").default(0).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("ready_recovery_link_wallet_idx").on(table.chainId, table.walletAddress, table.expiresAt),
    index("ready_recovery_link_expiry_idx").on(table.expiresAt),
  ],
);

export const vaultRecords = pgTable(
  "vault_records",
  {
    id: text("id").notNull(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    recordType: text("record_type").notNull(),
    revision: integer("revision").notNull(),
    ciphertext: text("ciphertext").notNull(),
    envelope: jsonb("envelope").notNull(),
    envelopeHash: text("envelope_hash").notNull(),
    supersededAt: timestamp("superseded_at", { withTimezone: true }),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.organizationId, table.id, table.revision] }),
    index("vault_records_org_type_idx").on(table.organizationId, table.recordType),
    uniqueIndex("vault_records_org_envelope_hash_idx").on(table.organizationId, table.envelopeHash),
  ],
);

export const vaultKeyGrants = pgTable(
  "vault_key_grants",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    granteePrincipalId: text("grantee_principal_id").notNull(),
    keyVersion: integer("key_version").notNull(),
    envelope: jsonb("envelope").notNull(),
    envelopeHash: text("envelope_hash").notNull(),
    createdBy: text("created_by").notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("vault_key_grants_org_principal_version_idx").on(
      table.organizationId,
      table.granteePrincipalId,
      table.keyVersion,
    ),
    index("vault_key_grants_grantee_idx").on(table.granteePrincipalId, table.revokedAt),
  ],
);

/**
 * Public commitments and deadlines for one pre-payday snapshot. Agreement
 * details, claim capabilities and salary values remain in the separately
 * encrypted vault envelope whose record ID equals this plan ID.
 */
export const obligationSnapshotPlans = pgTable(
  "obligation_snapshot_plans",
  {
    id: text("id").primaryKey(),
    runId: text("run_id").notNull(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    cycleId: text("cycle_id").notNull(),
    revision: integer("revision").notNull(),
    ownerAddress: text("owner_address").notNull(),
    agreementRoot: text("agreement_root").notNull(),
    claimRoot: text("claim_root").notNull(),
    policyRoot: text("policy_root").notNull(),
    runNullifier: text("run_nullifier").notNull(),
    snapshotFact: text("snapshot_fact").notNull(),
    dueAt: timestamp("due_at", { withTimezone: true }).notNull(),
    graceEndsAt: timestamp("grace_ends_at", { withTimezone: true }).notNull(),
    claimEndsAt: timestamp("claim_ends_at", { withTimezone: true }).notNull(),
    state: obligationSnapshotPlanState("state").default("prepared").notNull(),
    registrationTransactionHash: text("registration_transaction_hash"),
    registeredAt: timestamp("registered_at", { withTimezone: true }),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("obligation_snapshot_plans_org_cycle_revision_idx").on(
      table.organizationId,
      table.cycleId,
      table.revision,
    ),
    uniqueIndex("obligation_snapshot_plans_run_nullifier_idx").on(table.runNullifier),
    uniqueIndex("obligation_snapshot_plans_run_idx").on(table.runId),
    uniqueIndex("obligation_snapshot_plans_fact_idx").on(table.snapshotFact),
    index("obligation_snapshot_plans_org_due_idx").on(
      table.organizationId,
      table.state,
      table.dueAt,
    ),
  ],
);

export const payrollRuns = pgTable(
  "payroll_runs",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    cycleId: text("cycle_id").notNull(),
    revision: integer("revision").notNull(),
    state: payrollRunState("state").default("draft").notNull(),
    dueAt: timestamp("due_at", { withTimezone: true }).notNull(),
    manifestRoot: text("manifest_root"),
    agreementRoot: text("agreement_root"),
    policyRoot: text("policy_root"),
    fxRoot: text("fx_root"),
    runNullifier: text("run_nullifier"),
    obligationSnapshotPlanId: text("obligation_snapshot_plan_id")
      .references(() => obligationSnapshotPlans.id, { onDelete: "restrict" }),
    transactionHash: text("transaction_hash"),
    version: integer("version").default(1).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("payroll_runs_org_cycle_revision_idx").on(
      table.organizationId,
      table.cycleId,
      table.revision,
    ),
    uniqueIndex("payroll_runs_nullifier_idx").on(table.runNullifier),
    uniqueIndex("payroll_runs_snapshot_plan_idx").on(table.obligationSnapshotPlanId),
    index("payroll_runs_org_due_idx").on(table.organizationId, table.dueAt),
  ],
);

/**
 * One encrypted, worker-scoped opening of an immutable obligation snapshot.
 * The service can route it by authenticated principal but cannot decrypt the
 * agreement, amount, recipient, claim type or Merkle witnesses.
 */
export const obligationClaimAccessGrants = pgTable(
  "obligation_claim_access_grants",
  {
    id: text("id").primaryKey(),
    snapshotPlanId: text("snapshot_plan_id")
      .notNull()
      .references(() => obligationSnapshotPlans.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    claimantPrincipalId: text("claimant_principal_id").notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("obligation_claim_access_claimant_idx").on(
      table.claimantPrincipalId,
      table.revokedAt,
      table.createdAt,
    ),
    index("obligation_claim_access_snapshot_idx").on(table.snapshotPlanId),
    index("obligation_claim_access_run_idx").on(table.runId),
  ],
);

/**
 * Opaque scheduling metadata only. The agreement kind, recipient, token and
 * value remain inside the encrypted pay-agreement vault revision. A due row is
 * a draft signal for the browser; it never authorizes or executes a payment.
 */
/**
 * Opaque routing for a Claim v6 record. Claim kind, amount, agreement and
 * evidence remain in the worker/employer encrypted vault envelope. The two
 * public commitments are already part of the proof and eventual on-chain event.
 */
export const workerClaims = pgTable(
  "worker_claims",
  {
    id: text("id").primaryKey(),
    claimAccessGrantId: text("claim_access_grant_id")
      .notNull()
      .references(() => obligationClaimAccessGrants.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    claimantPrincipalId: text("claimant_principal_id").notNull(),
    proofBundleId: text("proof_bundle_id").notNull(),
    claimSubjectNullifier: text("claim_subject_nullifier").notNull(),
    claimFactCommitment: text("claim_fact_commitment").notNull(),
    state: workerClaimState("state").default("prepared").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("worker_claims_proof_bundle_idx").on(table.proofBundleId),
    uniqueIndex("worker_claims_subject_nullifier_idx").on(table.claimSubjectNullifier),
    index("worker_claims_claimant_idx").on(table.claimantPrincipalId, table.createdAt),
    index("worker_claims_org_run_idx").on(table.organizationId, table.runId),
    index("worker_claims_access_grant_idx").on(table.claimAccessGrantId),
  ],
);

/**
 * Public commitments for one employer-authored payroll statement. Salary,
 * recipient, claim type and line openings remain in encrypted worker packets.
 */
export const employerStatements = pgTable(
  "employer_statements",
  {
    id: text("id").primaryKey(),
    snapshotPlanId: text("snapshot_plan_id")
      .notNull()
      .references(() => obligationSnapshotPlans.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    ownerAddress: text("owner_address").notNull(),
    statementFact: text("statement_fact").notNull(),
    manifestRoot: text("manifest_root").notNull(),
    fxRoot: text("fx_root").notNull(),
    availabilityCommitment: text("availability_commitment").notNull(),
    observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
    source: text("source").default("employer_statement").notNull(),
    state: employerStatementState("state").default("prepared").notNull(),
    registrationTransactionHash: text("registration_transaction_hash"),
    registeredAt: timestamp("registered_at", { withTimezone: true }),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("employer_statements_run_fx_idx").on(table.runId, table.fxRoot),
    uniqueIndex("employer_statements_fact_idx").on(table.statementFact),
    uniqueIndex("employer_statements_transaction_idx").on(table.registrationTransactionHash),
    index("employer_statements_org_state_idx").on(table.organizationId, table.state, table.createdAt),
  ],
);

/** One claimant-only encrypted Merkle/line packet for a registered statement. */
export const payrollStatementEvidenceGrants = pgTable(
  "payroll_statement_evidence_grants",
  {
    id: text("id").primaryKey(),
    statementId: text("statement_id")
      .notNull()
      .references(() => employerStatements.id, { onDelete: "cascade" }),
    claimAccessGrantId: text("claim_access_grant_id")
      .notNull()
      .references(() => obligationClaimAccessGrants.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    claimantPrincipalId: text("claimant_principal_id").notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("payroll_statement_evidence_statement_access_idx").on(
      table.statementId,
      table.claimAccessGrantId,
    ),
    index("payroll_statement_evidence_claimant_idx").on(
      table.claimantPrincipalId,
      table.revokedAt,
      table.createdAt,
    ),
    index("payroll_statement_evidence_run_idx").on(table.runId),
  ],
);

export const obligationSchedules = pgTable(
  "obligation_schedules",
  {
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    agreementId: text("agreement_id").notNull(),
    agreementRevision: integer("agreement_revision").notNull(),
    scheduleCommitment: text("schedule_commitment").notNull(),
    dueAt: timestamp("due_at", { withTimezone: true }).notNull(),
    state: obligationScheduleState("state").default("active").notNull(),
    materializedAt: timestamp("materialized_at", { withTimezone: true }),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.organizationId, table.agreementId, table.agreementRevision] }),
    index("obligation_schedules_org_commitment_idx").on(
      table.organizationId,
      table.agreementId,
      table.scheduleCommitment,
    ),
    index("obligation_schedules_due_idx").on(table.state, table.materializedAt, table.dueAt),
    index("obligation_schedules_org_active_idx").on(table.organizationId, table.state, table.dueAt),
  ],
);

export const proofBundles = pgTable(
  "proof_bundles",
  {
    id: text("id").primaryKey(),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    proofType: text("proof_type").notNull(),
    proofVersion: text("proof_version").notNull(),
    subjectRecordId: text("subject_record_id").notNull(),
    proofPackage: jsonb("proof_package").notNull(),
    proofHash: text("proof_hash").notNull(),
    verificationState: text("verification_state").default("unverified").notNull(),
    verificationTransactionHash: text("verification_transaction_hash"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("proof_bundles_run_idx").on(table.runId),
    uniqueIndex("proof_bundles_run_type_subject_idx").on(
      table.runId,
      table.proofType,
      table.subjectRecordId,
    ),
  ],
);

export const settlements = pgTable(
  "settlements",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    workflowType: text("workflow_type").default("payroll").notNull(),
    subjectRecordId: text("subject_record_id").notNull(),
    walletRequestId: text("wallet_request_id").notNull(),
    idempotencyKey: text("idempotency_key").notNull(),
    state: settlementState("state").default("approval_pending").notNull(),
    tokenTotalsCommitment: text("token_totals_commitment").notNull(),
    agentPlanCommitment: text("agent_plan_commitment"),
    transactionHash: text("transaction_hash"),
    submittedAt: timestamp("submitted_at", { withTimezone: true }),
    confirmedAt: timestamp("confirmed_at", { withTimezone: true }),
    finalizedAt: timestamp("finalized_at", { withTimezone: true }),
    blockNumber: bigint("block_number", { mode: "bigint" }),
    blockHash: text("block_hash"),
    confirmationDepth: integer("confirmation_depth").default(0).notNull(),
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("settlements_org_idempotency_idx").on(table.organizationId, table.idempotencyKey),
    uniqueIndex("settlements_transaction_hash_idx").on(table.transactionHash),
    index("settlements_state_updated_idx").on(table.state, table.updatedAt),
    index("settlements_run_idx").on(table.runId),
    index("settlements_workflow_subject_idx").on(table.workflowType, table.subjectRecordId),
  ],
);


/**
 * Durable public routing for one encrypted Remediation v7 attempt. Token,
 * amount, recipient and claim type remain inside the encrypted vault envelope.
 */
export const wageRemediations = pgTable(
  "wage_remediations",
  {
    id: text("id").primaryKey(),
    workerClaimId: text("worker_claim_id")
      .notNull()
      .references(() => workerClaims.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    claimantPrincipalId: text("claimant_principal_id").notNull(),
    proofBundleId: text("proof_bundle_id").notNull(),
    claimSubjectNullifier: text("claim_subject_nullifier").notNull(),
    claimFactCommitment: text("claim_fact_commitment").notNull(),
    remediationSubjectNullifier: text("remediation_subject_nullifier").notNull(),
    remediationFactCommitment: text("remediation_fact_commitment").notNull(),
    actionCommitment: text("action_commitment").notNull(),
    fxRoot: text("fx_root").notNull(),
    validityExpiresAt: timestamp("validity_expires_at", { withTimezone: true }).notNull(),
    state: wageRemediationState("state").default("prepared").notNull(),
    settlementId: text("settlement_id")
      .references(() => settlements.id, { onDelete: "set null" }),
    authorizedAt: timestamp("authorized_at", { withTimezone: true }),
    paymentConfirmedAt: timestamp("payment_confirmed_at", { withTimezone: true }),
    reconciledAt: timestamp("reconciled_at", { withTimezone: true }),
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("wage_remediations_proof_bundle_idx").on(table.proofBundleId),
    uniqueIndex("wage_remediations_subject_nullifier_idx").on(
      table.remediationSubjectNullifier,
    ),
    uniqueIndex("wage_remediations_action_commitment_idx").on(table.actionCommitment),
    uniqueIndex("wage_remediations_settlement_idx").on(table.settlementId),
    index("wage_remediations_claim_state_idx").on(
      table.workerClaimId,
      table.state,
      table.createdAt,
    ),
    index("wage_remediations_org_state_idx").on(
      table.organizationId,
      table.state,
      table.updatedAt,
    ),
  ],
);

export const confirmationJobs = pgTable(
  "confirmation_jobs",
  {
    id: text("id").primaryKey(),
    settlementId: text("settlement_id")
      .notNull()
      .references(() => settlements.id, { onDelete: "cascade" }),
    state: durableJobState("state").default("pending").notNull(),
    attempts: integer("attempts").default(0).notNull(),
    availableAt: timestamp("available_at", { withTimezone: true }).defaultNow().notNull(),
    leaseOwner: text("lease_owner"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    lastErrorCode: text("last_error_code"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("confirmation_jobs_settlement_idx").on(table.settlementId),
    index("confirmation_jobs_poll_idx").on(table.state, table.availableAt),
  ],
);

export const proofVerificationJobs = pgTable(
  "proof_verification_jobs",
  {
    id: text("id").primaryKey(),
    settlementId: text("settlement_id")
      .notNull()
      .references(() => settlements.id, { onDelete: "cascade" }),
    proofBundleId: text("proof_bundle_id")
      .notNull()
      .references(() => proofBundles.id, { onDelete: "cascade" }),
    state: durableJobState("state").default("pending").notNull(),
    nextShard: integer("next_shard").default(0).notNull(),
    shard0Calldata: jsonb("shard_0_calldata").notNull(),
    shard1Calldata: jsonb("shard_1_calldata").notNull(),
    activeTransactionHash: text("active_transaction_hash"),
    shard0TransactionHash: text("shard_0_transaction_hash"),
    shard1TransactionHash: text("shard_1_transaction_hash"),
    attempts: integer("attempts").default(0).notNull(),
    availableAt: timestamp("available_at", { withTimezone: true }).defaultNow().notNull(),
    leaseOwner: text("lease_owner"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("proof_verification_jobs_settlement_idx").on(table.settlementId),
    uniqueIndex("proof_verification_jobs_bundle_idx").on(table.proofBundleId),
    index("proof_verification_jobs_poll_idx").on(table.state, table.availableAt),
  ],
);

/**
 * Durable proof-first authorizations for the vNext exception seal. Claim and
 * remediation proofs are submitted by the server relayer before any private
 * payment can consume an authorization. Proof calldata contains public proof
 * material only; the private witness remains in the encrypted vault bundle.
 */
export const exceptionAuthorizationJobs = pgTable(
  "exception_authorization_jobs",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    proofBundleId: text("proof_bundle_id")
      .notNull()
      .references(() => proofBundles.id, { onDelete: "cascade" }),
    workflowType: text("workflow_type").notNull(),
    subjectRecordId: text("subject_record_id").notNull(),
    proofCalldata: jsonb("proof_calldata").notNull(),
    transitionMetadata: jsonb("transition_metadata"),
    state: durableJobState("state").default("pending").notNull(),
    activeStep: text("active_step").default("source").notNull(),
    transactionHash: text("transaction_hash"),
    sourceTransactionHash: text("source_transaction_hash"),
    bookBeginTransactionHash: text("book_begin_transaction_hash"),
    bookTransitionShard0TransactionHash: text("book_transition_shard_0_transaction_hash"),
    bookTransitionShard1TransactionHash: text("book_transition_shard_1_transaction_hash"),
    bookFinalizeTransactionHash: text("book_finalize_transaction_hash"),
    attempts: integer("attempts").default(0).notNull(),
    availableAt: timestamp("available_at", { withTimezone: true }).defaultNow().notNull(),
    leaseOwner: text("lease_owner"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    authorizedAt: timestamp("authorized_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("exception_authorization_jobs_bundle_idx").on(table.proofBundleId),
    uniqueIndex("exception_authorization_jobs_subject_idx").on(
      table.organizationId,
      table.workflowType,
      table.subjectRecordId,
    ),
    index("exception_authorization_jobs_poll_idx").on(table.state, table.availableAt),
  ],
);

/**
 * Staged proof-first authorization for a vNext payroll. The snapshot proof is
 * verified first; payroll shards are accepted only in their payday window.
 * The private STRK20 payment can consume the resulting authorization once.
 */
export const payrollAuthorizationJobs = pgTable(
  "payroll_authorization_jobs",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    payrollProofBundleId: text("payroll_proof_bundle_id")
      .notNull()
      .references(() => proofBundles.id, { onDelete: "cascade" }),
    snapshotProofBundleId: text("snapshot_proof_bundle_id")
      .notNull()
      .references(() => proofBundles.id, { onDelete: "cascade" }),
    payrollShard0Calldata: jsonb("payroll_shard_0_calldata").notNull(),
    payrollShard1Calldata: jsonb("payroll_shard_1_calldata").notNull(),
    snapshotProofCalldata: jsonb("snapshot_proof_calldata").notNull(),
    state: durableJobState("state").default("pending").notNull(),
    activeStep: text("active_step").default("begin").notNull(),
    transactionHash: text("transaction_hash"),
    beginTransactionHash: text("begin_transaction_hash"),
    snapshotTransactionHash: text("snapshot_transaction_hash"),
    shard0TransactionHash: text("shard_0_transaction_hash"),
    shard1TransactionHash: text("shard_1_transaction_hash"),
    attempts: integer("attempts").default(0).notNull(),
    availableAt: timestamp("available_at", { withTimezone: true }).defaultNow().notNull(),
    leaseOwner: text("lease_owner"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    authorizedAt: timestamp("authorized_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("payroll_authorization_jobs_run_idx").on(table.runId),
    uniqueIndex("payroll_authorization_jobs_payroll_bundle_idx").on(table.payrollProofBundleId),
    uniqueIndex("payroll_authorization_jobs_snapshot_bundle_idx").on(table.snapshotProofBundleId),
    index("payroll_authorization_jobs_poll_idx").on(table.state, table.availableAt),
  ],
);

/**
 * Five-step proof-first authorization for Advanced v3 state/book payroll.
 * The relayer verifies two Advanced v2 shards and two v3 shards before Ready
 * can atomically settle and append the committed period-book entry.
 */
export const vestingAuthorizationJobs = pgTable(
  "vesting_authorization_jobs",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    payrollProofBundleId: text("payroll_proof_bundle_id")
      .notNull()
      .references(() => proofBundles.id, { onDelete: "cascade" }),
    transitionMetadata: jsonb("transition_metadata").notNull(),
    payrollShard0Calldata: jsonb("payroll_shard_0_calldata").notNull(),
    payrollShard1Calldata: jsonb("payroll_shard_1_calldata").notNull(),
    transitionShard0Calldata: jsonb("transition_shard_0_calldata").notNull(),
    transitionShard1Calldata: jsonb("transition_shard_1_calldata").notNull(),
    state: durableJobState("state").default("pending").notNull(),
    activeStep: text("active_step").default("begin").notNull(),
    transactionHash: text("transaction_hash"),
    beginTransactionHash: text("begin_transaction_hash"),
    payrollShard0TransactionHash: text("payroll_shard_0_transaction_hash"),
    payrollShard1TransactionHash: text("payroll_shard_1_transaction_hash"),
    transitionShard0TransactionHash: text("transition_shard_0_transaction_hash"),
    transitionShard1TransactionHash: text("transition_shard_1_transaction_hash"),
    attempts: integer("attempts").default(0).notNull(),
    availableAt: timestamp("available_at", { withTimezone: true }).defaultNow().notNull(),
    leaseOwner: text("lease_owner"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    authorizedAt: timestamp("authorized_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("vesting_authorization_jobs_run_idx").on(table.runId),
    uniqueIndex("vesting_authorization_jobs_payroll_bundle_idx").on(table.payrollProofBundleId),
    index("vesting_authorization_jobs_poll_idx").on(table.state, table.availableAt),
  ],
);

export const fxPublicationJobs = pgTable(
  "fx_publication_jobs",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    principalId: text("principal_id").notNull(),
    catalogRoot: text("catalog_root").notNull(),
    proofVersion: integer("proof_version").notNull(),
    proofDigest: text("proof_digest").notNull(),
    shard0Calldata: jsonb("shard_0_calldata").notNull(),
    shard1Calldata: jsonb("shard_1_calldata").notNull(),
    observedAt: bigint("observed_at", { mode: "number" }).notNull(),
    maximumAgeSeconds: integer("maximum_age_seconds").notNull(),
    historicalRenewal: boolean("historical_renewal").default(false).notNull(),
    renewalRunId: text("renewal_run_id").references(() => payrollRuns.id, { onDelete: "set null" }),
    renewalCount: integer("renewal_count").default(0).notNull(),
    state: durableJobState("state").default("pending").notNull(),
    transactionHash: text("transaction_hash"),
    attempts: integer("attempts").default(0).notNull(),
    availableAt: timestamp("available_at", { withTimezone: true }).defaultNow().notNull(),
    leaseOwner: text("lease_owner"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("fx_publication_jobs_org_root_idx").on(table.organizationId, table.catalogRoot),
    index("fx_publication_jobs_poll_idx").on(table.state, table.availableAt),
  ],
);

export const idempotencyRequests = pgTable(
  "idempotency_requests",
  {
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    scope: text("scope").notNull(),
    key: text("key").notNull(),
    requestHash: text("request_hash").notNull(),
    state: idempotencyState("state").default("started").notNull(),
    response: jsonb("response"),
    errorCode: text("error_code"),
    lockedUntil: timestamp("locked_until", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.organizationId, table.scope, table.key] }),
    index("idempotency_requests_expiry_idx").on(table.expiresAt),
  ],
);

export const chainCursors = pgTable(
  "chain_cursors",
  {
    chainId: text("chain_id").notNull(),
    consumer: text("consumer").notNull(),
    blockNumber: bigint("block_number", { mode: "bigint" }).notNull(),
    blockHash: text("block_hash").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [primaryKey({ columns: [table.chainId, table.consumer] })],
);

export const indexedChainBlocks = pgTable(
  "indexed_chain_blocks",
  {
    chainId: text("chain_id").notNull(),
    blockNumber: bigint("block_number", { mode: "bigint" }).notNull(),
    blockHash: text("block_hash").notNull(),
    parentHash: text("parent_hash").notNull(),
    canonical: boolean("canonical").default(true).notNull(),
    observedAt: timestamp("observed_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.chainId, table.blockNumber] }),
    uniqueIndex("indexed_chain_blocks_hash_idx").on(table.chainId, table.blockHash),
  ],
);

export const indexedChainEvents = pgTable(
  "indexed_chain_events",
  {
    chainId: text("chain_id").notNull(),
    transactionHash: text("transaction_hash").notNull(),
    eventIndex: integer("event_index").notNull(),
    blockNumber: bigint("block_number", { mode: "bigint" }).notNull(),
    blockHash: text("block_hash").notNull(),
    contractAddress: text("contract_address").notNull(),
    eventName: text("event_name").notNull(),
    payload: jsonb("payload").notNull(),
    canonical: boolean("canonical").default(true).notNull(),
    observedAt: timestamp("observed_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.chainId, table.transactionHash, table.eventIndex] }),
    index("indexed_chain_events_block_idx").on(table.chainId, table.blockNumber),
  ],
);

export const disclosureGrants = pgTable(
  "disclosure_grants",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    granteePrincipalId: text("grantee_principal_id").notNull(),
    fieldScope: jsonb("field_scope").notNull(),
    envelopeRecordId: text("envelope_record_id").notNull(),
    validAfter: timestamp("valid_after", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("disclosure_grants_org_grantee_idx").on(table.organizationId, table.granteePrincipalId)],
);

export const receipts = pgTable(
  "receipts",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "cascade" }),
    settlementId: text("settlement_id")
      .notNull()
      .references(() => settlements.id, { onDelete: "cascade" }),
    scope: text("scope").notNull(),
    granteePrincipalId: text("grantee_principal_id").notNull(),
    envelopeRecordId: text("envelope_record_id").notNull(),
    packageCommitment: text("package_commitment").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("receipts_run_scope_idx").on(table.runId, table.scope)],
);

export const agentCapabilities = pgTable(
  "agent_capabilities",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    principalId: text("principal_id").notNull(),
    capabilityHash: text("capability_hash").notNull().unique(),
    policy: jsonb("policy").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("agent_capabilities_org_principal_idx").on(table.organizationId, table.principalId)],
);

/**
 * One-time-issued MCP bearer credentials. Only the SHA-256 digest is stored;
 * every request remains bound to the live capability and its exact API scope.
 */
export const agentAccessTokens = pgTable(
  "agent_access_tokens",
  {
    id: text("id").primaryKey(),
    capabilityId: text("capability_id")
      .notNull()
      .references(() => agentCapabilities.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    principalId: text("principal_id").notNull(),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("agent_access_tokens_token_hash_idx").on(table.tokenHash),
    index("agent_access_tokens_capability_idx").on(table.capabilityId, table.expiresAt),
    index("agent_access_tokens_org_principal_idx").on(table.organizationId, table.principalId),
  ],
);
export const capabilityReservations = pgTable(
  "capability_reservations",
  {
    id: text("id").primaryKey(),
    capabilityId: text("capability_id")
      .notNull()
      .references(() => agentCapabilities.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    idempotencyKey: text("idempotency_key").notNull(),
    requestHash: text("request_hash").notNull(),
    periodKey: text("period_key").notNull(),
    tokenTotals: jsonb("token_totals").notNull(),
    callCount: integer("call_count").default(1).notNull(),
    requiresApproval: boolean("requires_approval").default(true).notNull(),
    state: capabilityReservationState("state").default("reserved").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("capability_reservations_capability_idempotency_idx").on(table.capabilityId, table.idempotencyKey),
    index("capability_reservations_period_idx").on(table.capabilityId, table.periodKey, table.state),
  ],
);

export const agentExecutions = pgTable(
  "agent_executions",
  {
    id: text("id").primaryKey(),
    capabilityId: text("capability_id")
      .notNull()
      .references(() => agentCapabilities.id, { onDelete: "restrict" }),
    reservationId: text("reservation_id")
      .notNull()
      .unique()
      .references(() => capabilityReservations.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "restrict" }),
    settlementId: text("settlement_id")
      .references(() => settlements.id, { onDelete: "restrict" }),
    requestCommitment: text("request_commitment").notNull(),
    requestPayload: jsonb("request_payload").notNull(),
    state: agentExecutionState("state").default("reserved").notNull(),
    requiresApproval: boolean("requires_approval").notNull(),
    runVersion: integer("run_version").notNull(),
    transactionHash: text("transaction_hash"),
    attempts: integer("attempts").default(0).notNull(),
    availableAt: timestamp("available_at", { withTimezone: true }).defaultNow().notNull(),
    leaseOwner: text("lease_owner"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    lastErrorAt: timestamp("last_error_at", { withTimezone: true }),
    submissionCommitment: text("submission_commitment"),
    errorCode: text("error_code"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("agent_executions_capability_request_idx").on(
      table.capabilityId,
      table.requestCommitment,
    ),
    index("agent_executions_org_state_idx").on(
      table.organizationId,
      table.state,
      table.updatedAt,
    ),
    index("agent_executions_run_idx").on(table.runId),
    uniqueIndex("agent_executions_settlement_idx").on(table.settlementId),
  ],
);

/**
 * Canonical private-note identity and state for one deployed policy address.
 * Capabilities rotate; this treasury identity must not, otherwise notes become
 * undiscoverable or independently spendable from divergent registries.
 */
export const directPrivacyTreasuries = pgTable(
  "direct_privacy_treasuries",
  {
    policyAccountAddress: text("policy_account_address").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "restrict" }),
    poolAddress: text("pool_address").notNull(),
    encryptedSecrets: jsonb("encrypted_secrets").notNull(),
    encryptedState: jsonb("encrypted_state").notNull(),
    stateVersion: integer("state_version").default(1).notNull(),
    registrationState: text("registration_state").default("pending").notNull(),
    registrationPublicKey: text("registration_public_key"),
    registrationBlockNumber: bigint("registration_block_number", { mode: "bigint" }),
    registrationBlockHash: text("registration_block_hash"),
    registeredAt: timestamp("registered_at", { withTimezone: true }),
    activeExecutionId: text("active_execution_id"),
    activeAccountId: text("active_account_id"),
    activeLeaseExpiresAt: timestamp("active_lease_expires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("direct_privacy_treasuries_organization_idx").on(table.organizationId),
    index("direct_privacy_treasuries_registration_idx").on(table.registrationState),
  ],
);

/** One explicitly provisioned direct-SDK account per autonomous capability. */
export const directPrivacyAccounts = pgTable(
  "direct_privacy_accounts",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    capabilityId: text("capability_id")
      .notNull()
      .unique()
      .references(() => agentCapabilities.id, { onDelete: "restrict" }),
    treasuryAddress: text("treasury_address")
      .notNull()
      .references(() => directPrivacyTreasuries.policyAccountAddress, { onDelete: "restrict" }),
    config: jsonb("config").notNull(),
    encryptedSecrets: jsonb("encrypted_secrets").notNull(),
    activationState: text("activation_state").default("pending").notNull(),
    activationBlockNumber: bigint("activation_block_number", { mode: "bigint" }),
    activationBlockHash: text("activation_block_hash"),
    activationClassHash: text("activation_class_hash"),
    activationBlockTimestamp: bigint("activation_block_timestamp", { mode: "bigint" }),
    activatedAt: timestamp("activated_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("direct_privacy_accounts_org_idx").on(table.organizationId)],
);

/** Exact run paths reviewed by the owner before policy-account activation. */
export const directPrivacyAuthorizedRuns = pgTable(
  "direct_privacy_authorized_runs",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => directPrivacyAccounts.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "restrict" }),
    runVersion: integer("run_version").notNull(),
    agreementRoot: text("agreement_root").notNull(),
    manifestRoot: text("manifest_root").notNull(),
    runNullifier: text("run_nullifier").notNull(),
    leaf: text("leaf").notNull(),
    pathBits: integer("path_bits").notNull(),
    siblings: jsonb("siblings").notNull(),
    encryptedWitness: jsonb("encrypted_witness"),
    witnessStagedAt: timestamp("witness_staged_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("direct_privacy_authorized_account_run_version_idx").on(
      table.accountId,
      table.runId,
      table.runVersion,
    ),
    index("direct_privacy_authorized_org_run_idx").on(table.organizationId, table.runId),
  ],
);

/**
 * Owner-staged, executor-encrypted witness and exact run authorization.
 * Execution requests only reference this material; they cannot provide calls,
 * calldata, targets, proofs, or signer parameters.
 */
export const directPrivacyRunMaterials = pgTable(
  "direct_privacy_run_materials",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => directPrivacyAccounts.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    capabilityId: text("capability_id")
      .notNull()
      .references(() => agentCapabilities.id, { onDelete: "restrict" }),
    runId: text("run_id")
      .notNull()
      .references(() => payrollRuns.id, { onDelete: "restrict" }),
    runVersion: integer("run_version").notNull(),
    requestCommitment: text("request_commitment").notNull(),
    materialCommitment: text("material_commitment").notNull().unique(),
    encryptedMaterial: jsonb("encrypted_material").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("direct_privacy_material_cap_run_version_idx").on(
      table.capabilityId,
      table.runId,
      table.runVersion,
    ),
    index("direct_privacy_material_org_run_idx").on(table.organizationId, table.runId),
  ],
);

/**
 * Exact randomized PayrollIntegrity calldata persisted before the
 * permissionless precommit. Chain state is authoritative for crash recovery;
 * transaction hashes provide a redacted operational audit trail.
 */
export const directPrivacyPayrollAuthorizations = pgTable(
  "direct_privacy_payroll_authorizations",
  {
    executionId: text("execution_id")
      .primaryKey()
      .references(() => agentExecutions.id, { onDelete: "restrict" }),
    accountId: text("account_id")
      .notNull()
      .references(() => directPrivacyAccounts.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    authorizationCommitment: text("authorization_commitment").notNull().unique(),
    encryptedAuthorization: jsonb("encrypted_authorization").notNull(),
    state: text("state").default("proof_ready").notNull(),
    precommitTransactionHash: text("precommit_transaction_hash"),
    shard0TransactionHash: text("shard_0_transaction_hash"),
    shard1TransactionHash: text("shard_1_transaction_hash"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("direct_privacy_payroll_auth_org_state_idx").on(
    table.organizationId,
    table.state,
    table.updatedAt,
  )],
);

/** Encrypted, proof-bound plan persisted before any relayer signature exists. */
export const directPrivacyPreparations = pgTable(
  "direct_privacy_preparations",
  {
    executionId: text("execution_id")
      .primaryKey()
      .references(() => agentExecutions.id, { onDelete: "restrict" }),
    accountId: text("account_id")
      .notNull()
      .references(() => directPrivacyAccounts.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    preparationCommitment: text("preparation_commitment").notNull().unique(),
    encryptedPreparation: jsonb("encrypted_preparation").notNull(),
    state: text("state").default("prepared").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("direct_privacy_preparations_org_state_idx").on(
    table.organizationId,
    table.state,
    table.updatedAt,
  )],
);

/** Crash-safe storage for one pre-signed direct-SDK broadcast. */
export const directPrivacySubmissions = pgTable(
  "direct_privacy_submissions",
  {
    executionId: text("execution_id")
      .primaryKey()
      .references(() => agentExecutions.id, { onDelete: "restrict" }),
    accountId: text("account_id")
      .notNull()
      .references(() => directPrivacyAccounts.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    submissionCommitment: text("submission_commitment").notNull().unique(),
    expectedTransactionHash: text("expected_transaction_hash").notNull().unique(),
    encryptedPrepared: jsonb("encrypted_prepared").notNull(),
    state: text("state").default("prepared").notNull(),
    transactionHash: text("transaction_hash"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("direct_privacy_submissions_org_state_idx").on(
    table.organizationId,
    table.state,
    table.updatedAt,
  )],
);

/** Durable SettlementMatch proof and one crash-safe FINALIZE transaction at a time. */
export const directPrivacyReconciliations = pgTable(
  "direct_privacy_reconciliations",
  {
    executionId: text("execution_id")
      .primaryKey()
      .references(() => agentExecutions.id, { onDelete: "restrict" }),
    accountId: text("account_id")
      .notNull()
      .references(() => directPrivacyAccounts.id, { onDelete: "restrict" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    state: text("state").default("proving").notNull(),
    settlementRoot: text("settlement_root").notNull(),
    transactionReference: text("transaction_reference").notNull(),
    draftCommitment: text("draft_commitment").unique(),
    encryptedDraft: jsonb("encrypted_draft"),
    proofCommitment: text("proof_commitment").unique(),
    encryptedProof: jsonb("encrypted_proof"),
    chunkCount: integer("chunk_count"),
    verifiedCount: integer("verified_count").default(0).notNull(),
    activeChunkIndex: integer("active_chunk_index"),
    activeCalldataHash: text("active_calldata_hash"),
    activeFinalizationCommitment: text("active_finalization_commitment"),
    encryptedActiveFinalization: jsonb("encrypted_active_finalization"),
    activeExpectedTransactionHash: text("active_expected_transaction_hash").unique(),
    activeTransactionHash: text("active_transaction_hash"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("direct_privacy_reconciliations_org_state_idx").on(
    table.organizationId,
    table.state,
    table.updatedAt,
  )],
);

export const auditEvents = pgTable(
  "audit_events",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    actorId: text("actor_id").notNull(),
    action: text("action").notNull(),
    subjectId: text("subject_id"),
    metadata: jsonb("metadata").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("audit_events_org_created_idx").on(table.organizationId, table.createdAt)],
);
