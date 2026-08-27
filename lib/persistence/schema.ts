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
export const idempotencyState = pgEnum("idempotency_state", ["started", "succeeded", "failed"]);
export const capabilityReservationState = pgEnum("capability_reservation_state", [
  "reserved",
  "committed",
  "released",
  "expired",
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
    index("payroll_runs_org_due_idx").on(table.organizationId, table.dueAt),
  ],
);

/**
 * Opaque scheduling metadata only. The agreement kind, recipient, token and
 * value remain inside the encrypted pay-agreement vault revision. A due row is
 * a draft signal for the browser; it never authorizes or executes a payment.
 */
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
