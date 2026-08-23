import {
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

export const organizations = pgTable("organizations", {
  id: text("id").primaryKey(),
  encryptedProfile: jsonb("encrypted_profile").notNull(),
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
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.organizationId, table.principalId] }),
    index("organization_members_principal_idx").on(table.principalId),
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
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.organizationId, table.id, table.revision] }),
    index("vault_records_org_type_idx").on(table.organizationId, table.recordType),
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
    runNullifier: text("run_nullifier"),
    transactionHash: text("transaction_hash"),
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
    proofPackage: jsonb("proof_package").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("proof_bundles_run_idx").on(table.runId)],
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
