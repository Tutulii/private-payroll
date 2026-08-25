CREATE TYPE "public"."capability_reservation_state" AS ENUM('reserved', 'committed', 'released', 'expired');--> statement-breakpoint
CREATE TYPE "public"."durable_job_state" AS ENUM('pending', 'leased', 'complete', 'dead');--> statement-breakpoint
CREATE TYPE "public"."idempotency_state" AS ENUM('started', 'succeeded', 'failed');--> statement-breakpoint
CREATE TYPE "public"."recovery_state" AS ENUM('required', 'package_downloaded', 'second_admin');--> statement-breakpoint
CREATE TYPE "public"."settlement_state" AS ENUM('approval_pending', 'submitted', 'confirmed', 'finalized', 'reorged', 'failed', 'reconciled');--> statement-breakpoint
CREATE TABLE "capability_reservations" (
	"id" text PRIMARY KEY NOT NULL,
	"capability_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"idempotency_key" text NOT NULL,
	"period_key" text NOT NULL,
	"token_totals" jsonb NOT NULL,
	"state" "capability_reservation_state" DEFAULT 'reserved' NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "chain_cursors" (
	"chain_id" text NOT NULL,
	"consumer" text NOT NULL,
	"block_number" bigint NOT NULL,
	"block_hash" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "chain_cursors_chain_id_consumer_pk" PRIMARY KEY("chain_id","consumer")
);
--> statement-breakpoint
CREATE TABLE "confirmation_jobs" (
	"id" text PRIMARY KEY NOT NULL,
	"settlement_id" text NOT NULL,
	"state" "durable_job_state" DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"available_at" timestamp with time zone DEFAULT now() NOT NULL,
	"lease_owner" text,
	"lease_expires_at" timestamp with time zone,
	"last_error_code" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "disclosure_grants" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"grantee_principal_id" text NOT NULL,
	"field_scope" jsonb NOT NULL,
	"envelope_record_id" text NOT NULL,
	"valid_after" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "idempotency_requests" (
	"organization_id" text NOT NULL,
	"scope" text NOT NULL,
	"key" text NOT NULL,
	"request_hash" text NOT NULL,
	"state" "idempotency_state" DEFAULT 'started' NOT NULL,
	"response" jsonb,
	"error_code" text,
	"locked_until" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "idempotency_requests_organization_id_scope_key_pk" PRIMARY KEY("organization_id","scope","key")
);
--> statement-breakpoint
CREATE TABLE "indexed_chain_events" (
	"chain_id" text NOT NULL,
	"transaction_hash" text NOT NULL,
	"event_index" integer NOT NULL,
	"block_number" bigint NOT NULL,
	"block_hash" text NOT NULL,
	"contract_address" text NOT NULL,
	"event_name" text NOT NULL,
	"payload" jsonb NOT NULL,
	"canonical" boolean DEFAULT true NOT NULL,
	"observed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "indexed_chain_events_chain_id_transaction_hash_event_index_pk" PRIMARY KEY("chain_id","transaction_hash","event_index")
);
--> statement-breakpoint
CREATE TABLE "receipts" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"settlement_id" text NOT NULL,
	"scope" text NOT NULL,
	"grantee_principal_id" text NOT NULL,
	"envelope_record_id" text NOT NULL,
	"package_commitment" text NOT NULL,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "settlements" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"wallet_request_id" text NOT NULL,
	"idempotency_key" text NOT NULL,
	"state" "settlement_state" DEFAULT 'approval_pending' NOT NULL,
	"token_totals" jsonb NOT NULL,
	"transaction_hash" text,
	"submitted_at" timestamp with time zone,
	"confirmed_at" timestamp with time zone,
	"finalized_at" timestamp with time zone,
	"block_number" bigint,
	"block_hash" text,
	"confirmation_depth" integer DEFAULT 0 NOT NULL,
	"last_error_code" text,
	"last_error_message" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "organization_members" ADD COLUMN "key_version" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "organization_members" ADD COLUMN "revoked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "recovery_state" "recovery_state" DEFAULT 'required' NOT NULL;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "recovery_package_hash" text;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "recovery_configured_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "key_version" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "payroll_runs" ADD COLUMN "agreement_root" text;--> statement-breakpoint
ALTER TABLE "payroll_runs" ADD COLUMN "policy_root" text;--> statement-breakpoint
ALTER TABLE "payroll_runs" ADD COLUMN "fx_root" text;--> statement-breakpoint
ALTER TABLE "payroll_runs" ADD COLUMN "version" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "proof_bundles" ADD COLUMN "proof_hash" text;--> statement-breakpoint
UPDATE "proof_bundles" SET "proof_hash" = 'legacy:' || "id" WHERE "proof_hash" IS NULL;--> statement-breakpoint
ALTER TABLE "proof_bundles" ALTER COLUMN "proof_hash" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "proof_bundles" ADD COLUMN "verification_state" text DEFAULT 'unverified' NOT NULL;--> statement-breakpoint
ALTER TABLE "proof_bundles" ADD COLUMN "verification_transaction_hash" text;--> statement-breakpoint
ALTER TABLE "vault_records" ADD COLUMN "envelope_hash" text;--> statement-breakpoint
UPDATE "vault_records" SET "envelope_hash" = 'legacy:' || "id" || ':' || "revision"::text WHERE "envelope_hash" IS NULL;--> statement-breakpoint
ALTER TABLE "vault_records" ALTER COLUMN "envelope_hash" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "vault_records" ADD COLUMN "superseded_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "capability_reservations" ADD CONSTRAINT "capability_reservations_capability_id_agent_capabilities_id_fk" FOREIGN KEY ("capability_id") REFERENCES "public"."agent_capabilities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "capability_reservations" ADD CONSTRAINT "capability_reservations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "confirmation_jobs" ADD CONSTRAINT "confirmation_jobs_settlement_id_settlements_id_fk" FOREIGN KEY ("settlement_id") REFERENCES "public"."settlements"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "disclosure_grants" ADD CONSTRAINT "disclosure_grants_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "disclosure_grants" ADD CONSTRAINT "disclosure_grants_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "idempotency_requests" ADD CONSTRAINT "idempotency_requests_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "receipts" ADD CONSTRAINT "receipts_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "receipts" ADD CONSTRAINT "receipts_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "receipts" ADD CONSTRAINT "receipts_settlement_id_settlements_id_fk" FOREIGN KEY ("settlement_id") REFERENCES "public"."settlements"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "settlements" ADD CONSTRAINT "settlements_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "settlements" ADD CONSTRAINT "settlements_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "capability_reservations_capability_idempotency_idx" ON "capability_reservations" USING btree ("capability_id","idempotency_key");--> statement-breakpoint
CREATE INDEX "capability_reservations_period_idx" ON "capability_reservations" USING btree ("capability_id","period_key","state");--> statement-breakpoint
CREATE UNIQUE INDEX "confirmation_jobs_settlement_idx" ON "confirmation_jobs" USING btree ("settlement_id");--> statement-breakpoint
CREATE INDEX "confirmation_jobs_poll_idx" ON "confirmation_jobs" USING btree ("state","available_at");--> statement-breakpoint
CREATE INDEX "disclosure_grants_org_grantee_idx" ON "disclosure_grants" USING btree ("organization_id","grantee_principal_id");--> statement-breakpoint
CREATE INDEX "idempotency_requests_expiry_idx" ON "idempotency_requests" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "indexed_chain_events_block_idx" ON "indexed_chain_events" USING btree ("chain_id","block_number");--> statement-breakpoint
CREATE INDEX "receipts_run_scope_idx" ON "receipts" USING btree ("run_id","scope");--> statement-breakpoint
CREATE UNIQUE INDEX "settlements_org_idempotency_idx" ON "settlements" USING btree ("organization_id","idempotency_key");--> statement-breakpoint
CREATE UNIQUE INDEX "settlements_transaction_hash_idx" ON "settlements" USING btree ("transaction_hash");--> statement-breakpoint
CREATE INDEX "settlements_state_updated_idx" ON "settlements" USING btree ("state","updated_at");--> statement-breakpoint
CREATE INDEX "settlements_run_idx" ON "settlements" USING btree ("run_id");--> statement-breakpoint
CREATE UNIQUE INDEX "proof_bundles_run_type_version_idx" ON "proof_bundles" USING btree ("run_id","proof_type","proof_version");--> statement-breakpoint
CREATE UNIQUE INDEX "vault_records_org_envelope_hash_idx" ON "vault_records" USING btree ("organization_id","envelope_hash");
