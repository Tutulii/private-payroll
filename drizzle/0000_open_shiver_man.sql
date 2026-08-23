CREATE TYPE "public"."organization_role" AS ENUM('admin', 'operator', 'reviewer');--> statement-breakpoint
CREATE TYPE "public"."payroll_run_state" AS ENUM('draft', 'calculated', 'proven', 'approval_pending', 'submitted', 'confirmed', 'reconciled', 'cancelled', 'failed', 'disputed');--> statement-breakpoint
CREATE TABLE "agent_capabilities" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"principal_id" text NOT NULL,
	"capability_hash" text NOT NULL,
	"policy" jsonb NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agent_capabilities_capability_hash_unique" UNIQUE("capability_hash")
);
--> statement-breakpoint
CREATE TABLE "audit_events" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"actor_id" text NOT NULL,
	"action" text NOT NULL,
	"subject_id" text,
	"metadata" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organization_members" (
	"organization_id" text NOT NULL,
	"principal_id" text NOT NULL,
	"role" "organization_role" NOT NULL,
	"vault_public_key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "organization_members_organization_id_principal_id_pk" PRIMARY KEY("organization_id","principal_id")
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" text PRIMARY KEY NOT NULL,
	"encrypted_profile" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "payroll_runs" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"cycle_id" text NOT NULL,
	"revision" integer NOT NULL,
	"state" "payroll_run_state" DEFAULT 'draft' NOT NULL,
	"due_at" timestamp with time zone NOT NULL,
	"manifest_root" text,
	"run_nullifier" text,
	"transaction_hash" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "proof_bundles" (
	"id" text PRIMARY KEY NOT NULL,
	"run_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"proof_type" text NOT NULL,
	"proof_version" text NOT NULL,
	"proof_package" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vault_records" (
	"id" text NOT NULL,
	"organization_id" text NOT NULL,
	"record_type" text NOT NULL,
	"revision" integer NOT NULL,
	"ciphertext" text NOT NULL,
	"envelope" jsonb NOT NULL,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vault_records_organization_id_id_revision_pk" PRIMARY KEY("organization_id","id","revision")
);
--> statement-breakpoint
ALTER TABLE "agent_capabilities" ADD CONSTRAINT "agent_capabilities_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_members" ADD CONSTRAINT "organization_members_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payroll_runs" ADD CONSTRAINT "payroll_runs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proof_bundles" ADD CONSTRAINT "proof_bundles_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proof_bundles" ADD CONSTRAINT "proof_bundles_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_records" ADD CONSTRAINT "vault_records_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "agent_capabilities_org_principal_idx" ON "agent_capabilities" USING btree ("organization_id","principal_id");--> statement-breakpoint
CREATE INDEX "audit_events_org_created_idx" ON "audit_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "organization_members_principal_idx" ON "organization_members" USING btree ("principal_id");--> statement-breakpoint
CREATE UNIQUE INDEX "payroll_runs_org_cycle_revision_idx" ON "payroll_runs" USING btree ("organization_id","cycle_id","revision");--> statement-breakpoint
CREATE UNIQUE INDEX "payroll_runs_nullifier_idx" ON "payroll_runs" USING btree ("run_nullifier");--> statement-breakpoint
CREATE INDEX "payroll_runs_org_due_idx" ON "payroll_runs" USING btree ("organization_id","due_at");--> statement-breakpoint
CREATE INDEX "proof_bundles_run_idx" ON "proof_bundles" USING btree ("run_id");--> statement-breakpoint
CREATE INDEX "vault_records_org_type_idx" ON "vault_records" USING btree ("organization_id","record_type");