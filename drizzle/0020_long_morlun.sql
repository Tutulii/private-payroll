CREATE TYPE "public"."employer_statement_state" AS ENUM('prepared', 'submitted', 'registered', 'failed');--> statement-breakpoint
CREATE TABLE "employer_statements" (
	"id" text PRIMARY KEY NOT NULL,
	"snapshot_plan_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"owner_address" text NOT NULL,
	"statement_fact" text NOT NULL,
	"manifest_root" text NOT NULL,
	"fx_root" text NOT NULL,
	"availability_commitment" text NOT NULL,
	"observed_at" timestamp with time zone NOT NULL,
	"source" text DEFAULT 'employer_statement' NOT NULL,
	"state" "employer_statement_state" DEFAULT 'prepared' NOT NULL,
	"registration_transaction_hash" text,
	"registered_at" timestamp with time zone,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "payroll_statement_evidence_grants" (
	"id" text PRIMARY KEY NOT NULL,
	"statement_id" text NOT NULL,
	"claim_access_grant_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"claimant_principal_id" text NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "employer_statements" ADD CONSTRAINT "employer_statements_snapshot_plan_id_obligation_snapshot_plans_id_fk" FOREIGN KEY ("snapshot_plan_id") REFERENCES "public"."obligation_snapshot_plans"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "employer_statements" ADD CONSTRAINT "employer_statements_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "employer_statements" ADD CONSTRAINT "employer_statements_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payroll_statement_evidence_grants" ADD CONSTRAINT "payroll_statement_evidence_grants_statement_id_employer_statements_id_fk" FOREIGN KEY ("statement_id") REFERENCES "public"."employer_statements"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payroll_statement_evidence_grants" ADD CONSTRAINT "payroll_statement_evidence_grants_claim_access_grant_id_obligation_claim_access_grants_id_fk" FOREIGN KEY ("claim_access_grant_id") REFERENCES "public"."obligation_claim_access_grants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payroll_statement_evidence_grants" ADD CONSTRAINT "payroll_statement_evidence_grants_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payroll_statement_evidence_grants" ADD CONSTRAINT "payroll_statement_evidence_grants_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "employer_statements_run_idx" ON "employer_statements" USING btree ("run_id");--> statement-breakpoint
CREATE UNIQUE INDEX "employer_statements_fact_idx" ON "employer_statements" USING btree ("statement_fact");--> statement-breakpoint
CREATE UNIQUE INDEX "employer_statements_transaction_idx" ON "employer_statements" USING btree ("registration_transaction_hash");--> statement-breakpoint
CREATE INDEX "employer_statements_org_state_idx" ON "employer_statements" USING btree ("organization_id","state","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "payroll_statement_evidence_statement_access_idx" ON "payroll_statement_evidence_grants" USING btree ("statement_id","claim_access_grant_id");--> statement-breakpoint
CREATE INDEX "payroll_statement_evidence_claimant_idx" ON "payroll_statement_evidence_grants" USING btree ("claimant_principal_id","revoked_at","created_at");--> statement-breakpoint
CREATE INDEX "payroll_statement_evidence_run_idx" ON "payroll_statement_evidence_grants" USING btree ("run_id");