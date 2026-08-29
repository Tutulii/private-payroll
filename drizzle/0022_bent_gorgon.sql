CREATE TYPE "public"."wage_remediation_state" AS ENUM('prepared', 'proved', 'authorization_pending', 'authorized', 'payment_pending', 'payment_confirmed', 'reconciled', 'expired', 'failed');--> statement-breakpoint
CREATE TABLE "wage_remediations" (
	"id" text PRIMARY KEY NOT NULL,
	"worker_claim_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"claimant_principal_id" text NOT NULL,
	"proof_bundle_id" text NOT NULL,
	"claim_subject_nullifier" text NOT NULL,
	"claim_fact_commitment" text NOT NULL,
	"remediation_subject_nullifier" text NOT NULL,
	"remediation_fact_commitment" text NOT NULL,
	"action_commitment" text NOT NULL,
	"fx_root" text NOT NULL,
	"validity_expires_at" timestamp with time zone NOT NULL,
	"state" "wage_remediation_state" DEFAULT 'prepared' NOT NULL,
	"settlement_id" text,
	"authorized_at" timestamp with time zone,
	"payment_confirmed_at" timestamp with time zone,
	"reconciled_at" timestamp with time zone,
	"last_error_code" text,
	"last_error_message" text,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "wage_remediations" ADD CONSTRAINT "wage_remediations_worker_claim_id_worker_claims_id_fk" FOREIGN KEY ("worker_claim_id") REFERENCES "public"."worker_claims"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wage_remediations" ADD CONSTRAINT "wage_remediations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wage_remediations" ADD CONSTRAINT "wage_remediations_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wage_remediations" ADD CONSTRAINT "wage_remediations_settlement_id_settlements_id_fk" FOREIGN KEY ("settlement_id") REFERENCES "public"."settlements"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "wage_remediations_proof_bundle_idx" ON "wage_remediations" USING btree ("proof_bundle_id");--> statement-breakpoint
CREATE UNIQUE INDEX "wage_remediations_subject_nullifier_idx" ON "wage_remediations" USING btree ("remediation_subject_nullifier");--> statement-breakpoint
CREATE UNIQUE INDEX "wage_remediations_action_commitment_idx" ON "wage_remediations" USING btree ("action_commitment");--> statement-breakpoint
CREATE UNIQUE INDEX "wage_remediations_settlement_idx" ON "wage_remediations" USING btree ("settlement_id");--> statement-breakpoint
CREATE INDEX "wage_remediations_claim_state_idx" ON "wage_remediations" USING btree ("worker_claim_id","state","created_at");--> statement-breakpoint
CREATE INDEX "wage_remediations_org_state_idx" ON "wage_remediations" USING btree ("organization_id","state","updated_at");