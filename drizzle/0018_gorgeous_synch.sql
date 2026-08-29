CREATE TYPE "public"."worker_claim_state" AS ENUM('proved', 'authorization_pending', 'accepted', 'rejected');--> statement-breakpoint
CREATE TABLE "worker_claims" (
	"id" text PRIMARY KEY NOT NULL,
	"claim_access_grant_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"claimant_principal_id" text NOT NULL,
	"proof_bundle_id" text NOT NULL,
	"claim_subject_nullifier" text NOT NULL,
	"claim_fact_commitment" text NOT NULL,
	"state" "worker_claim_state" DEFAULT 'proved' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "worker_claims" ADD CONSTRAINT "worker_claims_claim_access_grant_id_obligation_claim_access_grants_id_fk" FOREIGN KEY ("claim_access_grant_id") REFERENCES "public"."obligation_claim_access_grants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "worker_claims" ADD CONSTRAINT "worker_claims_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "worker_claims" ADD CONSTRAINT "worker_claims_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "worker_claims_proof_bundle_idx" ON "worker_claims" USING btree ("proof_bundle_id");--> statement-breakpoint
CREATE UNIQUE INDEX "worker_claims_subject_nullifier_idx" ON "worker_claims" USING btree ("claim_subject_nullifier");--> statement-breakpoint
CREATE INDEX "worker_claims_claimant_idx" ON "worker_claims" USING btree ("claimant_principal_id","created_at");--> statement-breakpoint
CREATE INDEX "worker_claims_org_run_idx" ON "worker_claims" USING btree ("organization_id","run_id");--> statement-breakpoint
CREATE INDEX "worker_claims_access_grant_idx" ON "worker_claims" USING btree ("claim_access_grant_id");