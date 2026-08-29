CREATE TABLE "obligation_claim_access_grants" (
	"id" text PRIMARY KEY NOT NULL,
	"snapshot_plan_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"claimant_principal_id" text NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "obligation_claim_access_grants" ADD CONSTRAINT "obligation_claim_access_grants_snapshot_plan_id_obligation_snapshot_plans_id_fk" FOREIGN KEY ("snapshot_plan_id") REFERENCES "public"."obligation_snapshot_plans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "obligation_claim_access_grants" ADD CONSTRAINT "obligation_claim_access_grants_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "obligation_claim_access_grants" ADD CONSTRAINT "obligation_claim_access_grants_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "obligation_claim_access_claimant_idx" ON "obligation_claim_access_grants" USING btree ("claimant_principal_id","revoked_at","created_at");--> statement-breakpoint
CREATE INDEX "obligation_claim_access_snapshot_idx" ON "obligation_claim_access_grants" USING btree ("snapshot_plan_id");--> statement-breakpoint
CREATE INDEX "obligation_claim_access_run_idx" ON "obligation_claim_access_grants" USING btree ("run_id");