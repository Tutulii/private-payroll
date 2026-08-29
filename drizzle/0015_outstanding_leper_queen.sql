CREATE TYPE "public"."obligation_snapshot_plan_state" AS ENUM('prepared', 'submitted', 'registered', 'consumed', 'cancelled', 'expired');--> statement-breakpoint
CREATE TABLE "obligation_snapshot_plans" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"cycle_id" text NOT NULL,
	"revision" integer NOT NULL,
	"owner_address" text NOT NULL,
	"agreement_root" text NOT NULL,
	"claim_root" text NOT NULL,
	"policy_root" text NOT NULL,
	"run_nullifier" text NOT NULL,
	"snapshot_fact" text NOT NULL,
	"due_at" timestamp with time zone NOT NULL,
	"grace_ends_at" timestamp with time zone NOT NULL,
	"claim_ends_at" timestamp with time zone NOT NULL,
	"state" "obligation_snapshot_plan_state" DEFAULT 'prepared' NOT NULL,
	"registration_transaction_hash" text,
	"registered_at" timestamp with time zone,
	"consumed_at" timestamp with time zone,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "payroll_runs" ADD COLUMN "obligation_snapshot_plan_id" text;--> statement-breakpoint
ALTER TABLE "obligation_snapshot_plans" ADD CONSTRAINT "obligation_snapshot_plans_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "obligation_snapshot_plans_org_cycle_revision_idx" ON "obligation_snapshot_plans" USING btree ("organization_id","cycle_id","revision");--> statement-breakpoint
CREATE UNIQUE INDEX "obligation_snapshot_plans_run_nullifier_idx" ON "obligation_snapshot_plans" USING btree ("run_nullifier");--> statement-breakpoint
CREATE UNIQUE INDEX "obligation_snapshot_plans_fact_idx" ON "obligation_snapshot_plans" USING btree ("snapshot_fact");--> statement-breakpoint
CREATE INDEX "obligation_snapshot_plans_org_due_idx" ON "obligation_snapshot_plans" USING btree ("organization_id","state","due_at");--> statement-breakpoint
ALTER TABLE "payroll_runs" ADD CONSTRAINT "payroll_runs_obligation_snapshot_plan_id_obligation_snapshot_plans_id_fk" FOREIGN KEY ("obligation_snapshot_plan_id") REFERENCES "public"."obligation_snapshot_plans"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "payroll_runs_snapshot_plan_idx" ON "payroll_runs" USING btree ("obligation_snapshot_plan_id");