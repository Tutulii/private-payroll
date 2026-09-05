CREATE TABLE "vesting_authorization_jobs" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"payroll_proof_bundle_id" text NOT NULL,
	"transition_metadata" jsonb NOT NULL,
	"payroll_shard_0_calldata" jsonb NOT NULL,
	"payroll_shard_1_calldata" jsonb NOT NULL,
	"transition_shard_0_calldata" jsonb NOT NULL,
	"transition_shard_1_calldata" jsonb NOT NULL,
	"state" "durable_job_state" DEFAULT 'pending' NOT NULL,
	"active_step" text DEFAULT 'begin' NOT NULL,
	"transaction_hash" text,
	"begin_transaction_hash" text,
	"payroll_shard_0_transaction_hash" text,
	"payroll_shard_1_transaction_hash" text,
	"transition_shard_0_transaction_hash" text,
	"transition_shard_1_transaction_hash" text,
	"attempts" integer DEFAULT 0 NOT NULL,
	"available_at" timestamp with time zone DEFAULT now() NOT NULL,
	"lease_owner" text,
	"lease_expires_at" timestamp with time zone,
	"last_error_code" text,
	"last_error_message" text,
	"authorized_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "vesting_authorization_jobs" ADD CONSTRAINT "vesting_authorization_jobs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vesting_authorization_jobs" ADD CONSTRAINT "vesting_authorization_jobs_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vesting_authorization_jobs" ADD CONSTRAINT "vesting_authorization_jobs_payroll_proof_bundle_id_proof_bundles_id_fk" FOREIGN KEY ("payroll_proof_bundle_id") REFERENCES "public"."proof_bundles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "vesting_authorization_jobs_run_idx" ON "vesting_authorization_jobs" USING btree ("run_id");--> statement-breakpoint
CREATE UNIQUE INDEX "vesting_authorization_jobs_payroll_bundle_idx" ON "vesting_authorization_jobs" USING btree ("payroll_proof_bundle_id");--> statement-breakpoint
CREATE INDEX "vesting_authorization_jobs_poll_idx" ON "vesting_authorization_jobs" USING btree ("state","available_at");