CREATE TABLE "exception_authorization_jobs" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"proof_bundle_id" text NOT NULL,
	"workflow_type" text NOT NULL,
	"subject_record_id" text NOT NULL,
	"proof_calldata" jsonb NOT NULL,
	"state" "durable_job_state" DEFAULT 'pending' NOT NULL,
	"transaction_hash" text,
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
ALTER TABLE "exception_authorization_jobs" ADD CONSTRAINT "exception_authorization_jobs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exception_authorization_jobs" ADD CONSTRAINT "exception_authorization_jobs_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exception_authorization_jobs" ADD CONSTRAINT "exception_authorization_jobs_proof_bundle_id_proof_bundles_id_fk" FOREIGN KEY ("proof_bundle_id") REFERENCES "public"."proof_bundles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "exception_authorization_jobs_bundle_idx" ON "exception_authorization_jobs" USING btree ("proof_bundle_id");--> statement-breakpoint
CREATE UNIQUE INDEX "exception_authorization_jobs_subject_idx" ON "exception_authorization_jobs" USING btree ("organization_id","workflow_type","subject_record_id");--> statement-breakpoint
CREATE INDEX "exception_authorization_jobs_poll_idx" ON "exception_authorization_jobs" USING btree ("state","available_at");