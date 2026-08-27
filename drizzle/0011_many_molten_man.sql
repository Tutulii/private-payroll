ALTER TABLE "fx_publication_jobs" ADD COLUMN "historical_renewal" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "fx_publication_jobs" ADD COLUMN "renewal_run_id" text;--> statement-breakpoint
ALTER TABLE "fx_publication_jobs" ADD COLUMN "renewal_count" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "fx_publication_jobs" ADD CONSTRAINT "fx_publication_jobs_renewal_run_id_payroll_runs_id_fk" FOREIGN KEY ("renewal_run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE set null ON UPDATE no action;