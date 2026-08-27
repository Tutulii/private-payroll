CREATE TABLE "fx_publication_jobs" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"principal_id" text NOT NULL,
	"catalog_root" text NOT NULL,
	"proof_version" integer NOT NULL,
	"proof_digest" text NOT NULL,
	"shard_0_calldata" jsonb NOT NULL,
	"shard_1_calldata" jsonb NOT NULL,
	"observed_at" bigint NOT NULL,
	"maximum_age_seconds" integer NOT NULL,
	"state" "durable_job_state" DEFAULT 'pending' NOT NULL,
	"transaction_hash" text,
	"attempts" integer DEFAULT 0 NOT NULL,
	"available_at" timestamp with time zone DEFAULT now() NOT NULL,
	"lease_owner" text,
	"lease_expires_at" timestamp with time zone,
	"last_error_code" text,
	"last_error_message" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "fx_publication_jobs" ADD CONSTRAINT "fx_publication_jobs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "fx_publication_jobs_org_root_idx" ON "fx_publication_jobs" USING btree ("organization_id","catalog_root");--> statement-breakpoint
CREATE INDEX "fx_publication_jobs_poll_idx" ON "fx_publication_jobs" USING btree ("state","available_at");