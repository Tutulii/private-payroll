CREATE TABLE "proof_verification_jobs" (
	"id" text PRIMARY KEY NOT NULL,
	"settlement_id" text NOT NULL,
	"proof_bundle_id" text NOT NULL,
	"state" "durable_job_state" DEFAULT 'pending' NOT NULL,
	"next_shard" integer DEFAULT 0 NOT NULL,
	"shard_0_calldata" jsonb NOT NULL,
	"shard_1_calldata" jsonb NOT NULL,
	"active_transaction_hash" text,
	"shard_0_transaction_hash" text,
	"shard_1_transaction_hash" text,
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
ALTER TABLE "proof_verification_jobs" ADD CONSTRAINT "proof_verification_jobs_settlement_id_settlements_id_fk" FOREIGN KEY ("settlement_id") REFERENCES "public"."settlements"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proof_verification_jobs" ADD CONSTRAINT "proof_verification_jobs_proof_bundle_id_proof_bundles_id_fk" FOREIGN KEY ("proof_bundle_id") REFERENCES "public"."proof_bundles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "proof_verification_jobs_settlement_idx" ON "proof_verification_jobs" USING btree ("settlement_id");--> statement-breakpoint
CREATE UNIQUE INDEX "proof_verification_jobs_bundle_idx" ON "proof_verification_jobs" USING btree ("proof_bundle_id");--> statement-breakpoint
CREATE INDEX "proof_verification_jobs_poll_idx" ON "proof_verification_jobs" USING btree ("state","available_at");