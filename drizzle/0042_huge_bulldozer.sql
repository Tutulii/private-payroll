ALTER TABLE "exception_authorization_jobs" ADD COLUMN "transition_metadata" jsonb;--> statement-breakpoint
ALTER TABLE "exception_authorization_jobs" ADD COLUMN "active_step" text DEFAULT 'source' NOT NULL;--> statement-breakpoint
ALTER TABLE "exception_authorization_jobs" ADD COLUMN "source_transaction_hash" text;--> statement-breakpoint
ALTER TABLE "exception_authorization_jobs" ADD COLUMN "book_begin_transaction_hash" text;--> statement-breakpoint
ALTER TABLE "exception_authorization_jobs" ADD COLUMN "book_transition_shard_0_transaction_hash" text;--> statement-breakpoint
ALTER TABLE "exception_authorization_jobs" ADD COLUMN "book_transition_shard_1_transaction_hash" text;--> statement-breakpoint
ALTER TABLE "exception_authorization_jobs" ADD COLUMN "book_finalize_transaction_hash" text;