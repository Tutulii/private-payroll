ALTER TABLE "payroll_authorization_jobs" ADD COLUMN "begin_transaction_hash" text;--> statement-breakpoint
ALTER TABLE "payroll_authorization_jobs" ADD COLUMN "snapshot_transaction_hash" text;--> statement-breakpoint
ALTER TABLE "payroll_authorization_jobs" ADD COLUMN "shard_0_transaction_hash" text;--> statement-breakpoint
ALTER TABLE "payroll_authorization_jobs" ADD COLUMN "shard_1_transaction_hash" text;