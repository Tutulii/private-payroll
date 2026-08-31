ALTER TABLE "direct_privacy_accounts" ADD COLUMN "activation_state" text DEFAULT 'pending' NOT NULL;--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" ADD COLUMN "activation_block_number" bigint;--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" ADD COLUMN "activation_block_hash" text;--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" ADD COLUMN "activated_at" timestamp with time zone;