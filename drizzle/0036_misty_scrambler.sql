ALTER TABLE "direct_privacy_reconciliations" ADD COLUMN "draft_commitment" text;--> statement-breakpoint
ALTER TABLE "direct_privacy_reconciliations" ADD COLUMN "encrypted_draft" jsonb;--> statement-breakpoint
ALTER TABLE "direct_privacy_reconciliations" ADD CONSTRAINT "direct_privacy_reconciliations_draft_commitment_unique" UNIQUE("draft_commitment");