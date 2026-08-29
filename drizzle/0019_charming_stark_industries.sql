ALTER TABLE "worker_claims" ALTER COLUMN "state" DROP DEFAULT;--> statement-breakpoint
CREATE TYPE "public"."worker_claim_state_next" AS ENUM('prepared', 'proved', 'authorization_pending', 'accepted', 'rejected');--> statement-breakpoint
ALTER TABLE "worker_claims" ALTER COLUMN "state" TYPE "public"."worker_claim_state_next" USING "state"::text::"public"."worker_claim_state_next";--> statement-breakpoint
DROP TYPE "public"."worker_claim_state";--> statement-breakpoint
ALTER TYPE "public"."worker_claim_state_next" RENAME TO "worker_claim_state";--> statement-breakpoint
ALTER TABLE "worker_claims" ALTER COLUMN "state" SET DEFAULT 'prepared';