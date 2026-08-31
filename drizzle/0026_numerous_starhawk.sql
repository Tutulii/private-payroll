ALTER TYPE "public"."agent_execution_state" ADD VALUE 'submitting' BEFORE 'submitted';--> statement-breakpoint
ALTER TABLE "agent_executions" ADD COLUMN "attempts" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "agent_executions" ADD COLUMN "available_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "agent_executions" ADD COLUMN "lease_owner" text;--> statement-breakpoint
ALTER TABLE "agent_executions" ADD COLUMN "lease_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agent_executions" ADD COLUMN "last_error_at" timestamp with time zone;