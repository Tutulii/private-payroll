CREATE TYPE "public"."agent_execution_state" AS ENUM('reserved', 'approval_pending', 'preparing', 'submitted', 'confirmed', 'failed', 'released');--> statement-breakpoint
CREATE TABLE "agent_executions" (
	"id" text PRIMARY KEY NOT NULL,
	"capability_id" text NOT NULL,
	"reservation_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"request_commitment" text NOT NULL,
	"request_payload" jsonb NOT NULL,
	"state" "agent_execution_state" DEFAULT 'reserved' NOT NULL,
	"requires_approval" boolean NOT NULL,
	"run_version" integer NOT NULL,
	"transaction_hash" text,
	"submission_commitment" text,
	"error_code" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agent_executions_reservation_id_unique" UNIQUE("reservation_id")
);
--> statement-breakpoint
ALTER TABLE "agent_executions" ADD CONSTRAINT "agent_executions_capability_id_agent_capabilities_id_fk" FOREIGN KEY ("capability_id") REFERENCES "public"."agent_capabilities"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_executions" ADD CONSTRAINT "agent_executions_reservation_id_capability_reservations_id_fk" FOREIGN KEY ("reservation_id") REFERENCES "public"."capability_reservations"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_executions" ADD CONSTRAINT "agent_executions_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_executions" ADD CONSTRAINT "agent_executions_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "agent_executions_capability_request_idx" ON "agent_executions" USING btree ("capability_id","request_commitment");--> statement-breakpoint
CREATE INDEX "agent_executions_org_state_idx" ON "agent_executions" USING btree ("organization_id","state","updated_at");--> statement-breakpoint
CREATE INDEX "agent_executions_run_idx" ON "agent_executions" USING btree ("run_id");