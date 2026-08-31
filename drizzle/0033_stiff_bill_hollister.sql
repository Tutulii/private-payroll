ALTER TYPE "public"."capability_reservation_state" ADD VALUE 'approval_linked' BEFORE 'committed';--> statement-breakpoint
ALTER TABLE "agent_executions" ADD COLUMN "settlement_id" text;--> statement-breakpoint
ALTER TABLE "agent_executions" ADD CONSTRAINT "agent_executions_settlement_id_settlements_id_fk" FOREIGN KEY ("settlement_id") REFERENCES "public"."settlements"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "agent_executions_settlement_idx" ON "agent_executions" USING btree ("settlement_id");