ALTER TYPE "public"."agent_execution_state" ADD VALUE 'reconciled' BEFORE 'failed';--> statement-breakpoint
CREATE TABLE "direct_privacy_reconciliations" (
	"execution_id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"state" text DEFAULT 'proving' NOT NULL,
	"settlement_root" text NOT NULL,
	"transaction_reference" text NOT NULL,
	"proof_commitment" text,
	"encrypted_proof" jsonb,
	"chunk_count" integer,
	"verified_count" integer DEFAULT 0 NOT NULL,
	"active_chunk_index" integer,
	"active_calldata_hash" text,
	"active_finalization_commitment" text,
	"encrypted_active_finalization" jsonb,
	"active_expected_transaction_hash" text,
	"active_transaction_hash" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "direct_privacy_reconciliations_proof_commitment_unique" UNIQUE("proof_commitment"),
	CONSTRAINT "direct_privacy_reconciliations_active_expected_transaction_hash_unique" UNIQUE("active_expected_transaction_hash")
);
--> statement-breakpoint
ALTER TABLE "direct_privacy_reconciliations" ADD CONSTRAINT "direct_privacy_reconciliations_execution_id_agent_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."agent_executions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_reconciliations" ADD CONSTRAINT "direct_privacy_reconciliations_account_id_direct_privacy_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."direct_privacy_accounts"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_reconciliations" ADD CONSTRAINT "direct_privacy_reconciliations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "direct_privacy_reconciliations_org_state_idx" ON "direct_privacy_reconciliations" USING btree ("organization_id","state","updated_at");