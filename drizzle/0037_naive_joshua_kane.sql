CREATE TABLE "direct_privacy_payroll_authorizations" (
	"execution_id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"authorization_commitment" text NOT NULL,
	"encrypted_authorization" jsonb NOT NULL,
	"state" text DEFAULT 'proof_ready' NOT NULL,
	"precommit_transaction_hash" text,
	"shard_0_transaction_hash" text,
	"shard_1_transaction_hash" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "direct_privacy_payroll_authorizations_authorization_commitment_unique" UNIQUE("authorization_commitment")
);
--> statement-breakpoint
ALTER TABLE "direct_privacy_payroll_authorizations" ADD CONSTRAINT "direct_privacy_payroll_authorizations_execution_id_agent_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."agent_executions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_payroll_authorizations" ADD CONSTRAINT "direct_privacy_payroll_authorizations_account_id_direct_privacy_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."direct_privacy_accounts"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_payroll_authorizations" ADD CONSTRAINT "direct_privacy_payroll_authorizations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "direct_privacy_payroll_auth_org_state_idx" ON "direct_privacy_payroll_authorizations" USING btree ("organization_id","state","updated_at");