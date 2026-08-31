CREATE TABLE "direct_privacy_submissions" (
	"execution_id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"submission_commitment" text NOT NULL,
	"expected_transaction_hash" text NOT NULL,
	"encrypted_prepared" jsonb NOT NULL,
	"state" text DEFAULT 'prepared' NOT NULL,
	"transaction_hash" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "direct_privacy_submissions_submission_commitment_unique" UNIQUE("submission_commitment"),
	CONSTRAINT "direct_privacy_submissions_expected_transaction_hash_unique" UNIQUE("expected_transaction_hash")
);
--> statement-breakpoint
ALTER TABLE "direct_privacy_submissions" ADD CONSTRAINT "direct_privacy_submissions_execution_id_agent_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."agent_executions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_submissions" ADD CONSTRAINT "direct_privacy_submissions_account_id_direct_privacy_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."direct_privacy_accounts"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_submissions" ADD CONSTRAINT "direct_privacy_submissions_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "direct_privacy_submissions_org_state_idx" ON "direct_privacy_submissions" USING btree ("organization_id","state","updated_at");