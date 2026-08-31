CREATE TABLE "direct_privacy_preparations" (
	"execution_id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"preparation_commitment" text NOT NULL,
	"encrypted_preparation" jsonb NOT NULL,
	"state" text DEFAULT 'prepared' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "direct_privacy_preparations_preparation_commitment_unique" UNIQUE("preparation_commitment")
);
--> statement-breakpoint
ALTER TABLE "direct_privacy_preparations" ADD CONSTRAINT "direct_privacy_preparations_execution_id_agent_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."agent_executions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_preparations" ADD CONSTRAINT "direct_privacy_preparations_account_id_direct_privacy_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."direct_privacy_accounts"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_preparations" ADD CONSTRAINT "direct_privacy_preparations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "direct_privacy_preparations_org_state_idx" ON "direct_privacy_preparations" USING btree ("organization_id","state","updated_at");