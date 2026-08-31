CREATE TABLE "agent_access_tokens" (
	"id" text PRIMARY KEY NOT NULL,
	"capability_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"principal_id" text NOT NULL,
	"token_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"last_seen_at" timestamp with time zone,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "agent_access_tokens" ADD CONSTRAINT "agent_access_tokens_capability_id_agent_capabilities_id_fk" FOREIGN KEY ("capability_id") REFERENCES "public"."agent_capabilities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_access_tokens" ADD CONSTRAINT "agent_access_tokens_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "agent_access_tokens_token_hash_idx" ON "agent_access_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "agent_access_tokens_capability_idx" ON "agent_access_tokens" USING btree ("capability_id","expires_at");--> statement-breakpoint
CREATE INDEX "agent_access_tokens_org_principal_idx" ON "agent_access_tokens" USING btree ("organization_id","principal_id");