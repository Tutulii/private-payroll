CREATE TABLE "ready_auth_challenges" (
	"id" text PRIMARY KEY NOT NULL,
	"wallet_address" text NOT NULL,
	"chain_id" text NOT NULL,
	"audience" text NOT NULL,
	"nonce" text NOT NULL,
	"issued_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"consumed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ready_auth_sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"token_hash" text NOT NULL,
	"wallet_address" text NOT NULL,
	"chain_id" text NOT NULL,
	"principal_id" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ready_principal_links" (
	"chain_id" text NOT NULL,
	"wallet_address" text NOT NULL,
	"principal_id" text NOT NULL,
	"link_method" text DEFAULT 'vault_recovery' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ready_principal_links_chain_id_wallet_address_pk" PRIMARY KEY("chain_id","wallet_address")
);
--> statement-breakpoint
CREATE TABLE "ready_recovery_link_challenges" (
	"id" text PRIMARY KEY NOT NULL,
	"wallet_address" text NOT NULL,
	"chain_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"legacy_principal_id" text NOT NULL,
	"proof_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"consumed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "ready_recovery_link_challenges" ADD CONSTRAINT "ready_recovery_link_challenges_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ready_auth_challenges_wallet_idx" ON "ready_auth_challenges" USING btree ("chain_id","wallet_address","expires_at");--> statement-breakpoint
CREATE INDEX "ready_auth_challenges_expiry_idx" ON "ready_auth_challenges" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "ready_auth_sessions_token_hash_idx" ON "ready_auth_sessions" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "ready_auth_sessions_wallet_idx" ON "ready_auth_sessions" USING btree ("chain_id","wallet_address","expires_at");--> statement-breakpoint
CREATE INDEX "ready_auth_sessions_principal_idx" ON "ready_auth_sessions" USING btree ("principal_id","expires_at");--> statement-breakpoint
CREATE INDEX "ready_principal_links_principal_idx" ON "ready_principal_links" USING btree ("principal_id");--> statement-breakpoint
CREATE INDEX "ready_recovery_link_wallet_idx" ON "ready_recovery_link_challenges" USING btree ("chain_id","wallet_address","expires_at");--> statement-breakpoint
CREATE INDEX "ready_recovery_link_expiry_idx" ON "ready_recovery_link_challenges" USING btree ("expires_at");