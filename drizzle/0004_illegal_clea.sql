CREATE TABLE "vault_key_grants" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"grantee_principal_id" text NOT NULL,
	"key_version" integer NOT NULL,
	"envelope" jsonb NOT NULL,
	"envelope_hash" text NOT NULL,
	"created_by" text NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "vault_key_grants" ADD CONSTRAINT "vault_key_grants_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "vault_key_grants_org_principal_version_idx" ON "vault_key_grants" USING btree ("organization_id","grantee_principal_id","key_version");--> statement-breakpoint
CREATE INDEX "vault_key_grants_grantee_idx" ON "vault_key_grants" USING btree ("grantee_principal_id","revoked_at");