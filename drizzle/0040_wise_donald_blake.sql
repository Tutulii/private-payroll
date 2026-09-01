CREATE TABLE "direct_privacy_treasuries" (
	"policy_account_address" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"pool_address" text NOT NULL,
	"encrypted_secrets" jsonb NOT NULL,
	"encrypted_state" jsonb NOT NULL,
	"state_version" integer DEFAULT 1 NOT NULL,
	"registration_state" text DEFAULT 'pending' NOT NULL,
	"registration_public_key" text,
	"registration_block_number" bigint,
	"registration_block_hash" text,
	"registered_at" timestamp with time zone,
	"active_execution_id" text,
	"active_account_id" text,
	"active_lease_expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" ADD COLUMN "treasury_address" text;--> statement-breakpoint
DO $$
BEGIN
	IF EXISTS (SELECT 1 FROM "direct_privacy_accounts") THEN
		RAISE EXCEPTION USING
			ERRCODE = '55000',
			MESSAGE = 'PAYO migration 0040 cannot contract a populated legacy direct_privacy_accounts table',
			HINT = 'Keep migration 0039 active and migrate each encrypted account into a canonical treasury before retrying 0040.';
	END IF;
END
$$;--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" ALTER COLUMN "treasury_address" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "direct_privacy_treasuries" ADD CONSTRAINT "direct_privacy_treasuries_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "direct_privacy_treasuries_organization_idx" ON "direct_privacy_treasuries" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "direct_privacy_treasuries_registration_idx" ON "direct_privacy_treasuries" USING btree ("registration_state");--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" ADD CONSTRAINT "direct_privacy_accounts_treasury_address_direct_privacy_treasuries_policy_account_address_fk" FOREIGN KEY ("treasury_address") REFERENCES "public"."direct_privacy_treasuries"("policy_account_address") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" DROP COLUMN "encrypted_state";--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" DROP COLUMN "state_version";--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" DROP COLUMN "active_execution_id";--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" DROP COLUMN "active_lease_expires_at";
