CREATE TABLE "contributor_wallet_claims" (
	"organization_id" text NOT NULL,
	"address_commitment" text NOT NULL,
	"payee_record_id" text NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"released_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "contributor_wallet_claims_organization_id_address_commitment_pk" PRIMARY KEY("organization_id","address_commitment")
);
--> statement-breakpoint
CREATE TABLE "worker_public_identities" (
	"chain_id" text NOT NULL,
	"wallet_address" text NOT NULL,
	"principal_id" text NOT NULL,
	"fingerprint" text NOT NULL,
	"identity" jsonb NOT NULL,
	"first_published_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "worker_public_identities_chain_id_wallet_address_pk" PRIMARY KEY("chain_id","wallet_address")
);
--> statement-breakpoint
ALTER TABLE "contributor_wallet_claims" ADD CONSTRAINT "contributor_wallet_claims_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "contributor_wallet_claims_payee_idx" ON "contributor_wallet_claims" USING btree ("organization_id","payee_record_id");--> statement-breakpoint
CREATE INDEX "worker_public_identities_principal_idx" ON "worker_public_identities" USING btree ("chain_id","principal_id");