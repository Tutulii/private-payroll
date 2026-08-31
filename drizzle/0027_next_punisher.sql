CREATE TABLE "direct_privacy_accounts" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"capability_id" text NOT NULL,
	"config" jsonb NOT NULL,
	"encrypted_secrets" jsonb NOT NULL,
	"encrypted_state" jsonb NOT NULL,
	"state_version" integer DEFAULT 1 NOT NULL,
	"active_execution_id" text,
	"active_lease_expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "direct_privacy_accounts_capability_id_unique" UNIQUE("capability_id")
);
--> statement-breakpoint
CREATE TABLE "direct_privacy_run_materials" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"capability_id" text NOT NULL,
	"run_id" text NOT NULL,
	"run_version" integer NOT NULL,
	"request_commitment" text NOT NULL,
	"material_commitment" text NOT NULL,
	"encrypted_material" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "direct_privacy_run_materials_material_commitment_unique" UNIQUE("material_commitment")
);
--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" ADD CONSTRAINT "direct_privacy_accounts_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_accounts" ADD CONSTRAINT "direct_privacy_accounts_capability_id_agent_capabilities_id_fk" FOREIGN KEY ("capability_id") REFERENCES "public"."agent_capabilities"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_run_materials" ADD CONSTRAINT "direct_privacy_run_materials_account_id_direct_privacy_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."direct_privacy_accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_run_materials" ADD CONSTRAINT "direct_privacy_run_materials_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_run_materials" ADD CONSTRAINT "direct_privacy_run_materials_capability_id_agent_capabilities_id_fk" FOREIGN KEY ("capability_id") REFERENCES "public"."agent_capabilities"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_run_materials" ADD CONSTRAINT "direct_privacy_run_materials_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "direct_privacy_accounts_org_idx" ON "direct_privacy_accounts" USING btree ("organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "direct_privacy_material_cap_run_version_idx" ON "direct_privacy_run_materials" USING btree ("capability_id","run_id","run_version");--> statement-breakpoint
CREATE INDEX "direct_privacy_material_org_run_idx" ON "direct_privacy_run_materials" USING btree ("organization_id","run_id");