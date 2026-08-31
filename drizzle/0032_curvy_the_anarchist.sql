CREATE TABLE "direct_privacy_authorized_runs" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"run_id" text NOT NULL,
	"run_version" integer NOT NULL,
	"agreement_root" text NOT NULL,
	"manifest_root" text NOT NULL,
	"run_nullifier" text NOT NULL,
	"leaf" text NOT NULL,
	"path_bits" integer NOT NULL,
	"siblings" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "direct_privacy_authorized_runs" ADD CONSTRAINT "direct_privacy_authorized_runs_account_id_direct_privacy_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."direct_privacy_accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_authorized_runs" ADD CONSTRAINT "direct_privacy_authorized_runs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "direct_privacy_authorized_runs" ADD CONSTRAINT "direct_privacy_authorized_runs_run_id_payroll_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."payroll_runs"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "direct_privacy_authorized_account_run_version_idx" ON "direct_privacy_authorized_runs" USING btree ("account_id","run_id","run_version");--> statement-breakpoint
CREATE INDEX "direct_privacy_authorized_org_run_idx" ON "direct_privacy_authorized_runs" USING btree ("organization_id","run_id");