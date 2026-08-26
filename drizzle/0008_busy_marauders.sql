CREATE TYPE "public"."obligation_schedule_state" AS ENUM('active', 'superseded');--> statement-breakpoint
CREATE TABLE "obligation_schedules" (
	"organization_id" text NOT NULL,
	"agreement_id" text NOT NULL,
	"agreement_revision" integer NOT NULL,
	"schedule_commitment" text NOT NULL,
	"due_at" timestamp with time zone NOT NULL,
	"state" "obligation_schedule_state" DEFAULT 'active' NOT NULL,
	"materialized_at" timestamp with time zone,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "obligation_schedules_organization_id_agreement_id_agreement_revision_pk" PRIMARY KEY("organization_id","agreement_id","agreement_revision")
);
--> statement-breakpoint
ALTER TABLE "obligation_schedules" ADD CONSTRAINT "obligation_schedules_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "obligation_schedules_org_commitment_idx" ON "obligation_schedules" USING btree ("organization_id","agreement_id","schedule_commitment");--> statement-breakpoint
CREATE INDEX "obligation_schedules_due_idx" ON "obligation_schedules" USING btree ("state","materialized_at","due_at");--> statement-breakpoint
CREATE INDEX "obligation_schedules_org_active_idx" ON "obligation_schedules" USING btree ("organization_id","state","due_at");