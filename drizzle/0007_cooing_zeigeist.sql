ALTER TABLE "settlements" ADD COLUMN "workflow_type" text DEFAULT 'payroll' NOT NULL;--> statement-breakpoint
ALTER TABLE "settlements" ADD COLUMN "subject_record_id" text;--> statement-breakpoint
UPDATE "settlements" SET "subject_record_id" = "run_id" WHERE "subject_record_id" IS NULL;--> statement-breakpoint
ALTER TABLE "settlements" ALTER COLUMN "subject_record_id" SET NOT NULL;--> statement-breakpoint
CREATE INDEX "settlements_workflow_subject_idx" ON "settlements" USING btree ("workflow_type","subject_record_id");
