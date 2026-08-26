DROP INDEX "proof_bundles_run_type_version_idx";--> statement-breakpoint
ALTER TABLE "proof_bundles" ADD COLUMN "subject_record_id" text;--> statement-breakpoint
UPDATE "proof_bundles" SET "subject_record_id" = "run_id" WHERE "subject_record_id" IS NULL;--> statement-breakpoint
ALTER TABLE "proof_bundles" ALTER COLUMN "subject_record_id" SET NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "proof_bundles_run_type_subject_idx" ON "proof_bundles" USING btree ("run_id","proof_type","subject_record_id");
