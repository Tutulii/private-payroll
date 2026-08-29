DROP INDEX "employer_statements_run_idx";--> statement-breakpoint
CREATE UNIQUE INDEX "employer_statements_run_fx_idx" ON "employer_statements" USING btree ("run_id","fx_root");