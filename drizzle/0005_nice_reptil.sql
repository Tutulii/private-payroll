DO $$
BEGIN
	IF EXISTS (SELECT 1 FROM "settlements" LIMIT 1) THEN
		RAISE EXCEPTION USING
			MESSAGE = 'PAYO migration refused: legacy settlements contain plaintext token totals',
			HINT = 'Complete an authorized client-side encrypted export/re-import before applying migration 0005.';
	END IF;
END $$;--> statement-breakpoint
ALTER TABLE "settlements" ADD COLUMN "token_totals_commitment" text NOT NULL;--> statement-breakpoint
ALTER TABLE "settlements" DROP COLUMN "token_totals";
