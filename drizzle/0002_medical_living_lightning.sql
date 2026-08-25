CREATE TABLE "indexed_chain_blocks" (
	"chain_id" text NOT NULL,
	"block_number" bigint NOT NULL,
	"block_hash" text NOT NULL,
	"parent_hash" text NOT NULL,
	"canonical" boolean DEFAULT true NOT NULL,
	"observed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "indexed_chain_blocks_chain_id_block_number_pk" PRIMARY KEY("chain_id","block_number")
);
--> statement-breakpoint
ALTER TABLE "capability_reservations" ADD COLUMN "request_hash" text;--> statement-breakpoint
UPDATE "capability_reservations" SET "request_hash" = 'legacy:' || "id" WHERE "request_hash" IS NULL;--> statement-breakpoint
ALTER TABLE "capability_reservations" ALTER COLUMN "request_hash" SET NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "indexed_chain_blocks_hash_idx" ON "indexed_chain_blocks" USING btree ("chain_id","block_hash");
