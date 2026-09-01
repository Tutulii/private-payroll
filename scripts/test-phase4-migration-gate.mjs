import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import postgres from "postgres";

const databaseUrl = process.env.PAYO_TEST_DATABASE_URL ?? process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("PAYO_TEST_DATABASE_URL or DATABASE_URL is required for the migration gate.");
}

const root = resolve(import.meta.dirname, "..");
const journal = JSON.parse(await readFile(resolve(root, "drizzle/meta/_journal.json"), "utf8"));
const legacyEntries = journal.entries.filter(({ idx }) => idx < 40);
const currentEntry = journal.entries.find(({ idx }) => idx === 40);
if (legacyEntries.length !== 40 || currentEntry?.tag !== "0040_wise_donald_blake") {
  throw new Error("The Phase 4 migration gate is not aligned with the Drizzle journal.");
}

function statements(source) {
  return source.split("--> statement-breakpoint").map((value) => value.trim()).filter(Boolean);
}

const suffix = randomBytes(6).toString("hex");
const databaseName = `payo_p4_migration_${suffix}`;
const adminUrl = new URL(databaseUrl);
adminUrl.pathname = "/postgres";
const testUrl = new URL(databaseUrl);
testUrl.pathname = `/${databaseName}`;
const admin = postgres(adminUrl.toString(), { max: 1, prepare: false, onnotice: () => undefined });
let legacy;

try {
  await admin.unsafe(`CREATE DATABASE "${databaseName}"`);
  legacy = postgres(testUrl.toString(), { max: 1, prepare: false, onnotice: () => undefined });
  for (const entry of legacyEntries) {
    const sql = await readFile(resolve(root, `drizzle/${entry.tag}.sql`), "utf8");
    await legacy.begin(async (transaction) => {
      for (const statement of statements(sql)) await transaction.unsafe(statement);
    });
  }

  await legacy.unsafe("SET session_replication_role = replica");
  try {
    await legacy.unsafe(`
      INSERT INTO direct_privacy_accounts (
        id, organization_id, capability_id, config, encrypted_secrets, encrypted_state
      ) VALUES (
        'legacy-account', 'legacy-org', 'legacy-capability',
        '{"policyAccountAddress":"0x123","poolAddress":"0x456"}'::jsonb,
        '{}'::jsonb, '{}'::jsonb
      )
    `);
  } finally {
    await legacy.unsafe("SET session_replication_role = origin");
  }

  const migration = await readFile(resolve(root, `drizzle/${currentEntry.tag}.sql`), "utf8");
  let rejected = false;
  try {
    await legacy.begin(async (transaction) => {
      for (const statement of statements(migration)) await transaction.unsafe(statement);
    });
  } catch (error) {
    rejected = error?.code === "55000"
      && String(error?.message).includes("cannot contract a populated legacy");
  }
  if (!rejected) throw new Error("Migration 0040 did not reject a populated legacy account table.");

  const [verification] = await legacy.unsafe(`
    SELECT
      (SELECT count(*)::int FROM direct_privacy_accounts) AS account_count,
      to_regclass('public.direct_privacy_treasuries') IS NULL AS treasury_rolled_back,
      (SELECT count(*)::int FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'direct_privacy_accounts'
          AND column_name = 'treasury_address') AS treasury_column_count,
      (SELECT count(*)::int FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'direct_privacy_accounts'
          AND column_name IN ('encrypted_state', 'state_version', 'active_execution_id', 'active_lease_expires_at'))
        AS legacy_column_count
  `);
  if (
    verification.account_count !== 1
    || verification.treasury_rolled_back !== true
    || verification.treasury_column_count !== 0
    || verification.legacy_column_count !== 4
  ) throw new Error("Migration 0040 did not roll back every schema and data mutation.");

  process.stdout.write(
    "Phase 4 migration gate passed: populated legacy state is rejected and fully preserved.\n",
  );
} finally {
  if (legacy) await legacy.end({ timeout: 5 });
  await admin.unsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  await admin.end({ timeout: 5 });
}
