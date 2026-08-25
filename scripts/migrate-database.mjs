import { migrate } from "drizzle-orm/postgres-js/migrator";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error("DATABASE_URL is required before running PAYO database migrations.");
}

const client = postgres(databaseUrl, {
  max: 1,
  prepare: false,
  onnotice: () => undefined,
});

try {
  await migrate(drizzle(client), { migrationsFolder: "drizzle" });
  console.log("PAYO database migrations are current.");
} finally {
  await client.end({ timeout: 5 });
}
