import "server-only";

import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

export type Database = ReturnType<typeof drizzle<typeof schema>>;
export type DatabaseExecutor = Pick<Database, "select">;
type DatabaseClient = ReturnType<typeof postgres>;

let database: Database | undefined;
let databaseClient: DatabaseClient | undefined;

function poolSize(): number {
  const configured = Number(process.env.PAYO_DB_POOL_SIZE ?? "");
  if (Number.isInteger(configured) && configured >= 1 && configured <= 50) return configured;
  return process.env.NODE_ENV === "production" ? 10 : 4;
}

export function getDatabase(): Database {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required for PAYO's encrypted data service.");
  }
  if (!database) {
    databaseClient = postgres(databaseUrl, {
      max: poolSize(),
      prepare: false,
    });
    database = drizzle(databaseClient, { schema });
  }
  return database;
}

export async function closeDatabase(): Promise<void> {
  const client = databaseClient;
  database = undefined;
  databaseClient = undefined;
  if (client) await client.end({ timeout: 5 });
}
