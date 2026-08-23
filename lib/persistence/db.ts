import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

type Database = ReturnType<typeof drizzle<typeof schema>>;

let database: Database | undefined;

export function getDatabase(): Database {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required for PAYO's encrypted data service.");
  }
  if (!database) {
    const client = postgres(databaseUrl, {
      max: process.env.NODE_ENV === "production" ? 10 : 1,
      prepare: false,
    });
    database = drizzle(client, { schema });
  }
  return database;
}
