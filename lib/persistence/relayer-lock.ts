import "server-only";

import { sql } from "drizzle-orm";
import { getDatabase } from "./db";

/**
 * Serializes nonce allocation for one Starknet relayer across all PAYO
 * processes sharing PostgreSQL. The lock is held only until the RPC accepts or
 * rejects the submission; confirmation polling happens after it is released.
 */
export async function withStarknetRelayerSubmissionLock<T>(
  relayerAddress: string,
  operation: () => Promise<T>,
): Promise<T> {
  return getDatabase().transaction(async (transaction) => {
    await transaction.execute(sql`
      select pg_advisory_xact_lock(
        hashtextextended(${`payo:starknet-relayer:${relayerAddress.toLowerCase()}`}, 0)
      )
    `);
    return operation();
  });
}
