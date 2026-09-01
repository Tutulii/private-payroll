const DISABLED_MESSAGE =
  "starknet-devnet is disabled in PAYO production dependencies; use PAYO's pinned external Devnet test harness instead.";

export class Devnet {
  static async spawnInstalled() {
    throw new Error(DISABLED_MESSAGE);
  }
}
