const DEFAULT_PROVER_THREADS = 1;
const MAXIMUM_PROVER_THREADS = 4;

export function parseProverThreadCount(value: string | undefined): number {
  if (value === undefined || value.trim() === "") return DEFAULT_PROVER_THREADS;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAXIMUM_PROVER_THREADS) {
    throw new Error(`PAYO_PROVER_THREADS must be an integer from 1 to ${MAXIMUM_PROVER_THREADS}.`);
  }
  return parsed;
}
