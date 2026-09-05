# Phase 5 autonomous-agent checkpoint

Status: paused at the user's request on 2026-09-04 (Asia/Dhaka).

## Live attempt diagnosed

- Capability: `01a065c9-e041-7c28-bea3-2fdbf61c22bd`.
- Payroll run: `01a065c8-59e0-79b9-b85c-e86db7bb67ad`.
- Execution: `01a065da-b64c-7b40-8571-867ad7b26c29`.
- PostgreSQL ended the execution as `failed` after 8 attempts with
  `AGENT_PREPARATION_FAILED`; the later terminal code was
  `AGENT_EXECUTION_REAUTHORIZATION_DENIED`.
- No transaction was broadcast, no funds moved, and the reservation was
  released.
- The live prover completed this execution's PayrollIntegrity proof at
  `2026-09-03T06:06:17Z` in `340862 ms`, after the execution had already been
  failed at `2026-09-03T06:04:34.727Z`.

## Confirmed root cause

Payment intents are valid for at most five minutes. The worker incorrectly
replayed that short admission check against current wall-clock time on every
proof-polling lease. The real Mainnet proof needed about 5 minutes 41 seconds,
so a correctly admitted and reserved execution was failed while its proof was
still running. The prover and policy account were active; this was a worker
authorization-lifetime bug.

## Uncommitted production fix

Modified files:

- `lib/persistence/capability-reservations.ts`
- `lib/persistence/agent-execution-worker-repository.ts`
- `lib/server/agent-execution-worker.ts`
- `lib/persistence/agent-execution-worker-repository.integration-helper.ts`
- `lib/persistence/direct-privacy-repository.integration-helper.ts`
- `lib/server/agent-execution-worker.test.ts`

The change keeps the five-minute intent anti-replay window at initial admission,
reauthorizes later leases at the immutable reservation admission timestamp,
continues checking live capability revocation/expiry, reservation expiry, and
run-version drift, extends autonomous preparation reservations from 10 to 30
minutes, and exposes only strict privacy-safe adapter error codes.

## Verification already passed

- Focused worker unit tests: 9/9.
- Exact long-proof PostgreSQL regression: 1/1.
- Full PostgreSQL durability suite: 70/70.
- TypeScript: passed.
- Full application tests: 626 passed, 70 integration tests skipped there.
- ESLint: passed.
- Production build was started, but its final result was not captured before
  this pause; rerun it rather than assuming it passed.

## Resume sequence

1. Review `git diff` and rerun `npm run build`.
2. Run `npm run verify:status` and any Phase 5 gates affected by the worker.
3. Commit and push only the six implementation/test files plus this checkpoint.
4. Deploy the web/worker service; no Starknet contract redeployment is required.
5. Create a fresh prepared run and fresh short-lived capability, then have the
