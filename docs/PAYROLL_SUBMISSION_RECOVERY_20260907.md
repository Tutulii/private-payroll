# Payroll submission recovery — 2026-09-07

## Incident and root cause

The affected vesting payroll transaction was
`0x06aea439656addfd17b315879696f0ace3880d9878ec01221033ee367d0deaf1`.
A direct Starknet Mainnet read confirms that it succeeded in block `14461163`
(`2026-09-06T15:49:42Z`) and emitted `PayrollBookEntryAppended` from the v3
`VestingBookSeal` at
`0x05208cc07cb4153235ab5c6ecd1936ee77f9be7a2ea09f6cc69518a6362493f`.
The receiver was paid. The missing state was PAYO's durable record of the
transaction hash.

Three failures combined:

1. Ready completed the private transaction but did not resolve
   `wallet_strk20InvokeTransaction` with its transaction hash before the browser
   timed out. The official Wallet API defines a successful result as
   `{ transaction_hash }` and warns that STRK20 invocation can be long-running
   because the wallet handles private proving and submission.
2. PAYO's historical indexer cursor had passed block `14461163` while its route
   still watched only the legacy seal. Support for the v3 book-seal address was
   added to that route later in commit `ffdd3a178c4f7eb1ca5f96e62e0a677264934344`.
   Adding the address did not rewind the already-advanced cursor, so the exact
   v3 event remained absent from `indexed_chain_events`.
3. Manual reconciliation refreshed the private balance by default. That caused
   a second Ready permission request after the user supplied the hash.

This was a confirmation/indexing failure after a successful payment. It was not
an unsuccessful transfer or a second asset deduction.

## Implemented recovery path

PAYO now treats only Wallet API errors that prove non-submission as final:
explicit refusal, invalid payload, unsupported network or API, unregistered
account, insufficient private balance, and privacy-leak rejection. A timeout,
transport loss, generic `UNKNOWN_ERROR` (`163`), or malformed post-submit result
is ambiguous. PAYO keeps the one-payment lock and polls the durable settlement;
it never opens another Ready transaction from that recovery loop.

Every indexer pass now performs a cursorless scan over a bounded finalized-chain
tail for all configured PAYO seal addresses and recovery selectors. The scan:

- derives its window from the current finalized head, independently of the
  historical cursor;
- queries all matching selectors and filters configured seal addresses locally;
- preserves the historical indexer's block-local event identity;
- atomically marks the prior window non-canonical and upserts the current
  canonical events under a PostgreSQL advisory lock;
- runs after historical catch-up/reorg handling, so a rollback cannot erase its
  result; and
- still runs and attempts exact submission recovery when historical indexing
  fails, while reporting that historical failure to worker monitoring.

The recovery repository records a transaction only when one canonical seal
event uniquely matches one pending settlement's proof-bound owner, period, and
entry commitment. Ambiguous matches fail closed. Transaction hashes are
canonicalized as Starknet felts, so Ready's padded form (`0x06…`) and the RPC's
unpadded form (`0x6…`) remain idempotently equivalent.

After canonical recovery, the browser immediately releases the one-payment lock
and renders the recovered transaction. Payroll, wage-claim, and remediation
confirmation no longer issue an automatic private-balance request. A user may
refresh balances explicitly later. If the entire recovery window expires and
Ready truly submitted nothing, the explicit cancel action now releases the
browser lock after the backend cancels the unsigned approval.

`PAYO_RECOVERY_INDEX_LOOKBACK_BLOCKS` controls the bounded scan and defaults to
`512`. The production worker invokes the indexer every ten seconds and the
configured finality lag remains two blocks. Normal Ready responses still record
immediately; timeout recovery completes after the event enters the finalized
window and the next worker/browser polling passes.

## Verification completed locally

- The new scanner read block `14461163` from Mainnet and returned exactly the
  affected transaction, v3 seal address, and `PayrollBookEntryAppended`
  selector without a manual hash.
- The internal indexer route ran end to end against a disposable migrated
  PostgreSQL database and live Mainnet RPC. It indexed 20 historical blocks and
  replaced a 32-block recovery window successfully.
- Focused wallet, payroll orchestration, tail-indexer, and reorg tests passed.
- Full Vitest suite: 805 passed; 75 database tests passed separately.
- TypeScript, ESLint, optimized Next.js production build, diff validation, and
  the repository status validator passed.
- Chromium rendered the actual recovery UI at 1280×900 and 390×844. Both tests
  opened manual hash recovery and verified the card, input, and all controls had
  no horizontal overflow.

The code has not been deployed as part of this investigation. A post-deployment
Ready timeout canary is still required before claiming live production
verification. The fallback cannot force Ready itself to return sooner; it makes
PAYO independent of that response once Mainnet contains the uniquely bound
canonical event.

## Primary references

- Starknet Wallet API method contract and long-running STRK20 note:
  https://github.com/starknet-io/types-js/blob/main/src/wallet-api/methods.ts
- Starknet Wallet API error codes:
  https://github.com/starknet-io/types-js/blob/main/src/wallet-api/errors.ts
- Official STRK20 Wallet API flow:
  https://strk20-by-example.org/starknet-wallet-api/private-defi
- Starknet JSON-RPC receipt/event source of truth:
  https://github.com/starkware-libs/starknet-specs/blob/master/api/starknet_api_openrpc.json
- Starknet privacy architecture and on-chain discovery:
  https://github.com/starkware-libs/starknet-privacy
