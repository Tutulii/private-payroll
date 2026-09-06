# Hackathon vesting + tax plan

Status: **completed for the defined vesting and complete-payroll-book scope on
Starknet Mainnet.** Local negative tests, real-proof composition, standalone Devnet
lifecycle evidence, deterministic Mainnet deployment/read-back, hosted web/prover
wiring, one approved live vesting release, worker-statement generation and
tax-reviewer disclosure have passed. Private-exit and autonomous-agent Mainnet
canaries remain separate Phase 5 work.

Evidence: `contracts/vesting_integration`,
`evidence/vesting-tax-devnet.json`,
`evidence/vesting-tax-mainnet-plan.json`,
`evidence/vesting-tax-mainnet.json`,
`evidence/vesting-tax-mainnet-canary-2026-09-06.json`,
`evidence/vesting-tax-hosted-rollout.json`,
`lib/disclosure/payroll-book-report.test.ts`,
`lib/disclosure/tax-evidence.test.ts`, and
`lib/client/payroll-report-workflow.test.ts`. Recipient-encrypted worker and
tax-reviewer files remain private and are not committed as public evidence.

The immutable pre-deployment plan estimated 600.472824438987809664 STRK
conservatively. The three declarations, atomic deployment and registry activation
consumed exactly 227.876862512710972474 STRK. Their class hashes, immutable wiring,
active `0/3` profile, ordered real-proof acceptance and reversed-shard rejection
were read back on Mainnet.

On 2026-09-06, the explicitly approved vesting canary succeeded in transaction
`0x06aea439656addfd17b315879696f0ace3880d9878ec01221033ee367d0deaf1`
at block `14461163`. Independent read-back confirmed the exact next vesting state,
consumed release nullifier, book entry commitment at index 2 of 3 and recomputed
complete-book accumulator root
`0x7939168b2e65494379eec64d0885403ee78d4a5170f365cd15d2234f120a0b1`.

The initial Ready callback did not persist the transaction hash automatically, so
that canary was recovered through the manual hash path. Commit `ffdd3a1` fixes the
production recovery path: the indexer watches both seal contracts, matches the exact
universal-book entry, recognizes completed `vesting_book_v3` authorization, and
advances the encrypted vesting agreement by gross entitlement. The focused recovery
suite, full pre-deployment regression, typecheck and production build passed, and
the corrected bundle is live on Fly. A second paid canary has not been used to
re-exercise this operational recovery path.

Latest release audit: 763 application tests, 72 PostgreSQL integration tests, 4 Noir
tests, 16 VestingBook contract tests and 5 real verifier-to-seal integration tests
passed, together with Linux Chromium UI evidence, lint, typecheck and production
build. The v3 circuit is 163,358 gates and its generated verification key matches the
published key.

## 1. One proof-bound state path — complete

- Advanced v3 public commitments bind the vesting schedule ID, previous and next
  state, reporting period and payroll-book entry.
- The proof enforces immutable terms, cliff/linear accrual, exact unpaid delta and
  release-sequence increment.
- The VestingBook seal atomically consumes the release nullifier, advances state and
  appends one finalized entry; early, replayed, changed and stale-state attempts fail.
- STRK20, policy/obligation registries and the existing verifier-bundle pattern are
  reused. Only the v3 verifier, ordered bundle and VestingBook seal were added.

## 2. Understandable private compliance — complete

- Workers receive recipient-encrypted statement sources and generate their final
  income statement locally.
- Employers and tax reviewers receive separately authorized complete-period books.
  The verifier rebuilds every entry and the independently read on-chain accumulator;
  omission, duplication or mutation fails.
- The same canonical evidence renders W-2-, P60- and T4-style views without claiming
  official filing, certification or legal advice.
- Every line preserves its exact proved policy pack and catalog root; changed policy
  source, revision, instruction or catalog membership fails closed.

## 3. Demo and completion gate — passed

- Team displays vested, released, available and next-release state.
- Activity created and reopened a worker-controlled statement and a tax-reviewer
  complete-book disclosure against the live book. The encrypted outputs are
  intentionally not public repository artifacts.
- Noir, Cairo, TypeScript, PostgreSQL, API/UI, Devnet, hosted configuration and
  Mainnet topology/read-back gates passed.
- The live vesting release and its three-entry complete payroll book are recorded in
  public, downloadable JSON evidence.

## Mainnet release identity

- Chain ID: `0x534e5f4d41494e` (self-decodes to `SN_MAIN`).
- Active v3 verifier:
  `0x4b35d2d366848169ea4fb32d4fffda498b5251160da2e60fc53030a37d5551c`.
- Active v3 bundle:
  `0x1bc7517191802bf82ccfb60fa4f27f9306d6cfee9160b545d7dea662e8870a8`.
- Active VestingBook seal:
  `0x5208cc07cb4153235ab5c6ecd1936ee77f9be7a2ea09f6cc69518a6362493f`.
- Full deployment and canary evidence:
  `evidence/vesting-tax-mainnet.json`.
- Compact canary evidence:
  `evidence/vesting-tax-mainnet-canary-2026-09-06.json`.
- Reproducible verifier command:
  `npm run vesting:mainnet:verify-canary -- <canary.json>`.
