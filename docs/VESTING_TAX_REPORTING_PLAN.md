# Hackathon vesting + tax plan

Status: local implementation, negative tests, real-proof composition, standalone
Devnet lifecycle evidence, Mainnet deployment/read-back, and hosted web/prover wiring
pass. The tiny live Mainnet canary remains pending explicit approval. Phase 5 agent
work remains paused at
`docs/PHASE5_AGENT_EXECUTION_CHECKPOINT.md`.

Evidence: `contracts/vesting_integration`, `evidence/vesting-tax-devnet.json`,
`evidence/vesting-tax-mainnet.json`, `evidence/vesting-tax-hosted-rollout.json`,
`lib/disclosure/payroll-book-report.test.ts`,
`lib/disclosure/tax-evidence.test.ts`, and
`lib/client/payroll-report-workflow.test.ts`. The Devnet lifecycle deliberately uses
a test-only public-input harness because the committed proof fixture is bound to a
fixed seal; the real v3 proof and production seal are composed separately in the
real-proof Cairo integration gate.

The immutable pre-deployment plan is recorded in
`evidence/vesting-tax-mainnet-plan.json`. Its 600.472824438987809664 STRK estimate was
a conservative historical simulation. The three declarations, atomic deployment and
registry activation later consumed exactly 227.876862512710972474 STRK. The deployed
class hashes, immutable wiring, active `0/3` profile, ordered real-proof acceptance and
reversed-shard rejection were read back in `evidence/vesting-tax-mainnet.json`.
No live canary transaction has been submitted.

Latest local audit: 718 executed application tests, 71/71 PostgreSQL tests, 4/4 Noir
tests, 16/16 VestingBook contract tests and 5/5 real verifier-to-seal integration
tests, Linux Chromium UI evidence, lint, typecheck,
and the production build all pass. The v3 circuit is 163,358 gates and its freshly
generated VK matches the published VK. The deployed source and later rollout-evidence
commit both passed clean-checkout hosted CI. Mainnet canary evidence remains pending.

## 1. One proof-bound state path

- Add Advanced v3 public commitments for vesting schedule ID, old state, new
  state, reporting period, and book entry.
- Prove immutable terms, cliff/linear accrual, exact unpaid delta, and sequence
  increment. A new state/book seal atomically consumes the old state, records the
  new state, and appends the finalized payroll entry; stale state and replay fail.
- Reuse STRK20, policy/obligation registries, and the generic bundle pattern.
  Deploy only the v3 verifier, its bundle, and the new seal.

## 2. Understandable private compliance

- Recipient exports a viewing-key-encrypted income statement; employer exports the
  complete period book; tax authority imports the fully disclosed encrypted book.
- The verifier recomputes every entry and the on-chain period accumulator, so an
  omitted, duplicated, or changed payroll fails. Render the same canonical facts
  as W-2/P60/T4-style reports without claiming official filing or legal advice.
- Preserve the exact policy pack and proved catalog root for every line; a changed
  revision, source, instruction or catalog member fails as policy substitution.

## 3. Demo and completion gate

- Team shows vested, released, available, and next release. Activity exports and
  verifies worker statements and the full tax book.
- Test cliff/mid/final release plus early, replay, stale-state, changed-amount,
  omitted-entry, wrong-key, and cross-tenant failures.
- Pass Noir, Cairo, database, API/UI, and Devnet E2E; then record one tiny Mainnet
  vesting release and one verified complete-book export before claiming complete.

## Mainnet release gate

- Active v3 verifier: `0x4b35d2d366848169ea4fb32d4fffda498b5251160da2e60fc53030a37d5551c`.
- Active v3 bundle: `0x1bc7517191802bf82ccfb60fa4f27f9306d6cfee9160b545d7dea662e8870a8`.
- Active VestingBook seal: `0x5208cc07cb4153235ab5c6ecd1936ee77f9be7a2ea09f6cc69518a6362493f`.
- Before the remaining canary mutation, rerun status/preflight checks and obtain
  explicit user approval immediately before submission.
- `vesting:mainnet:verify-canary -- <canary.json>` must verify the
  receipt, consumed release nullifier, exact next state, entry, count, and recomputed
  complete period accumulator.
