# Hackathon vesting + tax plan

Status: local implementation, negative tests, real-proof composition, standalone
Devnet lifecycle evidence, and read-only Mainnet planning/fee simulation pass.
Mainnet declaration, deployment, activation, and the tiny live canary remain pending
explicit approval. Phase 5 agent work remains paused at
`docs/PHASE5_AGENT_EXECUTION_CHECKPOINT.md`.

Evidence: `contracts/vesting_integration`, `evidence/vesting-tax-devnet.json`,
`lib/disclosure/payroll-book-report.test.ts`,
`lib/disclosure/tax-evidence.test.ts`, and
`lib/client/payroll-report-workflow.test.ts`. The Devnet lifecycle deliberately uses
a test-only public-input harness because the committed proof fixture is bound to a
fixed seal; the real v3 proof and production seal are composed separately in the
real-proof Cairo integration gate.

The deterministic Mainnet plan and current simulation are recorded in
`evidence/vesting-tax-mainnet-plan.json`. At 2026-09-05T04:55:06Z the three planned
classes and contracts were absent, profile `0/3` was inactive, the estimated total
was 600.472824438987809664 STRK, and the reviewed deployer held
505.966086733170101951 STRK.
The current plan is therefore not yet fully funded.
The plan records `mutationSubmitted: false`; no declaration, deployment, activation,
or canary transaction has been submitted.

Latest local audit: 718 executed application tests, 71/71 PostgreSQL tests, 4/4 Noir
tests, 16/16 VestingBook contract tests and 5/5 real verifier-to-seal integration
tests, Linux Chromium UI evidence, lint, typecheck,
and the production build all pass. The v3 circuit is 163,358 gates and its freshly
generated VK matches the published VK. Hosted CI and Mainnet canary evidence remain
pending.

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

- Planned v3 verifier: `0x4b35d2d366848169ea4fb32d4fffda498b5251160da2e60fc53030a37d5551c`.
- Planned v3 bundle: `0x1bc7517191802bf82ccfb60fa4f27f9306d6cfee9160b545d7dea662e8870a8`.
- Planned VestingBook seal: `0x5208cc07cb4153235ab5c6ecd1936ee77f9be7a2ea09f6cc69518a6362493f`.
- Before any mutation, rerun `vesting:mainnet:plan`, `vesting:mainnet:status`, and
  `vesting:mainnet:estimate`; obtain explicit user approval for each mutation stage.
- After activation, `vesting:mainnet:verify` must read back class hashes, immutable
  wiring, registry profile `0/3`, the ordered real proof pair, and reversed-shard
  rejection. `vesting:mainnet:verify-canary -- <canary.json>` must then verify the
  receipt, consumed release nullifier, exact next state, entry, count, and recomputed
  complete period accumulator.
