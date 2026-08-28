# Phase 3 implementation evidence

Updated: 2026-08-28

This file records what has been exercised, not what merely exists as source.
The rendered UI, encryption, proving, Devnet settlement, scoped disclosure, and
negative-rejection parts of the Phase 3 gate have now been exercised. The
transaction-safe merged-v2 verifier is declared, deployed, proof-read-back
verified, active on Mainnet, and wired into the live PAYO/Fly web and prover
services. Phase 3 is still **not complete** under the strict gate in
`MASTER_PLAN.md`: a fresh advanced payroll must complete through Ready, durable
finality, and receiver observation. Devnet's missing full transaction-proof
mode remains a separate limitation.

## Transaction-safe merged-v2 correction

An August 28 release audit found that the earlier advanced-v2 envelope joined a
base PayrollIntegrity proof to a separate AdvancedObligation proof. Its 6,339
raw felts could be read through RPC and exercised in Devnet, but could never be
submitted as a Starknet Mainnet invoke because the protocol limit is 5,000
calldata felts. The older deployment and receipts below remain valid historical
evidence of verifier behavior; they are not evidence of a transaction-viable
Mainnet v2 payroll.

The replacement `advanced_obligation` circuit is one merged proof system. It
retains all v1 policy, arithmetic, completeness, uniqueness, FX, classification,
final-pay, root, nullifier, deployment-binding, and shard-overlap constraints,
then proves the committed advanced plan in the same witness. The proof server
and browser worker now produce only this proof and reject any raw proof above
4,992 felts, reserving eight felts for invoke framing.

- Circuit SHA-256:
  `0x755bb9374c9cfc72cbd36b1a3e1d8c5e2792b11b8b08e190d2743dc508ebbe41`
- Proof-bound VK SHA-256:
  `0x50063de39c922bf1fe1089ff8b5e6839a56387da99e82e9071f067b9f72c90d7`
- Measured size per shard: 3,223 raw felts and 3,231 framed felts.
- Application-runtime proving: two self-verified generic shards in 696,368 ms;
  a second pair bound to `SN_MAIN` and the live tenant-aware seal self-verified
  in 664,475 ms and is committed under
  `evidence/phase3-mainnet-v2-fixtures/`.
- Circuit regression: 50/50 tests, including the inherited PayrollIntegrity
  failures plus advanced commitment, checkpoint, milestone, and offboarding
  rejection tests.
- Real Cairo integration: each direct Garaga proof passed the newly generated
  verifier, the single-verifier bundle, and `PayoPayrollSeal`; tampered proof
  paths remain rejected.
- Repository regression: 76 test files passed, 328 active tests passed, one
  file and 24 tests were intentionally skipped; typecheck and lint passed.

The guarded upgrade plan is separate from the historical deployment planner.
It verified the live tenant-aware seal `0x603c…6ac7`, policy registry
`0x3470…4477`, and tenant obligation registry `0x44b2…23b5`, then deployed
only the generated verifier and a generic single-verifier bundle. The registry
was not modified until both committed Mainnet-bound shards passed the deployed
verifier and deliberate calldata tampering was rejected.

- Declaration: `0x5eeb6853c70f575b88d6f7c47d9bbc5f497e0b7fe12f93fc0ae96e3fe0da038`;
  class `0xee7996f9fed69e8cb7248327c4391ca5847faa297926bf33592b7022520ba3`.
- Atomic verifier and bundle deployment:
  `0x741cec7856f28e3f93336c0e8bb90c1b0c25cf3f5ef3791e624e203cf496b8f`.
- Verifier `0x6845068feb530dbac0e730532df5fefb744c5caf4e1769e642bf1aec63ee043`;
  bundle `0xeba326f15f73968026bd12007220d88104fdcb322a56ad8c69fbe8a5350e18`.
- Registry activation: `0x5b60c1ed46ba781cbba0da6d1a9acecd226ebfe822ce2869be124564f555518`.
- Independent post-activation read-back passed at block 13,971,374. Exact
  artifacts, fees, class hashes, proof checks, and validity window are recorded
  in `evidence/phase3-v2-mainnet-upgrade.json`.

## Hosted v2 rollout evidence

The source containing the active bundle was rolled first to the isolated
32-GiB prover and then to the PAYO web service on Fly. The prover machine
reached Fly's good state and `/api/health` returned `ok`; the web release
database migration completed successfully, its machine reached good state,
and `/api/health` returned `ok`. `/payroll` returned HTTP 200.

The served payroll JavaScript was fetched independently after rollout and
contained both the expected prover origin
`https://private-payroll-prover.fly.dev` and active v2 bundle
`0xeba326f15f73968026bd12007220d88104fdcb322a56ad8c69fbe8a5350e18`.
The prover's browser preflight returned HTTP 204 with that PAYO origin as the
sole allowed origin, and an unauthenticated job read returned `AUTH_REQUIRED`,
showing that the endpoint is enabled but remains session protected. Commit
`b41401b` passed typecheck, tests, rendered production Phase 3 controls,
UI-to-proof evidence verification, lint, roadmap status verification, and the
production build in
[GitHub Actions run 33133713879](https://github.com/Tutulii/private-payroll/actions/runs/33133713879).

This proves deployment and runtime wiring, not the remaining Ready-signed
advanced payroll. That fresh private transaction, durable verifier finality,
and receiver balance observation remain the completion gate.

## Standalone Starknet Devnet evidence

`npm run phase3:devnet:check-artifacts` refuses missing or stale Sierra/CASM
artifacts across the base, advanced, claim, remediation, and PAYO contract
packages. A fresh deterministic Starknet Devnet 0.9.2 run then executed:

1. ten deployed contract instances: four Garaga verifiers, one advanced bundle,
   claim and remediation bundles, the policy registry, obligation registry, and
   payroll seal;
2. freshly generated v2, v3, and v4 proofs bound to `SN_SEPOLIA` and the actual
   deployed seal address;
3. immediate policy, FX, verifier, and obligation-root activation;
4. advanced status `2`, wage-claim status `4`, and linked remediation status
   `5`, each through seal plus ordered shard-0 and shard-1 transactions;
5. rejection of tampered proof calldata and nullifier replay for all three
   workflows.

The machine-readable deployment, class hashes, transaction hashes, proof
hashes, final statuses, and negative-check results are in:

- `evidence/phase3-devnet-deployment.json`
- `evidence/phase3-devnet.json`
- `evidence/phase3-matrix-devnet.json`
- `evidence/phase3-matrix-disclosure.json`
- `evidence/phase3-devnet-fixtures/`

Fresh proving benchmarks for this run were 672,722 ms for the linked advanced
v2 proof, 44,856 ms for wage claim v3, and 38,825 ms for remediation v4.

A second linked advanced-v2 matrix proof was generated from one encrypted
proof request and then submitted to the fresh standalone topology. Its seven
private agreement lines cover recurring, checkpoint stream, milestone, private
vesting, final pay, approved adjustment, and an employee statutory/FX/
classification line. The employee line proves 10,000,000 atomic native USDC
gross, the committed 22% reference-policy deduction, and a positive 7,800,000
atomic USD floor. Both ordered combined PayrollIntegrity + AdvancedObligation
shards were accepted by the real Garaga verifier and seal in Devnet blocks 25
and 26, producing final status `2`; calldata tampering and nullifier replay were
rejected. The current fixture uses the versioned six-fact rubric, derives the
employee score and threshold, and reuses its salted facts commitment as the
private agreement-leaf salt. Changing from the legacy score fixture changed the
agreement and manifest roots, proving that the rubric commitment is included in
the authoritative root. The four linked proof generations and local
self-verifications took 801,108 ms. Exact roots, proof-calldata hashes,
transaction hashes, coverage, and negative results are recorded in
`evidence/phase3-matrix-devnet.json`.

## Live Mainnet Pragma evidence

`npm run phase3:pragma:verify` now probes the production Mainnet contracts at a
single pinned block and writes `evidence/pragma-phase3-mainnet.json`. The fresh
2026-08-26 run passed at block `13902777`: STRK/USD had a six-decimal spot
median of `24808`, a 24-hour TWAP of `26473`, 12 aggregated sources, and a
195-second median age. PAYO selected the lower value, applied its one-percent
haircut, committed `24559`, and reconstructed the corresponding payroll FX
commitment. The same probe required USDC/USD protected lookup to fail with the
explicit `twap` unsupported component; ordinary USDC payroll still uses the
fresh median path. RPC credentials are not written to the evidence file.

Unit tests also pin median and TWAP calls to one block and reject stale,
under-sourced, malformed, and unsupported observations. The payroll execution
test proves that an unsupported protected pair stops before proof generation
or a Ready wallet request.

## Official STRK20 pool integration evidence

The official `starkware-libs/starknet-privacy` pool was built from
`PRIVACY-0.14.3-RC.0`; its computed and deployed class hash is
`0x052107fadffab71bdcbb6b2ccb68ba3e1b5558d94036538053e159d3076ad633`.
The integration uses the exact `PRIVACY-0.14.3-RC.2` SDK against Starknet
Devnet `0.8.0-rc.3` / RPC `0.10.2`. A preliminary pool probe registered a
recipient, deposited 100 atomic STRK units, privately transferred 40, and
independently rediscovered private balances of 60 for the sender and 40 for
the recipient.

PAYO was then redeployed with that official pool—not a test account—as the
seal's immutable pool caller. The integration read `get_pool()` back on-chain
and required exact equality before proving or settling. The current linked
matrix was rebuilt from encrypted records produced by the same production
agreement command used by the Team UI. Its deployment-bound composed proof
generated and locally verified in 680,302 ms. Transaction
`0x18160c08132dd95394e23341fb6f8137c17dabfe8ef00c9fe7eefe517651f3`
then performed seven distinct private STRK note outputs (one for each matrix
workflow) and the pool-to-PAYO `privacy_invoke` seal call atomically. Private
balance discovery changed from sender/recipient `50/50` to `43/57`.

The integrated builder already requested Privacy SDK `autoSetup` and refreshed
both notes and channels for that successful first-recipient transfer. The test
now additionally discovers the outgoing recipient channel and STRK token
subchannel after settlement and requires `SetupRequirement.Ready`. That new
explicit channel-readiness assertion is implemented in
`scripts/test-phase3-strk20-devnet.mjs`; it is not retroactively added to the
older committed receipt and remains pending a fresh official-pool Devnet rerun.

Real Garaga shard transactions
`0x776e271efd9a75c33589868c7aecb0ec029ac8ce0e305a819ade720e671fdaa`
and
`0x3f9a6986095c7066b7a72172a82d42586380a2af57d8e01db8057b88881f46b`
then advanced the proof-bound PAYO run from sealed status `1` to verified
status `2`. A real tampered-calldata transaction reverted without changing
shard state. A second pool-originated transaction using the same nullifier
also reverted, and rediscovery proved that the rejected replay did not move
private balances. Machine-readable receipts and limitations are in
`evidence/phase3-private-settlement-devnet.json`; run
`npm run phase3:strk20:verify-evidence` to check their internal consistency.

This is not full transaction-OS proof evidence. The pinned Devnet's
`proof-mode full` does not implement invoke proof verification, so the
official pool integration runs in `proof-mode none` with SDK-compiled proof
facts and records `fullTransactionProofVerification: false`. PAYO's composed
Noir/Garaga payroll proofs are real and verified on-chain, but that does not
permit the disabled STRK20 transaction-proof layer to be reported as complete.
Direct private output-to-manifest amount equality also remains the distinct
Phase 4 `SettlementMatch` requirement.

This limitation was retested on 2026-08-26 against Starknet Devnet `0.9.2`,
RPC `0.10.2`, with `--proof-mode full`, not inferred from the older pinned
node. The official pool class declaration succeeded, but the first deployment
invoke was rejected by Devnet with code `-1` and the exact message
`Proof verification in full mode not yet implemented`. The upstream Privacy
SDK compatibility matrix still pins Devnet `0.8.0-rc.3`; the later RC.5 SDK
release does not claim a full-mode Devnet replacement. `devnet` proof mode is
not substituted because Devnet documents it as a fake proof that it later
verifies, which cannot satisfy PAYO's no-mock completion rule.

The official-pool exception run uses newly generated v3/v4 proofs bound to the
same PAYO seal and one shared claim nullifier. Unlike the earlier generic
fixture, this run commits the actual recipient, token STRK, and a three-atomic-
unit shortfall so the observed private remediation uses the same recipient,
token, and amount. The proofs generated and locally verified in 35,494 ms for
the claim and 38,961 ms for remediation.

Private claimant transaction
`0x170d0a6f4cb2c2e390b1e7c5317a0b1f5fdcf4af714d48d7b97a581e1509971`
sealed the v3 claim without changing either party's private balance. Two real
Garaga shard receipts advanced PAYO to disputed status `4`. Private
remediation transaction
`0x33dbb8703a09fe632e9cde6edb23735994161bea25e13fe8018963e07888c34`
then transferred the committed three STRK units to the claimant and atomically
sealed v4. Its two real verifier shards advanced the shared-nullifier state to
reconciled status `5`; rediscovered private balances moved from `43/57` to
`40/60`. Claim tampering, remediation tampering, and a pool-originated
remediation replay were rejected without an extra balance movement. The exact
proof roots and all six accepted transaction receipts are in
`evidence/phase3-private-exceptions-devnet.json`; run
`npm run phase3:strk20:verify-exceptions` for the independent consistency
check. The same Devnet transaction-proof and Phase 4 SettlementMatch limits
described above still apply.

Every proved workflow line and the full matrix manifest were then rebuilt from
the same canonical witness. Seven separate worker packages each contain one
six-level line opening for recurring, checkpoint stream, milestone, private
vesting, final pay, approved adjustment, or statutory/FX/classification; every
opening reconstructs the on-chain manifest root. Employer, auditor, and tax
packages cover the full matrix with only their authorized fields. All ten
packages have balanced journals, were encrypted to distinct X25519 recipients,
and opened offline with the intended recipient key. Wrong recipients, expired
grants, and revoked grants were rejected independently for all ten packages.
Recipient private keys were not persisted. Package commitments, public
recipient keys, field/file scopes, workflow line indices, and negative results
are in `evidence/phase3-matrix-disclosure.json`; the encrypted archive envelopes
are under `evidence/phase3-devnet-fixtures/`.

The same committed real proof fixtures also pass
`contracts/phase3_integration/tests/phase3_real_proofs.cairo` under Starknet
Foundry. That test is supporting evidence; it is not substituted for the
standalone Devnet transactions above.

## Production UI-command traceability

The Team page and the Phase 3 evidence generator both invoke
`storeEncryptedAgreementFromForm`; there is no second test-only agreement
builder. `evidence/phase3-devnet-fixtures/advanced-matrix-ui-origin.json`
records all seven form drafts, their form-input commitments, the resulting v2
agreement records, and their authenticated encrypted envelopes. Exact decrypt
round trips pass and private form values are absent from the serialized
ciphertext envelopes. The linked matrix generator consumes those encrypted
records rather than a parallel hand-authored agreement list.

The Activity page and the exception evidence generator likewise share
`createEncryptedWageClaimDraft` and `createEncryptedRemediationDraft`.
`evidence/phase3-devnet-fixtures/claim-remediation-ui-origin.json` binds those
commands and their encrypted records to the v3 claim and v4 remediation proof
inputs. `npm run phase3:ui:verify-evidence` independently reconstructs the
agreement, recipient, schedule, manifest, policy, FX, nullifier, proof-calldata,
and official-pool receipt links. `npm run phase3:strk20:verify-exceptions`
performs the equivalent cross-check for the claim and remediation path.

Linux Chromium now also exercises the rendered production controls rather than
calling those commands directly. The test renders the exact `TeamPage` and
`ActivityPage` components, clicks `Encrypt contributor`, creates all seven
advanced agreement variants through `Encrypt proof-bound agreement`, drafts a
private claim through `Encrypt claim draft`, and drafts its linked remediation
through `Encrypt remediation draft`. It checks authenticated encryption round
trips, the statutory/FX/classification fields, workflow coverage, claim-to-
remediation linkage, and the absence of private earnings values from serialized
ciphertext. The green run and downloadable browser-origin artifact are at
[GitHub Actions run 32973338048](https://github.com/Tutulii/private-payroll/actions/runs/32973338048).

The browser harness replaces only authentication, vault persistence, and run
fixtures with a synthetic in-memory adapter. It does not replace the production
Team or Activity controls, record builders, schemas, or encryption functions.
The harness route requires both a non-production Next.js runtime and the
server-only `PAYO_BROWSER_EVIDENCE_MODE=1` flag. A production server smoke test
returned `200` for `/team` and `404` for `/payo-browser-evidence/team`, so the
synthetic principal and adapter are not an exposed production test route.

## Integrated application work

- The encrypted Team UI creates checkpoint streams, milestones, private
  vesting releases, final pay, and approved adjustment obligations. Exact
  checkpoint and vesting entitlements are derived, not browser-entered.
- Recurring agreement creation now uses the advanced v2 record as well, and
  permits a worker-selected six-decimal USD value floor. The visible Mainnet
  profile offers this only for STRK and binds it to a 24-hour Pragma TWAP plus
  a 15-minute median freshness limit. Legacy v1 agreements remain readable.
- Encrypted agreement revisions now register opaque durable schedules. The
  PostgreSQL migration stores no plan kind, token, recipient, or amount; a
  15-second worker materializes due commitments, Payroll decrypts and rechecks
  them locally, and Ready approval remains mandatory. The isolated PostgreSQL
  suite passed concurrent registration, replay, conflict rejection, revision
  supersession, and due materialization.
- Final-pay entry accepts explicit zero values for optional leave, notice,
  severance, adjustment, and deduction components while still requiring
  positive ordinary pay. This fixes the rendered form's previous rejection of
  its own safe zero defaults.
- Payroll selection keeps v1/v2 verifier profiles and distinct policy-catalog
  roots in separate fail-closed cohorts.
- Human agreement creation now collects six versioned factual classification
  signals, derives the score locally, rejects a treatment/score mismatch, and
  encrypts the complete assessment. Its salted facts commitment is reused as
  the private agreement-leaf salt, binding the assessment commitment into the
  authoritative proved agreement root. This remains a consistency screen, not
  a legal-status determination.
- The narrow `StatutoryCorrect` execution profile supports US employee,
  separately identified supplemental wages settled in USDC. The installed
  source-pinned policy derives the 22% withholding, the circuit proves it, and
  the wallet receives only net settlement. The UI explicitly says this is not
  a general tax engine or legal advice.
- STRK FX-protected payroll fetches Pragma spot median and a 24-hour TWAP at one
  pinned block, chooses the lower value, applies a conservative haircut,
  commits provenance, and exposes explicit unsupported-pair errors. USDC
  payroll remains supported without an FXFloor.
- Wage claim and remediation records, proof requests, settlement intents,
  relayer jobs, and lifecycle transitions are encrypted and durable. A claim
  becomes disputed only after v3 verification; remediation becomes reconciled
  only after linked v4 verification.
- The scoped-disclosure UI now selects any finalized payroll, wage-claim, or
  remediation settlement. For proof versions 3 and 4 it decrypts the authorized
  subject locally, reconstructs the exact claim or remediation manifest and
  nullifier from the original encrypted payroll witness, checks both on-chain
  verifier shards, creates a workflow-specific balanced journal and Merkle
  opening, and encrypts the exception fields only to the selected recipient.
- Recipient-encrypted proof packages support worker, employer, auditor, and tax
  scopes, balanced journals, worker Merkle openings, expiry, revocation, and
  offline verification.

## Passing gates

- 76 unit-test files passed, one skipped; 328 tests passed and 24 were skipped.
- Fresh pinned Noir runs passed PayrollIntegrity 45/45, merged advanced-v2
  50/50, WageClaim 5/5, and WageRemediation 5/5.
- PostgreSQL durability integration: 20/20 passed, including the opaque
  recurring scheduler's concurrency and revision lifecycle.
- TypeScript typecheck passed.
- ESLint passed with no project warnings after cleanup.
- The optimized Next.js production build passed with a 2 GB Node heap. The
  remaining webpack notices originate in optional Privy/viem dependency paths.
- Fresh Scarb builds passed for all Phase 3 packages.
- Fresh Starknet Foundry real-proof integration: 1/1 passed, exercising the
  committed advanced, claim, and remediation proof calldata and state changes.
- Standalone Devnet v2/v3/v4 verification passed.
- Standalone seven-workflow advanced-v2 matrix verification passed, including
  positive statutory and FX constraints plus tamper and replay rejection.
- Official STRK20 pool integration passed for seven distinct workflow outputs,
  an atomic pool-to-PAYO seal call, two real Garaga shard receipts, terminal
  status `2`, tamper rejection, pool-originated replay rejection, and private
  pre/post/replay balance discovery.
- The machine validator for `evidence/phase3-private-settlement-devnet.json`
  passed while preserving the explicit Devnet proof-mode and Phase 4 limits.
- The UI-origin matrix validator passed for seven production-command encrypted
  records, both real proof-calldata shards, the official-pool settlement, and
  tamper/replay rejection. The equivalent claim/remediation origin validator
  also passed.
- Linux Chromium clicked the exact rendered Team and Activity production
  controls for seven advanced agreements plus wage claim and remediation,
  validated encrypted round trips and private-field absence, and uploaded the
  browser-origin artifact in
  [CI run 32973338048](https://github.com/Tutulii/private-payroll/actions/runs/32973338048).
- The full proof-artifact workflow rebuilt the merged-v2 circuit, enforced its
  2^21 domain and Mainnet calldata budgets, reproduced its exact verification
  key and Garaga verifier, regenerated and self-verified the linked base proofs,
  passed fresh real-Cairo and standalone RPC Devnet integrations, and generated
  both base proofs in a Chromium Web Worker in
  [run 33130871328](https://github.com/Tutulii/private-payroll/actions/runs/33130871328).
- Official-pool v3 claim and exact-recipient/token/amount v4 private
  remediation passed with statuses `4` and `5`, real Garaga shard receipts,
  tamper and replay rejection, and private balance rediscovery; its separate
  machine validator passed.
- Seven workflow-specific worker packages plus employer, auditor, and tax
  packages derived from the recorded matrix were independently recipient-
  encrypted and opened offline, with wrong-key, expiry, and revocation
  rejection for every package.

## Remaining completion blockers

This is why Phase 3 is not reported as complete:

- The seven advanced matrix workflows now have official-pool private-value
  movements tied atomically to PAYO proof enforcement, but Devnet does not
  implement full transaction-proof verification. Running the pool with that
  proof layer disabled is partial evidence under the strict no-mock/no-disabled
  completion rule.
- The transaction-safe merged-v2 verifier is active and independently
  proof-read-back verified on Mainnet. PAYO/Fly still must be rolled to the new
  bundle and a fresh advanced payroll must reach Ready confirmation, durable
  finality, both on-chain verifier shards, terminal UI state, and receiver-side
  private balance observation.
- Phase 5 still separately requires the final public Mainnet demonstration set,
  release metadata, and video; none of those release claims are inferred here.
