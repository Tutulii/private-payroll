# Phase 3 implementation evidence

Updated: 2026-08-26

This file records what has been exercised, not what merely exists as source.
Phase 3 is **not complete** under the gate in `MASTER_PLAN.md`: every workflow
must be created in the UI, encrypted, proved, settled against Devnet, disclosed
to its intended recipient, and tested for negative rejection.

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

This is production-command traceability, not a claim that a browser automation
clicked every rendered control. That remaining distinction is preserved in the
completion blockers below.

## Integrated application work

- The encrypted Team UI creates checkpoint streams, milestones, private
  vesting releases, final pay, and approved adjustment obligations. Exact
  checkpoint and vesting entitlements are derived, not browser-entered.
- Recurring agreement creation now uses the advanced v2 record as well, and
  permits a worker-selected six-decimal USD value floor with a committed
  five-minute freshness limit. Legacy v1 agreements remain readable.
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
- Advanced payroll fetches Pragma spot median and TWAP at one pinned block,
  chooses the lower value, applies a conservative haircut, commits provenance,
  and exposes explicit unsupported-pair errors.
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

- 64 unit-test files passed, one skipped; 251 tests passed and 19 were skipped.
- Fresh pinned Noir runs passed all 60 relevant tests: PayrollIntegrity 45/45,
  AdvancedObligation 5/5, WageClaim 5/5, and WageRemediation 5/5.
- PostgreSQL durability integration: 19/19 passed.
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
- Official-pool v3 claim and exact-recipient/token/amount v4 private
  remediation passed with statuses `4` and `5`, real Garaga shard receipts,
  tamper and replay rejection, and private balance rediscovery; its separate
  machine validator passed.
- Seven workflow-specific worker packages plus employer, auditor, and tax
  packages derived from the recorded matrix were independently recipient-
  encrypted and opened offline, with wrong-key, expiry, and revocation
  rejection for every package.

## Remaining completion blockers

These are the reasons Phase 3 is not reported as complete:

- The seven advanced matrix workflows now have official-pool private-value
  movements tied atomically to PAYO proof enforcement, but Devnet does not
  implement full transaction-proof verification. Running the pool with that
  proof layer disabled is partial evidence under the strict no-mock/no-disabled
  completion rule.
- Every workflow now has reproducible production-command traceability from form
  data through encryption, proving, official-pool settlement, intended-scope
  disclosure, and negative rejection. The strict gate still requires a
  browser-driven authenticated run that exercises the rendered controls; the
  synthetic command fixture is deliberately not mislabeled as that browser
  event evidence.

Mainnet deployment and demonstrations belong to Phase 5 and are not counted as
Phase 3 completion evidence.
