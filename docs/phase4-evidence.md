# Phase 4 evidence — human and AI-agent payroll

Phase 4 is implemented for human-approved MCP requests and narrowly bounded
direct-Privacy-SDK execution. This record distinguishes implementation and
Devnet evidence from the Mainnet demonstration work reserved for Phase 5.

## Requirement audit

| Block | Integrated result | Primary evidence |
|---|---|---|
| P4-01 | Encrypted, expiring capabilities are tenant/principal bound and enforce action, token, recipient, purpose, payment, period, time, nonce, call-count and approval limits transactionally. Ready approval remains the default. | `lib/domain/capability.ts`, `lib/server/capability-policy-crypto.ts`, `lib/persistence/capability-reservations.ts`, `lib/persistence/database.integration.test.ts` |
| P4-02 | A dedicated SNIP-6/SNIP-9 account enforces the exact policy, pool, seal, token, recipient/run commitments, periods, validity, nonces and call counts. Rotation, pause, recovery and revocation are implemented. | `contracts/src/policy_account.cairo`, `contracts/tests/test_policy_account*.cairo`, `evidence/phase4-policy-account-devnet.json`, `docs/POLICY_ACCOUNT_RUNBOOK.md` |
| P4-03 | The gateway accepts only versioned `PaymentIntent` records, reloads authoritative state, reserves limits, rebuilds actions, proves, simulates, signs through an isolated owner signer, submits and recovers idempotently. Arbitrary hashes, calls, calldata, targets, proofs and signer methods are absent from the MCP surface and rejected by the signer boundary. | `lib/server/agent-execution-worker.ts`, `lib/server/direct-privacy-agent-driver.ts`, `lib/server/policy-owner-signer-*`, `lib/starknet/direct-privacy-*.ts`, `Dockerfile.policy-signer` |
| P4-04 | Direct Privacy SDK accounts use encrypted spend/viewing material, one treasury lease, pinned discovery, channel setup, fee simulation, submission recovery and private history. SettlementMatch v8 binds emitted notes to the approved manifest and finalizes only direct-SDK runs; Ready runs remain `confirmed`. | `lib/server/direct-privacy-*.ts`, `circuits/settlement_match`, `contracts/settlement_verifier_v8`, `lib/proof/server-prover.ts`, `evidence/phase4-private-payroll-devnet.json` |
| P4-05 | All eight MCP tools use production APIs. Team and Activity render approval, capability/revocation, one-run autonomy, limits, direct-account state and redacted audit history behind normal tenant controls. | `packages/mcp/src/payo-server.ts`, `app/team/page.tsx`, `app/activity/page.tsx`, `tests/browser/phase4-agent-controls.spec.ts`, `evidence/phase4-rendered-browser-ui-origin.json` |

## Real private-settlement evidence

On 2026-09-01, the deterministic Phase 4 harness deployed a fresh eight-contract
Devnet topology and completed one bounded private STRK payroll through the pinned
Privacy SDK and the hosted self-managed prover. The run produced and locally
verified a real UltraKeccakZKHonk SettlementMatch proof in 143,281 ms, submitted
it to the generated Starknet verifier, executed the private payment and PAYO
`FINALIZE` atomically, rediscovered the recipient note, and rejected a replay.

The committed evidence records:

- two PayrollIntegrity shard verifications before payment;
- exact extracted SDK ciphertext and SettlementMatch public bindings;
- circuit hash `0xa208f7c548a5205e9e777f4926e282510e918bee4ce7902db3bb8b2d46454033`;
- verification-key hash `0x4dba54029e3b3b507baad28f6f4f416b9eca9651f98cbad9312d91a637528e23`;
- atomic private transaction/finalization `0x9796b90a7edd2a9692b3153aea17c9de6c1baf564b426fa9222b74fa7e8604`;
- recipient balance movement from `1` to `1000000000000001` atomic STRK, an exact `1000000000000000` delta;
- a proof-bound settlement receipt, `FINALIZED` seal, and rejected replay.

Run `npm run phase4:verify-evidence` to bind the evidence to the committed circuit,
verification key, topology, balance delta, browser controls and policy lifecycle.

## Verification gates

- TypeScript application: 120 files passed, 569 tests passed; 65 database-only
  tests are intentionally skipped by the ordinary suite.
- PostgreSQL: 65/65 concurrency, isolation, recovery, lease and replay tests.
- MCP: 5/5 transport/adversarial tests exercising all eight tools.
- Rendered Chromium: 1/1 Phase 4 production-page workflow with private metadata
  redaction; the evidence route is enabled only by `PAYO_BROWSER_EVIDENCE_MODE=1`.
- Cairo: 65/65 PAYO contract tests including four 256-run fuzz tests, plus the
  generated SettlementMatch verifier accepting its real proof fixture.
- Noir: 4/4 SettlementMatch tests, published-artifact equality, generated Poseidon
  constant equality, positive witness acceptance and ciphertext-tamper rejection.
- Web gates: typecheck, lint and optimized production build passed.
- Runtime: the hosted prover generated the real proof with pinned `bb`
  `3.0.0-nightly.20251104`; the native proof path has a 30-minute timeout,
  single-job queue and private temporary witness cleanup.

The main clean-clone workflow now runs the Phase 4 browser and evidence gates in
addition to the ordinary application, PostgreSQL, MCP, lint and build gates. The
proof-artifacts workflow reproduces the circuit, verification key, Garaga source,
real proof and generated Cairo verifier.

## Mainnet state and explicit limits

At Mainnet block 14,180,984, RPC read-back confirmed the deployed Phase 4
SettlementMatch verifier, Payroll Seal and policy-account class hashes and the
active proof-version-8 verifier profile. Their addresses are recorded in
`evidence/phase4-mainnet-deployment.json`. No redeployment is required for the
native-prover or product-wiring changes.

This Phase 4 result does **not** claim a Mainnet autonomous-agent payroll. That
small live canary, together with the human STRK/USDC demonstrations and public
release package, belongs to Phase 5 and requires explicit user approval. Devnet
runs with transaction-OS proof verification disabled because its synthetic proof
facts are not wire-compatible with the pinned audited pool; the PAYO
PayrollIntegrity and SettlementMatch proofs are real and verified onchain. The
separate official transaction-prover capacity record is
`evidence/phase4-transaction-prover-mainnet.json`.
