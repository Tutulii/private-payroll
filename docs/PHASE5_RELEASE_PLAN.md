# Phase 5 compact production plan

Status: active. `README.md`, `MASTER_PLAN.md`, `architecture.md`,
`docs/implementation-status.json`, and `docs/POLICY_ACCOUNT_RUNBOOK.md` remain
normative; this file only orders the release work.

## P5-A — Isolated-signer cutover

1. Keep autonomous dispatch disabled while the signer is absent or unattested.
2. Build the signer, bind it to Fly private IPv6 only, and pass HMAC replay,
   restricted-method, malformed-request, key-mismatch, and startup-attestation tests.
3. Generate distinct owner and treasury-viewing keys without logging or committing
   them; make an offline owner recovery copy before any rotation.
4. Create the private signer app and place the owner key, RPC, HMAC secret, and
   viewing **public** key only there. Put the signer URL, HMAC secret, expected owner
   public key, and viewing **private** key only in the web/worker secret store.
5. Simulate, explicitly approve, submit, and read back treasury registration and
   owner rotation. Fund the policy account with only its reviewed public gas budget.
6. Verify chain, class hash, owner, pool, viewing registration, unpaused state,
   signer health, and negative requests at one pinned Mainnet block before enabling
   the executor.

## P5-B — Bounded autonomous canary

1. Create one short-lived, one-call capability for one exact proven payroll run.
2. Simulate policy configuration and settlement before either Mainnet mutation.
3. Execute a deliberately small agent payroll and retain its request commitment,
   policy read-back, STRK20 transaction, PAYO proof/finality receipt, exact private
   balance delta, SettlementMatch `FINALIZE`, and reconciliation evidence.
4. Revoke or expire the canary policy and verify replay rejection. Human Ready
   approval remains the default and recovery path.

## P5-C — Mainnet demonstration evidence

Record and RPC-verify at least three successful transactions touching the live
STRK20 pool and PAYO contracts: human STRK, human native USDC, and one advanced
obligation or autonomous-agent flow. Link hashes, roots, contract calls, state
transitions, gas/proof benchmarks, and privacy-safe balance effects.

## P5-D — Public release gate

Complete `strk20.json`, contract/class/verifier tables, demo URL, three-minute
video, and deployment, administration, recovery, incident-response, security,
privacy-leakage, legal-boundary, and known-limitations documentation. From a clean
clone, pass every ordinary and proof CI gate, dependency review, Mainnet evidence
validator, `npm run verify:status`, and finally `npm run verify:completion`. Phase 5
is complete only when all 31 roadmap and all 16 architecture entries have linked
evidence and the public release artifacts exist.
