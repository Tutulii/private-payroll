# PAYO Mainnet release and operations runbook

Status: Phase 5 release procedure. This is not an audit or a completion claim.
The exact policy-account administration rules in `POLICY_ACCOUNT_RUNBOOK.md`
remain mandatory.

## Release invariants

- Keep `PAYO_AGENT_EXECUTOR_ENABLED=false` until the isolated signer, treasury
  registration, owner rotation, one-run policy and autonomous canary have all
  passed pinned Mainnet read-back.
- Every Mainnet mutation needs a fresh simulation, an exact human approval and a
  final receipt/read-back. Never substitute an earlier estimate.
- Never place an owner, viewing, Ready, vault, recipient or salary secret in Git,
  logs, screenshots, evidence JSON, the MCP process or a public Fly application.
- Human Ready approval remains the default and recovery path. An autonomous
  capability is narrow, expiring, revocable and limited to committed runs.
- A private transaction receipt proves contract execution, not plaintext salary,
  token or recipient. Publish only commitments and privacy-safe balance effects.

## Production topology

| Service | Exposure | Holds | Must not hold |
|---|---|---|---|
| `private-payroll` | Public HTTPS | encrypted database keys, relayer key, treasury viewing key, signer HMAC/public key | policy-owner key, Ready keys, plaintext payroll |
| `private-payroll-prover` | authenticated service | temporary witness during one proof job | account, owner, viewing or vault keys |
| `payo-privacy-discovery` | service network | public pool index | viewing/private keys |
| `payo-transaction-prover` | service network | transaction-OS proving state | PAYO owner or viewing keys |
| `payo-policy-signer` | Fly private 6PN only | policy-owner key, signer HMAC, viewing **public** key | viewing private key, vault key, arbitrary-call API |
| MCP client/server | user-controlled transport | scoped capability/access token | owner/viewing/Ready private keys |

The signer has no `http_service` or public Fly proxy. It binds to IPv6 `::` so
only sibling applications can reach `payo-policy-signer.internal` over Fly 6PN.

## Secret placement

| Variable | Signer | Web/worker | Offline only |
|---|:---:|:---:|:---:|
| `PAYO_POLICY_OWNER_PRIVATE_KEY` | yes | never | recovery copy |
| `PAYO_POLICY_SIGNER_SECRET` | yes | yes | optional sealed copy |
| `PAYO_POLICY_SIGNER_PUBLIC_KEY` | derived/attested | yes | public |
| `PAYO_AGENT_POLICY_VIEWING_PUBLIC_KEY` | yes | optional | public |
| `PAYO_AGENT_POLICY_VIEWING_KEY` | never | yes | recovery copy |
| `PAYO_PROOF_RELAYER_PRIVATE_KEY` | never | yes | recovery copy |
| vault/recovery/Ready secrets | never | never | user-controlled only |

Rotate immediately if a secret appears in a command argument, log, screenshot,
Git object, support ticket or public artifact. Fly secrets must be provided by
stdin or a protected environment file and checked by name only afterward.

## Preflight

1. Stop autonomous workers and confirm the source and hosted environment both
   report `PAYO_AGENT_EXECUTOR_ENABLED=false`.
2. From the exact release commit, run:

   ```bash
   npm ci
   npm run audit:production
   npm run typecheck
   npm test
   npm run test:mcp
   npm run lint
   npm run build
   npm run phase4:verify-evidence
   npm run verify:payo-strk
   npm run verify:payo-usdc
   npm run verify:payo-mixed
   npm run verify:status
   ```

3. Confirm the policy-account, STRK20 pool, agent seal and verifier class hashes
   from RPC at one recorded Mainnet block.
4. Generate distinct owner and treasury-viewing keys outside the repository.
   Store the owner recovery file on separate encrypted/offline media and verify
   that copy before rotation. Do not print either private key.
5. Verify the signer bundle, Fly configuration and HMAC/replay/restricted-method
   tests. A signer that cannot attest the expected chain, account owner, pool or
   viewing registration must exit before accepting requests.

## Cutover order

1. Run `phase4:treasury:status`, then `phase4:treasury:estimate` with the new
   viewing key and current owner. Record the pinned block, registration public
   key and fee. After exact approval, run `phase4:treasury:register` and read the
   same public key back from STRK20.
2. Estimate the policy account's public-gas requirement. Fund only the reviewed
   canary/rotation budget and verify the resulting public STRK balance.
3. Run `phase4:owner:plan` and `phase4:owner:estimate`. Compare account, current
   owner, new owner, nonce, acceptance digest and fee. After exact approval, run
   `phase4:owner:rotate`, wait for finality and run `phase4:owner:verify`.
4. Create/configure the private signer application and deploy exactly one
   machine. Confirm configuration by querying `/health` only from a sibling Fly
   machine. Test missing HMAC, bad HMAC, stale timestamp, nonce replay, malformed
   body, forbidden method and owner/viewing mismatch rejection.
5. Put only signer URL, shared HMAC, expected owner public key and treasury
   viewing private key in the web/worker secret store. Confirm no policy-owner
   key exists there.
6. Run the complete pinned attestation again. Do not enable the executor yet.

## One-run autonomous canary

1. Use a fresh organization test agreement and a deliberately small private
   amount. The employer must review the token, recipient commitment, purpose,
   period, due time and maximum amount.
2. Create one capability with one call, one exact run commitment, one token,
   one recipient commitment, a short expiry and human-approved bounded autonomy.
3. Simulate the exact `configure_policy` self-call and settlement action list.
   Record the policy ID, run-nullifier commitment, Merkle root, targets, limits,
   nonce and fee; obtain explicit approval before activation.
4. Submit the policy, read every field back, and confirm `is_policy_active` and
   run availability before dispatch.
5. Let the agent request the payroll through MCP. The worker must reload
   authoritative state, reserve limits once, build/prove/simulate once, obtain
   only the canonical signer response and submit idempotently.
6. Require final STRK20 receipt, PAYO proof receipt, exact private recipient
   balance delta, SettlementMatch `FINALIZE`, database reconciliation and no
   plaintext leakage in logs.
7. Verify replay rejection, then revoke or allow the one-run policy to expire and
   confirm it is inactive before increasing any limit.

## Deployment health and rollback

After each Fly release, verify the release version and machine health for web,
prover, discovery, transaction prover and signer. Check `/api/health`, database
migration completion, index lag, proof queue depth and signer private health.

If any check fails:

1. keep/restore `PAYO_AGENT_EXECUTOR_ENABLED=false`;
2. stop the signer or worker that can submit new transactions;
3. preserve every known transaction hash and reservation—never retry with a new
   nonce while the first hash may exist;
4. reconcile final chain state before releasing a reservation;
5. roll back the application release only after schema compatibility is checked;
6. for signer compromise, pause the policy account, revoke affected policies,
   rotate owner/session/HMAC keys and attest again before unpausing.

Stopping a web release does not revert an accepted Starknet transaction. Never
describe a UI timeout as a chain failure without checking the transaction/index.

## Privacy leakage boundary

Public observers can see contract addresses, submitter, timing, calldata,
commitment roots, nullifiers, proof/version identifiers and public gas. PAYO may
also reveal organization access timing to its hosted infrastructure. Recipient,
salary, token and private balance are not publicly decoded from the pool receipt.
Direct submission does not hide the transaction-paying policy account; a private
relay/paymaster would be needed to hide that relationship.

Proof packages reveal only their selected scope to the recipient identity. They
remain ciphertext until locally decrypted, can still be copied by an authorized
recipient after opening, and are not a substitute for organizational access
controls or endpoint security.

## Security and legal boundary

- PAYO contracts, circuits and operational services are experimental and have
  not received an independent security audit.
- Reference US/UK packs and ZK predicates demonstrate committed calculations;
  they are not tax, accounting, legal or employment advice.
- Classification and statutory correctness depend on truthful real-world inputs.
  A proof cannot establish facts that were falsely committed by an employer.
- FX floors prove the configured snapshot/rule, not guaranteed liquidity or a
  worker's off-chain purchasing power.
- PAYO is non-custodial software. Employers remain responsible for funding,
  authorization, reporting, withholding, labor compliance and dispute handling.

## Known limitations

- Autonomous Mainnet execution is disabled until the Phase 5 canary is complete.
- Only STRK and native Circle USDC are supported; token substitution is forbidden.
- PayrollIntegrity is capped at 50 real recipients in a fixed 64-leaf batch.
- Ready-backed payrolls stop at `confirmed`; only direct-SDK settlement with a
  verified SettlementMatch proof becomes `reconciled`.
- USDC/USD historical TWAP is unsupported by the current Pragma path and therefore
  fails closed when a requested proof depends on it.
- Direct policy-account execution needs a small visible public STRK gas balance.
- Hosted availability depends on Fly, RPC, proving and discovery services; each
  path fails closed rather than silently bypassing proof or authorization.

## Release evidence

Record only public/privacy-safe facts in `docs/phase5-evidence.md` and evidence
JSON: commit, image/release versions, pinned block, class hashes, transaction
hashes, status/read-backs, proof/gas timings, capability bounds, redacted balance
delta and replay/revocation result. Complete `strk20.json`, add the demo video,
run all ordinary and proof CI gates from a clean clone, then run
`npm run verify:completion`. A failing completion gate is a release blocker.
