# PAYO Policy Account Runbook

Status: Phase 4 operational procedure. The policy account is a bounded AI-agent signer; it is not a replacement for Ready's human-approval flow.

## Security boundary

- The owner key is the recovery and administration key. It exists only in the
  isolated `payo-policy-signer` service (plus an offline recovery backup), never
  in the web, MCP, worker, prover, discovery or transaction-relayer runtimes.
- The agent receives only one short-lived Stark-curve session key.
- A session key may call only `execute_from_outside_v2`, with one outer call back to the account's `execute_policy_intent` entrypoint.
- Each authorized run is committed in the policy's depth-8 Merkle root. The leaf binds the policy, agreement root, manifest root and run nullifier.
- The account parses the exact STRK20 action list, rejects public deposits, withdrawals and transfers, and permits exactly one invocation of the configured PAYO seal.
- Pausing, key rotation, policy creation and revocation require an owner-signed self-call. An MCP or gateway process must never hold the owner key.
- The web authenticates to the signer with a distinct 32-byte-or-longer HMAC
  secret over timestamp, nonce, method, path and body hash. The signer rejects
  stale or replayed nonces and is reachable only over Fly private networking.
- The online signer exposes only canonical STRK20 `compile_actions` proof
  signatures and bounded `configure_policy` submissions. It rejects typed
  messages, declarations, deployments, owner rotation, pause, revocation,
  arbitrary calls, paymasters and nonzero proof-invocation fees.

## Pre-deployment gate

1. Build from the pinned `contracts/Scarb.lock` and record the `PayoPolicyAccount` Sierra and CASM class hashes.
2. Run `snforge test policy_account`. All positive, adversarial, limit and fuzz cases must pass.
3. Verify the configured pool and seal against the intended network's reviewed deployment artifact.
4. Create a fresh owner key and a distinct session key. Never derive one from the other.
5. Start with a short validity window, a one-call period limit and a deliberately small authorized-run tree.
6. Simulate deployment and policy configuration at the same pinned block before broadcasting.

Every Mainnet mutation requires a fresh simulation, an explicit human approval,
and a pinned read-back. Never reuse Devnet keys on Mainnet.

## Isolated signer cutover

1. Generate a fresh owner key outside the repository, logs and shell history;
   store its recovery copy offline. Derive and record only its public key.
2. Generate one distinct treasury viewing key. Before owner rotation, run the
   digest-pinned `phase4:treasury:estimate` bootstrap and inspect its exact pool,
   account, block and fee. After explicit approval, run
   `phase4:treasury:register`; retain only its public-key and transaction evidence.
3. Fund the policy account with only the public STRK operational gas budget.
   Run `phase4:owner:estimate`, then after explicit approval rotate with
   `phase4:owner:rotate` and prove the new key with `phase4:owner:verify`.
4. Set `PAYO_POLICY_OWNER_PRIVATE_KEY`, `STARKNET_RPC_URL`,
   `PAYO_POLICY_SIGNER_SECRET` and `PAYO_AGENT_POLICY_VIEWING_PUBLIC_KEY` only on
   the private signer app. The private viewing key is never a signer variable.
5. Set `PAYO_POLICY_SIGNER_URL`, the same HMAC secret, the expected owner public
   key and `PAYO_AGENT_POLICY_VIEWING_KEY` only in the web/worker secret store.
   PAYO encrypts that viewing key again before database storage. Remove any
   policy-owner private key from the web/worker app.
6. Before starting, the signer must attest at one pinned block that chain,
   policy-account owner and STRK20 registration public key all match its config.
7. Start one signer machine with no public Fly service. Confirm `/health` only
   through the private network, then run rejection tests before a canary policy.
8. Maintain only the public STRK operational gas budget;
   private payroll value remains in STRK20 notes. Alert before the gas floor.

Do not enable autonomous dispatch if rotation, signer attestation, web-secret
removal, policy-account gas, or the canary read-back is incomplete.

## Deploy and configure

1. Declare `PayoPolicyAccount` and verify the declared class hash matches the locally recorded CASM/Sierra pair.
2. Deploy with only the owner public key as constructor calldata.
3. Verify SNIP-6 and SNIP-9 v2 interface support through SRC-5.
4. Generate the authoritative run leaves in the backend, build the depth-8 Merkle tree and retain the exact sibling path for every approved run.
5. Have the owner submit a self-call to `configure_policy(policy_id, config)`.
6. Read back `get_policy(policy_id)` and compare every field byte-for-byte with the reviewed configuration.
7. Confirm `is_policy_active(policy_id)` and `is_run_available(mode, nullifier)` before enabling the session signer.

Never configure a zero commitment, an unreviewed pool/seal, a wildcard target, or a policy lifetime longer than the operational need.

## Session-key rotation

1. Pause autonomous dispatch in the gateway.
2. Generate the replacement session key outside logs and shell history.
3. Have the owner submit `rotate_session_key(policy_id, new_public_key)` as a self-call.
4. Read back the policy and confirm the new public key.
5. Delete the old encrypted key only after the rotation transaction is final.
6. Submit one pre-authorized canary run; resume dispatch only after it is final and indexed.

Old signatures fail immediately after the on-chain key changes.

## Emergency pause and recovery

1. Stop the gateway worker and preserve submitted transaction hashes.
2. Have the owner call `set_policy_account_paused(true)`.
3. Verify `is_policy_account_paused()` at a final block. Both SNIP-9 execution and policy execution must now revert.
4. Revoke affected policies with `revoke_policy(policy_id)`; revocation is irreversible for that policy ID.
5. Rotate the normal SNIP-6 owner public key through the inherited OpenZeppelin account interface if owner-key compromise is suspected.
6. Create a new policy ID and a new session key. Never reuse a revoked ID or compromised nonce/key material.
7. Unpause only after gateway configuration, on-chain reads and a simulated canary all match.

## Routine revocation

1. Disable the capability and future reservations in PAYO first.
2. Wait for any already-submitted transaction hash to reach a terminal chain state.
3. Have the owner self-call `revoke_policy(policy_id)`.
4. Verify `get_policy(policy_id).revoked == true` and archive a redacted audit record containing only the policy ID, transaction hash and timestamp.
5. Destroy the encrypted session key and release reservations that never reached submission.

## Incident invariants

- Never retry with a new outside-execution nonce when the original transaction hash may exist. Recover the original hash first.
- Never release a reservation after signing or submission; mark it committed and reconcile idempotently.
- Never log private actions, note data, session secrets, plaintext recipients or salary amounts.
- A Ready-backed run stops at `confirmed`. Only a direct-SDK run with a verified SettlementMatch proof may become `reconciled`.
