# Phase 4 Production Plan — Human and AI-Agent Payroll

Status: **active**

Normative sources: `MASTER_PLAN.md` Phase 4 and `architecture.md` sections 9, 14–16.

Goal: humans approve payroll through Ready; AI agents execute only narrowly authorized private payroll through MCP, without receiving a treasury key or arbitrary-call signer.

## Current baseline

- All eight MCP tool surfaces exist.
- Signed capability checks and human-approval routing exist.
- Autonomous signing, the restricted policy account, direct Privacy SDK settlement, and SettlementMatch remain incomplete.

## Production blocks

### P4-01 — Capability and approval authority

- Encrypt capabilities and bind tenant, principal, actions, token, recipient commitment, purpose, amount/period limits, time, nonce, call count, and approval threshold.
- Make reservation, consumption, revocation, expiry, replay prevention, and concurrent limits server-authoritative and transactional.
- Keep Ready approval as the default; autonomy is explicit, narrow, expiring, and revocable.

Gate: PostgreSQL positive, expiry, revocation, replay, cross-tenant, threshold, and concurrent-overspend tests pass.

### P4-02 — Restricted Starknet policy account

- Implement a dedicated SNIP-6/SNIP-9 account with revocable session keys.
- Enforce exact STRK20/PAYO targets, selectors, tokens, recipient commitments, purposes, limits, periods, validity, nonces, and call counts onchain.
- Add deployment, rotation, pause, recovery, and revocation procedures.

Gate: Cairo unit, fuzz, and adversarial tests reject arbitrary targets/calldata, substitutions, replay, and limit bypass.

### P4-03 — Structured-intent execution gateway

- Accept only a versioned `PaymentIntent`; never caller-supplied hashes, calldata, call arrays, targets, proofs, or signer parameters.
- Reload authoritative data, reserve limits atomically, rebuild private actions, generate/verify PAYO proofs, simulate, sign, submit, and recover idempotently.
- Redact responses/audits and safely release unused pre-submission reservations.

Gate: approval and autonomous flows pass end to end; injection, substitution, TOCTOU, duplicate submission, and concurrency attacks fail closed.

### P4-04 — Direct Privacy SDK and SettlementMatch

- Add encrypted local spend/viewing-key control, block-pinned discovery, channel readiness, fee simulation, recovery, and private history.
- Implement the real SettlementMatch proof and Payroll Seal `FINALIZE` path for direct-SDK runs.
- Keep Ready runs at `confirmed`; only verified direct-SDK runs become `reconciled`.

Gate: account recovery, STRK/USDC settlement, note discovery, tampering, wrong-manifest, replay, reorg, and `FINALIZE` tests pass.

### P4-05 — MCP product wiring and evidence

- Wire all eight MCP tools to production authorization, payroll, proof, settlement, recovery, receipt, and disclosure services.
- Add UI controls for capability creation/revocation, human approvals, agent state/limits, and redacted audit history.
- Record reproducible Devnet human-approval and bounded-autonomy evidence; update status only from actual results.

Gate: MCP transport/adversarial, concurrent-limit, approval/autonomy, direct-SDK recovery, SettlementMatch, database, browser, build, and clean-clone CI tests pass.

## Completion rule

Phase 4 is complete only when all five blocks have integrated code, positive and negative tests, and linked evidence; `npm run verify:status` passes; and comparison with `MASTER_PLAN.md` Phase 4 plus relevant `architecture.md` requirements finds no partial or missing item. Then remove the temporary Phase 4 directive from `AGENTS.md`.
