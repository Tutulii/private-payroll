# PAYO Wage-Claim vNext — Compact Production Plan

Status: in progress. The Mainnet topology is deployed and verified; the hosted
rollout and one product-origin claim/remediation run remain.

## Goal

A worker can privately prove one real payroll failure, and an employer can privately remediate it. Claim type, salary, recipient and amount stay encrypted; only commitments/nullifiers are public.

## Work

1. **Claim v6**
   - Register every due obligation before payday in an immutable snapshot.
   - Give each worker an encrypted, worker-only claim capability and Merkle opening.
   - Prove one exact condition: missing obligation, below FX floor, or incomplete final pay.
   - Derive a deterministic claim nullifier so the same claim cannot be accepted twice.

2. **Employer evidence**
   - Missing obligation uses the registered snapshot after its grace deadline and only when no run/statement exists.
   - FX-floor and final-pay claims require a registered employer statement or SettlementMatch; PAYO never fabricates a failing payroll.

3. **Remediation v7**
   - Bind remediation to one accepted Claim v6 fact, recipient, token, decimals and exact amount/conversion.
   - Use a separate remediation nullifier with expiry, retry and recovery.
   - Keep claim proved, payment confirmed and payment reconciled as separate states.

4. **Product wiring**
   - Activity lists worker-owned claim access without granting organization-wide vault access.
   - Worker proves/submits Claim v6; employer sees only the encrypted claim and can prove/settle Remediation v7.
   - Proof Package Inspector shows the disclosed claim type, original snapshot, claim ID, amount/token, remediation link and on-chain status.

5. **Release gate**
   - Positive proof vectors for all three claim types and remediation.
   - Negative tests for false type, altered root/leaf/slot, wrong worker, tenant, token, amount, recipient, replay, expiry and tampered package.
   - PostgreSQL concurrency/recovery, browser controls, Noir proofs, Cairo tests, clean-clone CI and roadmap-vs-code verification all pass.

## Done means

P3-06 stays partial until all five blocks pass in the real codebase. A Ready transfer is called confirmed, not reconciled, unless PAYO has SettlementMatch or authorized note evidence.

## Current evidence

- Blocks 1–4 are implemented locally across the v5/v6/v7 circuits, exception seal, encrypted persistence, relayers, Activity UI and proof-package inspector.
- Block 5 local gates pass: all three claim conditions and both token/FX remediation paths produced real self-verified proofs; the fresh-proof Cairo integration is 6/6, the full Cairo suite is 40/40, PostgreSQL is 30/30, and the application suite is 448/448 with lint, typecheck and the 33-route production build green.
- Linux CI now enforces PostgreSQL concurrency, rendered Chromium controls, fresh v5/v6/v7 proof generation, every claim/remediation vector through the real Cairo verifiers, and the existing clean-build gates. The release commit itself must be green before Block 5 is closed.
- Block 5 closed locally before the deployment simulation and explicit Mainnet
  approval. The remaining completion gate is one product-origin Mainnet
  claim/remediation end-to-end run.
- The approved Mainnet rollout declared and deployed Snapshot v5, Claim v6,
  Remediation v7 and the vNext exception seal on 2026-08-29. Frozen-block
  readback at block `14041891` matched every reviewed class hash and address,
  kept PayrollIntegrity v2 active, accepted all three valid proof fixtures and
  rejected their tampered forms. See
  `evidence/phase3-wage-claim-mainnet.json`.
- P3-06 remains `partial` until the current web/prover build is rolled to the
  vNext seal and one browser-origin Mainnet claim plus linked remediation
  reaches authorization, private payment confirmation and reconciliation.
