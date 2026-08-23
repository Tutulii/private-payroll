# PAYO verification report

This is a point-in-time evidence report, not a production-readiness or completion claim.

## Baseline

- Recorded: `2026-08-24T01:23:49+06:00`
- Branch: `main`
- Base commit before this Phase 0 work: `25abd62700be8a613da5b528f280dc545249226f`
- Roadmap: `7/31` strict-complete; `41.9%` weighted implementation
- Architecture: `1/16` strict-complete

The machine-readable source of these counts is `docs/implementation-status.json`. Mocks, disabled paths, schema-only work, and uncommitted external claims are not counted as complete.

## Verified locally

| Check | Result | Evidence |
|---|---|---|
| TypeScript | Pass | `npm run typecheck` |
| Application/domain tests | 47/47 pass | `npm test` |
| ESLint | Pass | `npm run lint` |
| Next.js production build | Pass with documented upstream warnings | `npm run build` |
| Status-matrix structure | Pass | `npm run verify:status` |
| Noir | 8/8 pass; build pass | Noir `1.0.0-beta.16`, noirc commit `2d46fca7203545cbbfb31a0d0328de6c10a8db95` |
| Cairo contracts | Build pass | Scarb/Cairo `2.16.1`, Sierra `1.7.0` |
| Cairo tests | 5/5 pass | Starknet Foundry `0.57.0` |
| Cross-language commitments | Pass | TypeScript, Noir, and Cairo match `vectors/commitments-v1.json` |
| Clean dependency install | Pass | `npm ci --ignore-scripts` from the committed lockfile |

The production build warnings originate in optional Privy/viem dependency paths (`@farcaster/mini-app-solana` and a dynamic `ox/tempo` import). They did not fail compilation, type checking, or prerendering. They remain a dependency-integration finding rather than being hidden.

`npm audit --omit=dev` currently reports 10 moderate and no high or critical production findings. They are transitive through Privy's EVM/wagmi/MetaMask dependency path; npm's suggested remedy is a breaking Privy downgrade. No unsafe forced downgrade was applied. This must be reassessed and explicitly resolved or accepted before the Phase 5 dependency gate.

## Phase 0 hard gate still open

Native Circle USDC shielding and a cross-account private transaction are proven at the Ready `wallet confirmed` evidence level. The shield's USDC details are public; the private transaction's asset and recipient relationship are Ready/user-attested because the pool hides them by design. This is not SettlementMatch. Exact evidence and limitations are recorded in `evidence/usdc-mainnet.json` and `docs/usdc-mainnet-evidence.md`.

Phase 1 may start after `npm run verify:usdc` independently confirms the public shield and private-note receipts while preserving the explicit Ready-attestation boundary.

## Known non-completion evidence

- The current Noir circuit remains `v1-core`; final policy and FX membership composition is not implemented.
- The Cairo seal tests use a mocked verifier; a generated Garaga verifier is not integrated.
- PAYO contracts are not deployed.
- Durable chain indexing/reorg recovery and database integration are incomplete.
- SettlementMatch and the policy-account signer are missing.
- Mainnet release transactions, public deployment, video, and runbooks are missing.

These facts are why `npm run verify:completion` is expected to fail today.
