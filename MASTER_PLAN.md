# PAYO 100% completion master plan

This plan completes every requirement in the README roadmap and `architecture.md` in strict Phase 0 → Phase 5 order. A later phase cannot begin until the previous phase's implementation, negative tests, integration evidence, and documentation gate all pass.

## Definition of done

PAYO may be called 100% complete only when:

- all 31 roadmap requirements and all 16 architecture sections are `complete` in `docs/implementation-status.json`;
- `npm run verify:completion` and the complete web, Noir, Garaga, Cairo, database, MCP, wallet, security, and Mainnet suites pass from a clean clone;
- the encrypted-run → browser proof → real Garaga verifier → PAYO seal → STRK20 settlement → durable confirmation → SettlementMatch path has real end-to-end evidence;
- deployed addresses, class hashes, verifier/VK hashes, proof benchmarks, at least three qualifying Mainnet transactions, a live demo, a three-minute video, and all runbooks are public;
- a final human/agent audit rereads `README.md:72+` and all of `architecture.md` against the actual codebase.

No source directory, interface, mock, disabled control, isolated calculator, or unverified external claim counts as a delivered feature.

## Phase 0 — Protocol and safety foundation

1. Persist this completion gate, the evidence matrix, status validator, and CI checks.
2. Freeze versioned schemas for every architecture record, UUIDv7 identifiers, atomic amounts, state transitions, and privacy classifications.
3. Complete canonical Keccak encoding and golden vectors in TypeScript, Noir, and Cairo.
4. Pin exact npm, Starknet, Privacy SDK, Noir, Barretenberg, Garaga, Scarb, Cairo, and Foundry versions.
5. Verify native Circle USDC against Ready and the live Mainnet STRK20 pool with a deliberately small shield, refresh, transfer, and balance-delta test before enabling it.

Gate: schemas and privacy boundaries are tested, every cross-language vector matches, exact toolchains build, and live native-USDC evidence is committed.

## Phase 1 — Deployment-bound PayrollIntegrity

1. Replace experimental `v1-core` with the final circuit: schema/policy/FX roots, authoritative agreement membership, sorted unique coverage, bounded policy execution, exact decimals, Pragma freshness/source rules, schedules, classification, and explicit final-pay components.
2. Add exhaustive positive and negative circuit tests for every assertion in the architecture.
3. Add official-source, versioned US and UK reference packs without claiming legal certification.
4. Generate proofs in a browser Web Worker without witness logging or main-thread plaintext leakage.
5. Generate and commit the pinned Garaga verifier; CI regenerates it and fails on a diff.
6. Pass a real proof through the real generated verifier and PAYO seal test path. Mocks do not satisfy this gate.

Gate: final public inputs and private memberships match the architecture, all negative tests pass, real verifier calldata is accepted, and verifier/VK/circuit hashes and benchmarks are recorded.

Phase 1 gate evidence: **passed on 2026-08-24** at commit `1792cc2e5897a14c1e36edd6bfc7910574be227e`. The reproducible hashes, native/browser benchmarks, real-verifier gas, test counts, and green workflow are recorded in [`docs/phase1-evidence.md`](./docs/phase1-evidence.md). This is implementation evidence, not a Mainnet deployment claim.

## Phase 2 — Durable encrypted settlement

1. Integrate client-encrypted organizations, principals, payees, agreements, runs, proof bundles, settlements, receipts, disclosures, capabilities, claims, remediation, and audit events into the real UI/API.
2. Add encrypted recovery packages, second-admin recovery, key rotation, grant revocation, and fail-closed lost-key behavior.
3. Add PostgreSQL idempotency, transactional capability reservations, confirmation jobs, chain cursors, event indexing, restart recovery, and reorg handling.
4. Execute single- and mixed-token STRK/native-USDC batches with separate fee reserves.
5. Finalize and deploy the non-custodial seal, policy/FX/verifier registry, authoritative obligation-root registry, and generated verifier. Support pool-only calls, replay protection, version/root expiry, all proof modes, and the sealed-hash fallback.

Gate: database/API/recovery/reorg tests, real-proof devnet integration, wallet tests, contract fuzzing, and deployed-address verification pass.

## Phase 3 — Advanced obligations and disclosure

1. Deliver `StatutoryCorrect`, `FXFloor`, `ClassificationConsistency`, and `OffboardingCorrect` as verifier-backed proof profiles.
2. Integrate Pragma median/TWAP snapshots with decimals, timestamp, source count, maximum age, haircut, and unsupported-pair behavior.
3. Deliver encrypted recurring, checkpoint stream, milestone, vesting, termination, and adjustment workflows through STRK20 channels and PAYO proof enforcement.
4. Add private wage-claim and remediation circuits plus `CLAIM` and `REMEDIATE` state transitions.
5. Add recipient-encrypted worker, employer, auditor, and tax proof packages with line openings, Merkle paths, field scopes, expiry, revocation, balanced journals, and offline verification.

Gate: each workflow is created in UI, encrypted, proved, settled on devnet, disclosed only to its intended scope, and rejected by its negative cases.

## Phase 4 — Human and AI-agent payroll

1. Keep Ready as the human signer and human approval as the default.
2. Encrypt signed agent capabilities and make period spending server-authoritative and transactionally race-safe.
3. Implement a dedicated SNIP-6/SNIP-9 policy account and revocable session signer restricted by exact pool/PAYO targets, selectors, tokens, recipient commitments, purpose, amount, period, time, nonce, and call count.
4. Make the gateway accept only structured `PaymentIntent`, rebuild actions, generate proofs, simulate, validate, and sign; arbitrary hashes, calldata, calls, targets, and caller proofs are rejected.
5. Integrate the direct Starknet Privacy SDK with local encrypted viewing-key control, block-pinned discovery, fee simulation, and transaction history.
6. Implement SettlementMatch for direct SDK accounts and `FINALIZE`; Ready-backed runs remain honestly `confirmed` until Ready exposes compatible evidence.
7. Complete all eight MCP tools end to end with approval and bounded-autonomy paths.

Gate: MCP transport and adversarial tests, concurrent limit tests, approval/autonomy tests, direct-SDK recovery tests, and SettlementMatch tests pass.

## Phase 5 — Mainnet evidence and release

1. Record a human STRK payroll, a human native-USDC payroll, and an advanced obligation or agent payroll that each touch the live STRK20 pool and PAYO contracts.
2. Verify transaction success, contract calls, state transitions, roots, and balance effects by RPC.
3. Complete `strk20.json`, deploy the public application, and publish a three-minute demo video.
4. Publish contract/class/verifier hashes, proof and gas benchmarks, policy/FX roots, deployment and administration procedures, recovery, incident response, security, privacy leakage, legal boundaries, and known limitations.
5. Run `npm run verify:completion` and perform the final README/architecture-to-code audit from a clean clone.

Gate: 31/31 roadmap requirements and 16/16 architecture sections have linked evidence, every suite passes, the dependency audit has no unaccepted finding, and all release evidence is public.

## Locked implementation defaults

- Phase order is strict, not parallel.
- Ready signs human flows; a dedicated policy account signs bounded agent flows.
- Proof generation is local/offchain; proof verification and PAYO state enforcement are onchain.
- Native Circle USDC is the only USDC and is never silently replaced.
- US/UK packs are reference examples, not legal advice.
- Mainnet deployments and human transactions require simulation and explicit user approval. No recovery phrase or unrestricted private key enters the repository.
- Any unavailable external capability remains incomplete or blocked; it never becomes a documentation exception to 100%.
