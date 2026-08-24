# Phase 1 PayrollIntegrity evidence

Phase 1 passed its implementation gate on 2026-08-24 at commit `1792cc2e5897a14c1e36edd6bfc7910574be227e` in the green [PayrollIntegrity artifacts workflow](https://github.com/Tutulii/private-payroll/actions/runs/32695106358). This record covers the deployment-bound proof implementation. It does not claim that the verifier or PAYO contracts are deployed on Mainnet.

## Circuit and proof boundary

- Fixed 64-leaf agreement and payroll trees, at most 50 real recipients, implemented as two linked 25-line proofs against one circuit and VK.
- Exactly 17 public inputs per shard; the first 16 deployment fields and roots match, and ordered shard indices are `0` then `1`.
- 45 Noir positive and negative tests passed.
- ACIR opcodes: `206,987`; backend circuit size: `864,348`, within the enforced `2^20` domain.
- Published circuit SHA-256: `3c739cc5bc376bfc3a9c46d316118107e9c97acd4e37e938de116c841b678f78`.
- Verification-key SHA-256: `d622dff7f86da80f1b9e2fae58d4aee071d2fdec5ae018bcec353a6ce8941d96`.
- Garaga verification-key hash: `0x083a0b53dfd5611364613319f15de9b3c9b42568586814e371a71608f95b47b4`.

## Native prover evidence

- Both ZK UltraHonk/Keccak shards generated and self-verified against the same VK.
- Proof size: `10,560` bytes per shard; public inputs: `17` per shard; Garaga calldata: `3,187` inner felts per shard.
- CI proving time: `47,222 ms` for shard 0 and `46,671 ms` for shard 1; total timed command: `96.41 s`.
- Maximum native prover resident memory: `1,817,308 KiB`; no swap was consumed.
- The workflow regenerated the Garaga verifier from the proof-bound VK and passed the source-diff gate.

ZK proofs use fresh prover randomness, so proof and calldata hashes differ between valid runs. CI validates their structure, self-verifies both proofs natively, then verifies that run's newly generated calldata in Cairo instead of incorrectly requiring byte equality with a prior randomized proof.

## Real Cairo integration evidence

- Both committed real proof fixtures passed the generated Garaga verifier.
- Both freshly generated CI proofs passed the same generated verifier.
- Both sets passed the uninterrupted real-proof → `PayoIntegrityBundleVerifier` → `PayoPayrollSeal` test; no cryptographic verifier mock is used in this path.
- Fresh-proof CI gas: approximately `286,700,535` and `287,121,523` L2 gas for individual shards; approximately `604,258,918` L2 gas for the linked verifier/bundle/seal path.
- The separate PAYO contract suite passed `12/12` tests for bundle ordering, public-input binding, caller restriction, verifier failure, replay, and policy-root behavior.

## Browser-worker evidence

- Chromium `151.0.7922.34` generated and self-verified both linked proofs inside `payroll-proof.worker.ts` from an encrypted synthetic witness.
- The main thread accepted only ciphertext plus the scoped principal key; payroll plaintext was decrypted inside the worker, witnesses were zeroed after use, and no witness was logged.
- The worker returned the ordered two-shard result with `34` deployment-bound public inputs.
- Browser proving and verification completed in `314,598 ms` against the pinned circuit SHA-256 above.

## Supporting gates

- The narrow, versioned US IRS 2026 supplemental-wage and UK HMRC 2026–27 Category A examples remained source-linked, review-gated, bounded to 16 policy instructions, and passed their exact calculation/commitment tests. They are reference examples, not legal certification.
- Application typecheck passed.
- Application tests passed: `59/59` across `15/15` files.
- Production application build passed.
- Exact versions were enforced for Noir `1.0.0-beta.16`, Barretenberg `3.0.0-nightly.20251104`, Garaga `1.1.0`, Scarb/Cairo `2.16.1`, and Starknet Foundry `0.57.0`.
- The uploaded workflow artifact is `payo-payroll-integrity-1792cc2e5897a14c1e36edd6bfc7910574be227e` with archive digest `sha256:4c6da0d44e837a0ac7efa127a5349128dbc86c7807321e79951708f0d99d3cea` and 14-day retention.
