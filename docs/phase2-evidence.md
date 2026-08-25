# Phase 2 implementation evidence (in progress)

This document records verified Phase 2 work without claiming that the Phase 2 gate has passed. The proof topology is deployed on Mainnet and the Ready STRK payroll row now passes end to end. Native-USDC-only and mixed PAYO payroll rows remain pending.

## Requirement audit

| Master-plan requirement | Evidence-backed state |
|---|---|
| Client-encrypted records in the real UI/API | Implemented for organizations, principals, payees, agreements, runs/lines, proof bundles, settlements, receipts, disclosure grants, agent capabilities, claim/remediation drafts, and operational audit events. |
| Recovery and key lifecycle | Recovery packages, recovery acknowledgement, second-admin enrollment, full latest-record key rotation, principal revocation, and fail-closed missing-key behavior are integrated and database-tested. |
| Durable PostgreSQL execution | Idempotency, transactional capability reservations, proof and confirmation leases, restart recovery, block cursors, event indexing, bounded reorg rollback, and delayed-confirmation behavior are implemented and tested. |
| STRK/native-USDC single and mixed batches | Exact orchestration, passive live fee quotes, per-token totals, and separate reserve validation are unit-tested. A live Ready STRK payroll passed, including employee receipt attestation, durable confirmation, seal status `proven`, and both on-chain verifier shards. Native-USDC-only and mixed PAYO payroll evidence remains pending. |
| Final proof-enforcement contracts | Complete. The generated verifier, bundle verifier, policy/FX registry, obligation-root registry, and seal are deployed on Mainnet; their class hashes and seven constructor/administrator/verifier/pool bindings re-verified at block `13,820,751`. Baseline policy root and proof version 1 are active. |

## Verified locally on 2026-08-25

- Web/domain suite: 169 passed; 14 environment-gated PostgreSQL tests were skipped in the generic command and then passed separately against the migrated test database.
- PostgreSQL durability suite: 14 passed against a migrated PostgreSQL database.
- PAYO Cairo suite: 23 passed, including 256 fuzz runs for each policy/FX, obligation-root, and verifier lifecycle property. Immediate policy, verifier, obligation, and FX-publisher activation plus fresh, stale, unauthorized, expiring, and revocation cases pass.
- Generated-verifier suite: 3 passed. Both proof shards passed the real Garaga verifier; the linked test consumed approximately `634,425,340` L2 gas in Starknet Foundry.
- Current immediate-activation RPC gate: passed against pinned Starknet Devnet `0.9.2` / RPC `0.10.2` after rebuilding both Scarb packages. Five current classes were declared and five instances deployed; the policy, verifier, and obligation entries were read back as active in the scheduling transaction's confirming block. Two new deployment-bound witnesses and UltraHonk proofs self-verified against the pinned key, passed through the current generated verifier, bundle, registries, and seal, reached status `proven`, and replay simulation was rejected.
- Production Next.js build passed. The remaining warnings come from Privy's optional Farcaster/Solana import and viem's Tempo dynamic dependency.
- The guarded Mainnet planner and mutation path declared all five reviewed classes, deployed the deterministic topology, simulated each write, waited for receipts, and read all bindings back. `npm run phase2:mainnet:verify` passed again at block `13,820,751` on 2026-08-25. The procedure is documented in `docs/phase2-mainnet-deployment.md`.
- The local `/deployment` Ready operator serves only fresh rebuilt artifacts, recomputes their class hashes again in the browser, requires an exact typed confirmation plus wallet approval, handles partial/restarted declaration and deployment state idempotently, verifies seven administrator/verifier/pool/registry bindings, and activates the canonical policy root and proof version on confirmation. It reads both entries back before reporting success. Its artifact route and page were exercised locally without sending a wallet request.

## Full-topology proof fixture

`Prover-phase2.toml` and `Prover-phase2-shard-1.toml` use a proof window of `86500..87500`. The window is a deterministic proof fixture; registry entries now activate in their confirming block and no registry read is mocked.

The integration deploys and exercises:

1. the pinned Garaga `UltraKeccakZKHonkVerifier`;
2. `PayoIntegrityBundleVerifier`;
3. `PayoPolicyRegistry` with the real policy root, short-lived FX root, and mode/version verifier entry;
4. `PayoObligationRootRegistry` with the proof's authoritative agreement root; and
5. the proof-bound `PayoPayrollSeal` at the address exposed by both proofs.

The pool seals both proof hashes, then the real verifier checks each committed shard in a bounded follow-up call. Only after both succeed does the run become `proven`. The phase-two and Phase 1/browser fixtures share verification-key SHA-256 `d622dff7f86da80f1b9e2fae58d4aee071d2fdec5ae018bcec353a6ce8941d96`.

The workflow regenerates the deployment-bound witnesses and proofs, checks that the verification key is unchanged, stages fresh calldata, and reruns the full topology.

## Standalone RPC deployment-bound proof

`scripts/test-phase2-devnet.mjs` refuses non-devnet chain IDs, an incompatible RPC version, missing artifacts, and deploy artifacts older than their Cairo source package. Its stages declare and deploy the generated verifier, bundle verifier, policy registry, obligation registry, and seal; activate and immediately read back the policy/verifier/obligation entries; publish the exact fresh FX root through the constrained publisher path; then submit the sealed-hash fallback plus both real proof shards.

Artifact discovery and freshness checks are shared with the Mainnet planner, so
Devnet evidence and production deployment cannot silently select different
Sierra/CASM files. The Mainnet path additionally records content digests,
recomputes class hashes, predicts the full constructor-bound topology, simulates
writes, and verifies every deployed binding through RPC.

Unlike the fixed Foundry fixture, this proof input is generated after deployment and binds the actual RPC-deployed seal address and Devnet chain ID. On 2026-08-25, both rebuilt proofs self-verified against verification-key SHA-256 `d622dff7f86da80f1b9e2fae58d4aee071d2fdec5ae018bcec353a6ce8941d96`. The current immediate policy-registry class hash was `0x06366141e5ae47f2e170409c6babaa4d6ae220b5b255f8dcbf9b0173f8681cfd`; the obligation-registry class hash was `0x00a7f868967f49461e948c8e8d70b2bccc74fc623e2d3ecd4af8cb4c2ccd8165`. The activation transaction was `0x07da5aaabf9ed37c31888a3011a2e2dddc487a702ea23bce3f75cad645d22d2`; the fresh FX publication was `0x04c3cf40c8a1d6710f250a8b102af1cb408c641b5152d61a5d336e992ef3ffb3`. Proof hashes `0x044bf9ae811c002f9b003a6f9c4953112909c8081d698719cbae7f7ee308604d` and `0x0201abc7aa705c3ddfc748c433d607ec29453a0e074d768a1e92f7e07fa03669` passed, the run finished with on-node status `2` (`proven`), and replay simulation was rejected. UltraHonk proofs are randomized, so proof hashes differ between valid runs. Devnet addresses and hashes are local evidence, not Mainnet deployment claims.

The configured devnet account represents the STRK20 pool caller at the seal boundary. Live pool execution remains part of the separate wallet/Mainnet gates below.

## Starknet Mainnet topology

All addresses below are bound to `SN_MAIN` and the canonical STRK20 pool `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`:

| Component | Address | Class hash |
|---|---|---|
| Generated Garaga verifier | `0x475cc47caf5d8b5b3a719915ceef5ae3e959f8754f2c0faa634d2e8c73d06db` | `0x601776a0980ab1b8e3d629d456dccc5eace85ba6f47a015d2e3c3448a758bb9` |
| PayrollIntegrity bundle verifier | `0x2755c2260220f44c319249402887ca50c8b968ab43364e90de54f5afd66759` | `0x451e59b2f2e454a5a53914ca317069d84faf504498e1d56609a78fb626da2bc` |
| Policy / FX registry | `0x4e5309dc9662bf8e136c1d626c1410ea07f74e743a0972c1e253b08ece46aad` | `0x6366141e5ae47f2e170409c6babaa4d6ae220b5b255f8dcbf9b0173f8681cfd` |
| Obligation-root registry | `0x21a91368561d32c91a861412ec6823a21cc2b64ab10110f575bf57709b7880c` | `0x0a7f868967f49461e948c8e8d70b2bccc74fc623e2d3ecd4af8cb4c2ccd8165` |
| Payroll seal | `0x4bde3263ff117f245f9ebea20670b363550951f61cf54f236c449f70181c01f` | `0x4c1dc6a699f310964bad2380adf2b0f9bdcb14825a0f19fb20fd4c13458fc40` |

The five declarations are recorded in the ignored operator evidence package. The deterministic deployment transaction is `0x510eee3af791d825701fd3cb3ba9c5d82e0d23c15c91ef5a857d6d4f41da8a8`. Baseline activation transaction `0x235d95d7b9c24b725bf513b48d08cac7a91e4c89c890dbc6d2a68d9e32f6017` succeeded at block `13,815,354`, activating policy root `0x16575a4f2517b43a894ae1d8ad892448892830da2cb8162b50354f396e3d6073`, precommit mode, and proof version 1.

The permissionless, fee-only proof relayer is deployed at `0x0126a7a572cf8935d069af937e9f7b27a24949e271e1fbccfe4de0c0d8dc8ea9`. Deployment transaction `0x395c4175c9db10b6520020f8aa3f89804c51a587a3cfcc5fd0edfb1cd7b15a7` installed pinned OpenZeppelin account class `0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381`; the guarded operator script re-derived the address, estimated the fee, waited for the receipt, and read the deployed class hash back. This account can call permissionless proof verification but has no authority over private payroll assets or PAYO registries.

This proves deployment and configuration, not a live private payroll. Recipient and amount privacy prevents using a public explorer alone as payroll evidence; PAYO must record its encrypted run, wallet receipt, seal state, and both on-chain verifier-shard receipts.

## Live proof-bound STRK payroll

On 2026-08-25, a Ready Wallet API 0.10.3 user approved a deliberately limited STRK payroll through the deployed STRK20 pool and PAYO seal. PAYO stored the encrypted run and proof bundle, recorded the wallet transaction, finalized the settlement through the durable confirmation worker, and queued both hash-bound proof shards. The permissionless relayer then submitted both shards to the real generated verifier. Mainnet RPC reads returned seal status `2` (`proven`) with both shard flags true.

- Private payroll transaction: `0x345a1be9710d3630915d6cd8279173ce47b198161f4c8a9cb4c64e1fc98fb26`, `SUCCEEDED` / `ACCEPTED_ON_L2`, block `13,833,610`.
- Verifier shard 0: `0x75d8f23f287125a73e8d8dc091d8782bbe3838c1f9cb34a15b2f120cb9e9639`, `SUCCEEDED` / `ACCEPTED_ON_L2`, block `13,833,625`.
- Verifier shard 1: `0x2eb9e69bfef8b5f6f6a4b97baf7072624819fd1a161f7f04e527ecc69dae0a7`, `SUCCEEDED` / `ACCEPTED_ON_L2`, block `13,833,635`.
- Recipient evidence: the user confirmed that the external employee Ready account received the shielded STRK. Recipient and salary amount remain deliberately absent from public repository evidence.
- Machine-readable record: [`evidence/payo-strk-mainnet.json`](../evidence/payo-strk-mainnet.json). `npm run verify:payo-strk` rechecks all three receipts, the pool/seal event path, run status, and both shard flags over Mainnet RPC.
- A fresh read-only topology verification passed at Mainnet block `13,834,173` after this run.

This is sufficient for the STRK row of the Phase 2 wallet matrix and for the deployed real-verifier architecture requirement. It does not prove native-USDC-only or mixed-token PAYO payroll behavior and therefore does not close Phase 2.

## Still required for the Phase 2 gate

- Complete live Ready wallet tests for one native-USDC-only PAYO batch and one mixed STRK/native-USDC PAYO batch using passive live fee reserves. The STRK row is complete.
- Keep the funded permissionless proof relayer and confirmation/proof/indexer workers healthy; PAYO verifies Privy access tokens against the app-bound public JWKS without an App Secret.
- For each live run, activate its exact obligation root and publish the short-lived FX root before Ready approval.
- Record the remaining two encrypted run records, wallet receipts, two verifier-shard receipts per run, final seal status, and clean-clone CI evidence.

Until those items pass, Phase 2 is not 100% complete.
