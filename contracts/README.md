# PAYO Starknet contracts

- `PayoPayrollSeal` is a non-custodial STRK20 `privacy_invoke` helper. Only its configured pool may call it. It accepts two linked PayrollIntegrity proof payloads, validates all 34 returned public inputs, consumes the run nullifier only after both proofs pass, emits a proof receipt, and returns no token deposit.
- `PayoIntegrityBundleVerifier` calls one proof-bound Garaga `UltraKeccakZKHonkVerifier` for shard 0 and shard 1, propagates either verifier failure, and returns both 17-input arrays in order.
- `integrity_verifier/` is the Garaga 1.1.0 generated verifier for the exact committed PayrollIntegrity VK. Its tests verify both real proof fixtures and the uninterrupted verifier → bundle → seal path.
- `PayoPolicyRegistry` activates policy roots, verifier addresses, and FX-publisher rotation in the confirming block for the hackathon Mainnet profile. Its narrowly scoped publisher can register only short-lived FX roots (maximum one hour). Both the publisher and administrator can revoke compromised roots.
- `PayoObligationRootRegistry` independently activates authoritative agreement roots on confirmation and supports expiry and revocation.

The seal enforces ordered `PRECOMMIT`, `FINALIZE`, `CLAIM`, and `REMEDIATE` state transitions. The proof payload is always verified by the configured mode/version verifier. Large proofs use the sealed-hash fallback: the pool stores two non-zero proof hashes, then either shard is verified in a bounded follow-up transaction before the run becomes proven. An intermediate sealed run is never reported as proven.

The full-topology test uses a second deployment-bound witness fixture and no registry mocks. It deploys the generated Garaga verifier, bundle verifier, policy/FX registry, obligation-root registry, and proof-bound seal; activates every root through the real registry contracts; and passes both real proof shards through the sealed-hash path. The fixture uses the same verification-key hash as the browser/Phase 1 proofs.

The proof-artifact workflow also runs `scripts/test-phase2-devnet.mjs` against pinned standalone Starknet Devnet `0.9.2` / RPC `0.10.2`. The deploy stage refuses artifacts older than their Cairo sources. The test declares and deploys the same five-contract topology over JSON-RPC, generates new proofs bound to the deployed seal and chain ID, activates governance and obligation roots immediately, publishes the fresh short-lived FX root, verifies both shards, and rejects a replay. Its deployment and evidence manifests are uploaded with the workflow artifacts.

## Build and verify

```bash
cd contracts
scarb build
snforge test

cd integrity_verifier
scarb build
snforge test
```

The generated verifier must never be hand-authored. `.github/workflows/proof-artifacts.yml` regenerates its source from the proof-bound VK and fails on a source diff. The proof commands, exact versions, artifact hashes, and calldata rules are documented in `circuits/README.md`.

## Mainnet constructor values

- STRK20 pool: `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`
- chain ID: `SN_MAIN`
- verifier: deployed Garaga `UltraKeccakZKHonkVerifier` from the exact pinned VK
- bundle verifier: deployed `PayoIntegrityBundleVerifier` pointing to that verifier
- policy registry: multisig admin; activate the policy root and bundle verifier for every enabled proof mode/version, then rotate the FX publisher to a dedicated limited-purpose account through the immediate two-step flow
- FX publisher: publish only roots computed from block-pinned Pragma observations; each root expires within one hour and the publisher must never control payroll funds
- obligation registry: multisig admin; schedule each authoritative agreement root before its proof window
- seal: immutable STRK20 pool, policy-registry address, obligation-registry address, and `SN_MAIN` chain ID

The guarded Mainnet planner/deployer is
`scripts/payo-mainnet-deployment.mjs`; its complete operator procedure is in
[`docs/phase2-mainnet-deployment.md`](../docs/phase2-mainnet-deployment.md). It
recomputes artifact and class hashes, predicts constructor-bound addresses,
refuses a non-Mainnet RPC or stale artifacts, simulates every write, requires an
exact confirmation phrase, and reads every deployed binding back before
producing evidence. A mutation still requires explicit operator approval and a
temporary hardware-backed or otherwise isolated deployment signer; no private
key is stored by PAYO.

For an existing Ready administrator, `/deployment` provides the keyless operator
path: artifacts remain server-side until explicitly loaded, Ready handles each
simulation and approval, browser code recomputes the reviewed hashes, and the UI
will not offer baseline activation until the entire deployed topology reads back
correctly.
