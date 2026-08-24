# PAYO Starknet contracts

- `PayoPayrollSeal` is a non-custodial STRK20 `privacy_invoke` helper. Only its configured pool may call it. It accepts two linked PayrollIntegrity proof payloads, validates all 34 returned public inputs, consumes the run nullifier only after both proofs pass, emits a proof receipt, and returns no token deposit.
- `PayoIntegrityBundleVerifier` calls one proof-bound Garaga `UltraKeccakZKHonkVerifier` for shard 0 and shard 1, propagates either verifier failure, and returns both 17-input arrays in order.
- `integrity_verifier/` is the Garaga 1.1.0 generated verifier for the exact committed PayrollIntegrity VK. Its tests verify both real proof fixtures and the uninterrupted verifier → bundle → seal path.
- `PayoPolicyRegistry` timelocks versioned policy roots and supports emergency revocation. Production ownership must be transferred to a multisig.

The seal currently implements only `PRECOMMIT` (`mode = 0`). SettlementMatch, claims, remediation, and the sealed-hash fallback remain later-phase work and are rejected rather than silently downgraded.

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
- seal verifier argument: the bundle-verifier address

Deployment is not automated with a private key. Declaration and deployment require simulation and explicit approval from Ready or a hardware-backed Starknet account after the local and CI proof/contract gates pass.
