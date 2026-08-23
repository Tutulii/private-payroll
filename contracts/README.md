# PAYO Starknet contracts

- `PayoPayrollSeal` is a non-custodial STRK20 `privacy_invoke` helper. Only the configured pool may call it. It verifies a Garaga UltraKeccakZKHonk proof, checks every returned public input, consumes the run nullifier, emits a proof receipt, and returns no token deposit.
- `PayoPolicyRegistry` timelocks versioned policy roots and supports emergency revocation. Production ownership must be transferred to a multisig.

The seal currently implements only `PRECOMMIT` (`mode = 0`). SettlementMatch, claims, and remediation are intentionally rejected until their independent circuits and viewing-key evidence exist.

## Build

```bash
scarb build
snforge test
```

The generated `integrity_verifier` workspace is created by the command in `circuits/README.md` after the Noir proof and verification key have been produced. Do not hand-author or deploy a placeholder verifier.

## Mainnet constructor values

- STRK20 pool: `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`
- chain ID: `SN_MAIN`
- verifier: class instance generated from the exact pinned PAYO circuit artifacts

Deployment is not automated with a private key. Declaration and deployment should be approved in Ready or a hardware-backed Starknet account after local proof/contract tests pass.
