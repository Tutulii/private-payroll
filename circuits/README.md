# PAYO circuits

`payroll_integrity` is the deployment-bound v1 private calculation circuit. It binds fixed 64-leaf authoritative-agreement and payroll-manifest trees and permits at most 50 due obligations. The circuit has 16 public inputs:

1. Starknet chain ID, PAYO seal address, proof version, and schema version;
2. agreement, manifest, policy-catalog, and FX-catalog roots as high/low `u128` limbs;
3. a circuit-derived run nullifier as high/low limbs; and
4. validity start and expiry.

The private witness proves one-to-one coverage of every due agreement, sorted unique agreement identifiers, canonical padding, committed recipient/earnings/token/schedule terms, bounded policy execution, deductions and net arithmetic, classification consistency, token and quote decimals, source-count and freshness rules, deterministic FX floor rounding, and explicit final-pay components. Agreement-term, policy-program, FX-snapshot, payroll-leaf, and nullifier encodings have TypeScript/Noir golden tests. V1 normalizes USD and GBP floors to six reference-currency decimals and rejects any other quote scale.

The circuit is deliberately a consistency proof, not a legal opinion. A policy catalog must be reviewed and activated by the organization or its authorized reviewer. A classification proof cannot establish whether the private real-world facts supplied to the agreement are true.

## Pinned proof pipeline

The exact compatibility set is Noir `1.0.0-beta.5`, Barretenberg/bb.js `0.87.4-starknet.1`, Garaga `0.18.2`, Scarb/Cairo `2.16.1`, and Starknet Foundry `0.57.0`. It uses the `UltraStarknetZKHonk` flavor supported by that Garaga release. `toolchains.lock.json`, exact npm versions, and `.github/workflows/proof-artifacts.yml` are authoritative; never mix proof, calldata, VK, or verifier outputs from another set.

```bash
npm run proof:input
cd circuits/payroll_integrity
nargo test
nargo build
nargo execute witness
cd ../..
npm run proof:prove
```

`proof:prove` explicitly requests `starknetZK`, self-verifies before writing any artifact, derives the VK from the same pinned circuit, and generates Garaga calldata only after verification. A non-ZK fallback is forbidden. The previous Noir beta.16/Barretenberg 3.0 Keccak-ZK path produced matching proof-bound and standalone VKs but rejected valid large-circuit proofs because of the upstream large-domain ZK defect; it is intentionally not used.

The proof-root layer uses Poseidon2 for circuit-internal leaves and fixed trees while externally disclosed v1 identity/text commitments and the run nullifier remain canonical Keccak. Native and browser proof generation run on the x64 artifact workflow rather than being inferred from witness execution on a phone. The committed browser artifact is `public/circuits/payroll_integrity-v1.json`; CI compares its semantic circuit fields to a fresh pinned build.
