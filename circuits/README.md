# PAYO circuits

`payroll_integrity` is the deployment-bound v1 private calculation circuit. It binds fixed 64-leaf authoritative-agreement and payroll-manifest trees and permits at most 50 due obligations. The circuit has 16 public inputs:

1. Starknet chain ID, PAYO seal address, proof version, and schema version;
2. agreement, manifest, policy-catalog, and FX-catalog roots as high/low `u128` limbs;
3. a circuit-derived run nullifier as high/low limbs; and
4. validity start and expiry.

The private witness proves one-to-one coverage of every due agreement, sorted unique agreement identifiers, canonical padding, committed recipient/earnings/token/schedule terms, bounded policy execution, deductions and net arithmetic, classification consistency, token and quote decimals, source-count and freshness rules, deterministic FX floor rounding, and explicit final-pay components. Agreement-term, policy-program, FX-snapshot, payroll-leaf, and nullifier encodings have TypeScript/Noir golden tests. V1 normalizes USD and GBP floors to six reference-currency decimals and rejects any other quote scale.

The circuit is deliberately a consistency proof, not a legal opinion. A policy catalog must be reviewed and activated by the organization or its authorized reviewer. A classification proof cannot establish whether the private real-world facts supplied to the agreement are true.

## Pinned proof pipeline

The exact compatibility set is Noir `1.0.0-beta.16`, Barretenberg `3.0.0-nightly.20251104`, Garaga `1.1.0`, Scarb/Cairo `2.16.1`, and Starknet Foundry `0.57.0`. `toolchains.lock.json`, exact npm versions, and `.github/workflows/proof-artifacts.yml` are authoritative; never mix proof, calldata, VK, or verifier outputs from another set.

```bash
npm run proof:input
cd circuits/payroll_integrity
nargo test
nargo build
nargo execute witness

bb write_vk --scheme ultra_honk --oracle_hash keccak \
  -b target/payo_payroll_integrity.json -o target
bb prove --scheme ultra_honk --oracle_hash keccak \
  -b target/payo_payroll_integrity.json -w target/witness.gz -k target/vk -o target
bb verify --scheme ultra_honk --oracle_hash keccak \
  -k target/vk -p target/proof -i target/public_inputs
```

This Barretenberg release generates zero-knowledge UltraHonk proofs by default; `--disable_zk` is never used. The artifact runner supplies bounded swap because this circuit's normal prover path needs substantially more memory than a standard hosted runner provides.

The pinned circuit reports 622,777 ACIR opcodes. Native and browser proof generation therefore run on the x64 artifact workflow rather than being inferred from witness execution on a phone. The committed browser artifact is `public/circuits/payroll_integrity-v1.json`; CI compares its semantic circuit fields to a fresh pinned build.
