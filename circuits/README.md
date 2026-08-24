# PAYO circuits

`payroll_integrity` is PAYO's deployment-bound v1 private calculation circuit. It binds fixed 64-leaf authoritative-agreement and payroll-manifest trees and permits at most 50 real obligations.

To keep the proof domain within `2^20` without weakening coverage, one payroll run is proved as two linked shards against one circuit and one verification key:

- shard 0 authenticates agreement leaves 0–25 and payroll leaves 0–24;
- shard 1 authenticates agreement leaves 24–49 and payroll leaves 25–49;
- the two-agreement overlap proves the private global sorting boundary;
- both proofs expose identical deployment fields and roots; their final public input is respectively `0` and `1`.

Each shard exposes 17 public inputs: chain ID, PAYO seal address, proof/schema versions, agreement/manifest/policy/FX roots as high/low `u128` limbs, the run-nullifier limbs, validity start/expiry, and the shard index. The Payroll Seal requires the ordered 34-input bundle and rejects missing, duplicate, reordered, or root-mismatched shards.

The private witness proves one-to-one coverage of every due agreement, sorted unique agreement identifiers, canonical padding, committed recipient/earnings/token/schedule terms, bounded policy execution, deductions and net arithmetic, classification consistency, token and quote decimals, FX source-count/freshness/floor rules, and explicit final-pay components. TypeScript/Noir golden tests cover the agreement, policy, FX, payroll-leaf, empty-leaf, and nullifier encodings.

This is a consistency proof, not a legal opinion. Reference policy catalogs must be reviewed by an authorized professional before activation.

## Pinned proof pipeline

The exact compatibility set is:

- Noir `1.0.0-beta.16` (`noirc` commit `2d46fca7203545cbbfb31a0d0328de6c10a8db95`);
- native Barretenberg `3.0.0-nightly.20251104`;
- Garaga `1.1.0`;
- Scarb/Cairo `2.16.1`; and
- Starknet Foundry `0.57.0`.

Proofs use ZK UltraHonk with a Keccak transcript (`ultra_keccak_zk_honk`). Circuit-internal leaves and tree nodes use domain-separated BN254 Poseidon2. The Keccak transcript is required by the generated Garaga verifier; a non-ZK fallback is forbidden.

```bash
npm run proof:input

cd circuits/payroll_integrity
nargo test
nargo build
nargo execute witness-shard-0 --prover-name Prover
nargo execute witness-shard-1 --prover-name Prover-shard-1
cd ../..

npm run proof:prove
cd contracts/integrity_verifier
scarb build
snforge test
```

`proof:prove` invokes the pinned native `bb`, generates both proofs in low-memory mode, verifies each proof independently, requires the same VK and first 16 public inputs, validates shard indices 0/1, and emits the inner Garaga calldata felts. The generated Cairo suite verifies each proof and the uninterrupted real-proof → bundle verifier → Payroll Seal path.

Current proof-bound measurements:

- ACIR opcodes: `206,987`;
- backend circuit size: `864,348` (`log_circuit_size = 20`);
- proof size: `10,560` bytes per shard;
- public inputs: `17` per shard;
- Garaga calldata: `3,187` inner felts per shard;
- VK file SHA-256: `d622dff7f86da80f1b9e2fae58d4aee071d2fdec5ae018bcec353a6ce8941d96`;
- Garaga VK hash: `0x083a0b53dfd5611364613319f15de9b3c9b42568586814e371a71608f95b47b4`.

The committed browser artifact is `public/circuits/payroll_integrity-v1.json`; its SHA-256 is pinned in `lib/proof/protocol.ts`. CI rebuilds the circuit, enforces the `2^20` gate budget, regenerates both witnesses/proofs/calldata and the verifier source, runs the real Cairo integration, and finally proves both shards inside the browser Web Worker.
