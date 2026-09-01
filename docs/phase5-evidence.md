# Phase 5 evidence

Status: in progress. This file records evidence, not a completion claim.

## Baseline Mainnet demonstrations

On 2026-09-01 the committed validators queried Starknet Mainnet again and
confirmed all three existing private payroll transactions. Each accepted receipt
contains events from the reviewed live STRK20 pool and PAYO Payroll Seal; the
corresponding run is `proven` and both ordered PayrollIntegrity shards are verified.
Recipient identities and salary values remain withheld.

| Flow | Payroll transaction | Payroll block | Proof blocks | Validator |
|---|---|---:|---|---|
| STRK | `0x345a1be9710d3630915d6cd8279173ce47b198161f4c8a9cb4c64e1fc98fb26` | 13,833,610 | 13,833,625 / 13,833,635 | `npm run verify:payo-strk` |
| Native USDC | `0x18ec86c318d1adcaa61bf145a91ee3ae67ed45dcce85187c5ab8cbfd58e04fd` | 13,852,558 | 13,852,572 / 13,852,587 | `npm run verify:payo-usdc` |
| Mixed STRK + native USDC | `0x7e41fd161a1d034b4d58348b3ee6eb7a4451cd29ce9e05f556cee868e3e510c` | 13,845,714 | 13,845,729 / 13,845,739 | `npm run verify:payo-mixed` |

These three hashes satisfy the public sprint's baseline `strk20.json` transaction
shape. They do **not** replace PAYO's stricter advanced-obligation/autonomous-agent
canary requirement.

## Isolated-signer cutover snapshot

Read-only RPC inspection at Mainnet block 14,187,831 recorded:

- policy account `0x656928a6f3aeb62c2e62ff7457d351a41ed987ceed07c514539165662ecb7e0` has the reviewed class hash `0x282ed1d7682b465e1189877a1286776e0134030a84cef22101be038812bae8a`;
- its current owner is `0x6e3e81271a762ead3ac1efc8c1193397882a7851f10ce7deea7ec83433da8ef` and it is not paused;
- its STRK20 viewing-key registration is zero and its public STRK balance is zero;
- the `payo-policy-signer` Fly application does not yet exist;
- the hosted web has no policy-signer HMAC/public-key or policy-treasury viewing-key secrets and therefore its prematurely enabled autonomous worker fails closed.

The source configuration now keeps the executor disabled until cutover, binds the
private signer to Fly IPv6, and records the cutover ordering in
`docs/PHASE5_RELEASE_PLAN.md`. No Mainnet mutation has been submitted in Phase 5.

The Phase 5 dependency revalidation also removed the SDK's unused vulnerable
Devnet-only downloader chain from production without modifying the pinned SDK
archive. The archive SHA-256 is enforced from `toolchains.lock.json`; a local
replacement fails closed if production code attempts Devnet spawning, and a
source-boundary regression test forbids imports of the SDK testing path. On
2026-09-01 `npm run audit:production` reported 0 critical, 0 high, 0 moderate and
5 low findings. The remaining lows are accepted for this release as the pinned
Garaga verifier's `elliptic` chain; npm's proposed remedy is an incompatible
Garaga downgrade.

The consolidated current Mainnet inventory is published in
`evidence/mainnet-contract-inventory.json` and `docs/MAINNET_CONTRACTS.md`. At
block 14,189,695, `npm run verify:mainnet-contracts` read all 12 live pool,
registry, advanced, exception, SettlementMatch and agent-policy addresses from
RPC and matched every deployed class hash.

`docs/MAINNET_BENCHMARKS.md` consolidates the committed native/browser proof
timings, calldata sizes, historical actual Mainnet deployment fees and current
non-mutating Phase 5 funding/rotation simulations. It deliberately leaves the
treasury-registration and autonomous-canary rows pending until real receipts exist.

## Remaining release evidence

- offline recovery-copy confirmation;
- treasury registration simulation, approval, transaction and read-back;
- public-gas funding simulation, approval and read-back;
- owner rotation simulation, approval, transaction and read-back;
- private signer deployment, attestation and rejection probes;
- exact one-run policy activation and small autonomous Mainnet canary;
- reconciled SettlementMatch receipt and replay rejection;
- advanced/agent transaction added to the public evidence set;
- public contract/hash/benchmark table, video and remaining runbooks;
- clean-clone CI, dependency disposition and `npm run verify:completion`.
