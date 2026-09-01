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

## Isolated-signer cutover

The Phase 5 cutover was performed on 2026-09-01 with autonomous dispatch kept
disabled. Every transaction below was simulated immediately before explicit
approval and then independently read back from Starknet Mainnet:

| Operation | Transaction | Block | Actual transaction fee |
|---|---|---:|---:|
| Fund policy account with exactly 20 public STRK | `0x18efc86065b91fe73dd7dad9085cb08c5b9806a494d6bbfb2f68f7515635026` | 14,194,477 | 0.055514240023138569 STRK |
| Register treasury viewing identity and approve a bounded pool allowance | `0x7b50b46e25bea43603126596554f86c465175ced90c2fe1496f1a9372a1dbcb` | 14,195,201 | 2.689681523546163560 STRK |
| Rotate policy-account owner to the isolated signer | `0x24acdfaeb99b97f1291c7d17619e3ff591e3a9631eed7143c5a5d3604e1c881` | 14,195,417 | 0.034535746559995256 STRK |

The registration call paid the live 6 STRK pool fee in addition to its
transaction fee. Its final read-back matched treasury public key
`0xf7ea4ef939f75b1777390f719836dcf652d070c503d07fe7bc7c7ba9b54f04`,
left a deliberately bounded 12 STRK pool allowance, and left
11.310318476453836440 public STRK on the policy account. The owner rotation's
final read-back matched
`0x18e71b3a12c6b6aeecdb4d2cbcf59f143acf5547371750c23e828082b839cc1`.
The offline owner recovery copy was confirmed before rotation.

The private `payo-policy-signer` Fly application is now deployed from image
`deployment-01M1E8SHYAHS0C0XFGBW8AREQB`. Machine `784e4dea051028` is healthy
in `sin`; it has no public HTTP service and is reachable only over Fly 6PN.
The hosted web read `/health` through the private network and received the exact
rotated owner public key. Live rejection probes returned 401 for missing HMAC,
400 for an authenticated malformed policy, 401 for replay of the same nonce,
and 404 for an unknown route. The web holds the treasury viewing key and signer
client material, but not the policy-owner key. Its executor remains explicitly
disabled, so human Ready payroll remains the default while the canary is pending.

At Mainnet block 14,195,790, the complete inventory verifier matched all 12 live
pool, registry, verifier, seal and policy-account class hashes. The owner and
treasury status verifiers independently matched the rotated owner and registered
viewing key.

`npm run verify:phase5-cutover` independently replays all three receipts and
historical read-backs: funded balance, registered viewing key, bounded pool
allowance, rotated owner, pause state and deployed class hash. It also fails if
the evidence discloses the private funding amount or enables the executor early.

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
timings, calldata sizes, historical actual Mainnet deployment fees and accepted
Phase 5 cutover receipts. It deliberately leaves only the autonomous-canary row
pending until a real reconciled receipt exists.

At Mainnet block 14,196,362, direct SDK discovery indexed private STRK funding
for the isolated policy treasury. Public evidence records only that the funding
was indexed and its observation block; the private amount remains undisclosed.

## Remaining release evidence

- exact one-run policy activation and small autonomous Mainnet canary;
- reconciled SettlementMatch receipt and replay rejection;
- advanced/agent transaction added to the public evidence set;
- public contract/hash/benchmark table, video and remaining runbooks;
- clean-clone CI, dependency disposition and `npm run verify:completion`.
