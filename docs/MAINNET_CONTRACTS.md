# Active PAYO Mainnet contracts

This is the current application topology, not a security-audit claim. Run
`npm run verify:mainnet-contracts` to compare every address with Starknet RPC at
one recorded latest block. The machine-readable source is
`evidence/mainnet-contract-inventory.json`.

| Component                      | Address                                                             | Class hash                                                          |
| ------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| STRK20 privacy pool (external) | `0x40337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a` | `0x67dddd89d80fedadc06b6f160798f94800a4a70164e5a24301cd0d6076b554d` |
| Policy registry                | `0x34701f573096b7bab0e5678e1ed2f17a87c8d56eb5f4d70bcf2197bab8e4477` | `0x6366141e5ae47f2e170409c6babaa4d6ae220b5b255f8dcbf9b0173f8681cfd` |
| Obligation registry            | `0x44b22f1a17d2710c2f51ed0b37b8b0ff8435262d3c8c0f2f17be07c84ac23b5` | `0x50ac78b67fd69d7e2a892dc51014159d7e69fe1770c3f4f33add21131aa2a0b` |
| Advanced verifier v2           | `0x6845068feb530dbac0e730532df5fefb744c5caf4e1769e642bf1aec63ee043` | `0xee7996f9fed69e8cb7248327c4391ca5847faa297926bf33592b7022520ba3`  |
| Advanced bundle v2             | `0xeba326f15f73968026bd12007220d88104fdcb322a56ad8c69fbe8a5350e18`  | `0x451e59b2f2e454a5a53914ca317069d84faf504498e1d56609a78fb626da2bc` |
| Snapshot verifier v5           | `0x6ff3b2b74fe14c70bf96bf274c75ec78f2ab346cc6a359410b15d2baf2c1d4e` | `0x14e6a1f1ec3746db2d488a52164d5de818d76ac47c679cf04791d69a88333a2` |
| Wage-claim verifier v6         | `0x6258a5dd16d03e73f13b2f4e653a9f7675ddfbcacfc5e923c53438ec957b9d4` | `0x2ff425a9cf03c287f46cb82efc5242ccd953daf3d41aca214dd05219f8ecc34` |
| Remediation verifier v7        | `0x25ec16cca6a625bb89aa3f0cdd279c84f569d4dada9f857ba4c5efb1750fdf9` | `0x6fc8b2a2ff20b7be7627222e0c50562af57c0a80f4fe63ed6cd674e0db791f9` |
| Current exception/payroll seal | `0x3394e58bb2bb294e0ae92514079a1394c6c66eae8a6c033a6f7f449b1d12ce`  | `0x612f04ea11fd47f83793efee058a9ddd1380b03fe1273fe9fab13ff58b3a3b`  |
| SettlementMatch verifier v8    | `0x4e45d14e253cb845144711a81f4e6b9945e910da487e8f291f4a0ec84567060` | `0x17ecc3317283c824c542e0aa059cbfe498475bf1063f374654d0c05f647657a` |
| Agent payroll seal             | `0x1b0208114f33ea0ac800f6474307680a0cf239d13ac11818523f70cba49c84a` | `0x760530190cc8c5851d16325ba45c4c4604f8c7636ea8cca8702775646b36c84` |
| Agent policy account           | `0x656928a6f3aeb62c2e62ff7457d351a41ed987ceed07c514539165662ecb7e0` | `0x282ed1d7682b465e1189877a1286776e0134030a84cef22101be038812bae8a` |

The web's ordinary human payroll flow uses the current exception/payroll seal.
Advanced v2 remains active in the policy registry; Snapshot v5, Claim v6 and
Remediation v7 serve the bound wage-exception lifecycle. Autonomous direct-SDK
settlement uses the separate agent seal, SettlementMatch v8 verifier and policy
account. Historical deployment addresses remain in their phase evidence files;
they are not silently presented as the current frontend topology.

Mainnet source/read-back evidence:

- `evidence/phase3-v2-mainnet-upgrade.json`
- `evidence/phase3-wage-claim-mainnet.json`
- `evidence/phase4-mainnet-deployment.json`
- `docs/phase5-evidence.md`

## Active vesting and compliance-book topology

These reviewed deterministic addresses were declared, atomically deployed and activated
on Mainnet on 2026-09-05. `evidence/vesting-tax-mainnet-plan.json` preserves the
immutable pre-deployment plan; `evidence/vesting-tax-mainnet.json` records receipts and
read-back, and `evidence/vesting-tax-hosted-rollout.json` records the web/prover wiring.

| Component                     | Deterministic address                                               | Current state                       |
| ----------------------------- | ------------------------------------------------------------------- | ----------------------------------- |
| VestingTransition verifier v3 | `0x4b35d2d366848169ea4fb32d4fffda498b5251160da2e60fc53030a37d5551c` | Declared and deployed               |
| VestingTransition bundle v3   | `0x1bc7517191802bf82ccfb60fa4f27f9306d6cfee9160b545d7dea662e8870a8` | Deployed; active profile `0/3`      |
| VestingBook state/book seal   | `0x5208cc07cb4153235ab5c6ecd1936ee77f9be7a2ea09f6cc69518a6362493f`  | Deployed and wired to web + prover  |

The conservative pre-deployment simulation estimated 600.472824438987809664 STRK;
the recorded declaration/deployment/activation total was exactly
227.876862512710972474 STRK. The tiny live vesting/book/tax-export canary remains
pending and is not authorized merely by documenting this topology.

## Planned private-exit instance

The reviewed upstream `EkuboSwapAnonymizer` class is already declared on Mainnet.
PAYO therefore needs one deterministic empty-constructor instance, not another class
declaration.

| Candidate component | Deterministic address | Class hash | Current state |
| --- | --- | --- | --- |
| STRK20 Ekubo anonymizer | `0x6737a6cdde0e0c4f39d88ec7301e1db8d7c46ffed35ade0ee9a56ed87ab784` | `0x2a4ac595283d4d64b9952f5ef5c0da1775bfdb7c9d92237524a21dd8d19ebd7` | Class declared; instance undeployed |

`evidence/private-exit-mainnet-plan.json` binds the upstream revision, source and
artifact hashes, deterministic salt, empty constructor, exact ABI readback and
read-only fee simulation. The latest 2026-09-05 estimate is
0.083765866841584179 STRK. Together with the VestingBook estimate, the reviewed
deployer is short 94.590503572659291892 STRK before fee drift and live canaries.
Deployment, hosted configuration and a tiny Ready-wallet canary still require
separate immediate user approval.
