# Multi-tenant PAYO Mainnet evidence

Observed on Starknet Mainnet on 2026-08-27. The source deployment is commit
`1329e06c9c7177656f31e650c901fefcbb0de30c` plus the restart-safe verification
fix recorded immediately after deployment.

## Contracts

| Component | Address | Class hash |
|---|---|---|
| Policy/FX/verifier registry | `0x34701f573096b7bab0e5678e1ed2f17a87c8d56eb5f4d70bcf2197bab8e4477` | `0x6366141e5ae47f2e170409c6babaa4d6ae220b5b255f8dcbf9b0173f8681cfd` |
| Tenant obligation registry | `0x44b22f1a17d2710c2f51ed0b37b8b0ff8435262d3c8c0f2f17be07c84ac23b5` | `0x50ac78b67fd69d7e2a892dc51014159d7e69fe1770c3f4f33add21131aa2a0b` |
| Payroll seal | `0x603c607bf001e279365fd141901ba09b95f72f5a72506742b30f6db32c36ac7` | `0x1500b1e66ef8c1528f5ea301cbb0420b28a19742d927c5d595ce567b0266148` |

The seal read-back binds the existing live STRK20 pool, the policy registry,
the tenant obligation registry, and `SN_MAIN`. The registry read-back binds
proof profiles `(PRECOMMIT,v1)`, `(PRECOMMIT,v2)`, `(CLAIM,v3)`, and
`(REMEDIATE,v4)` to the previously verified verifier bundles.

## Transactions

| Action | Block | Transaction | Actual fee |
|---|---:|---|---:|
| Declare tenant registry | 13,935,727 | [`0x3011…0ad7`](https://starkscan.co/tx/0x3011e50f7a04e1994590051b4908ab4a698f1ba8907848d6999aa093f300ad7) | 7.805420234702978 STRK |
| Deploy three deterministic instances | 13,935,751 | [`0x0f09…0af5`](https://starkscan.co/tx/0x0f095258e3561312e41380ab914f2e3572a43605e4fcf33b679363351f90af5) | 0.201305349118029689 STRK |
| Activate baseline and four verifiers | 13,935,798 | [`0x1844…5514`](https://starkscan.co/tx/0x1844c318bd6bcd9faad325c4b56f4e1a1b740cc33bdbea6ad38dd33516a5514) | 0.320507846279543494 STRK |

Total actual fee: **8.327233430100551 STRK**.

## Verification

`npm run multitenant:mainnet:verify` passed independently at block 13,935,809.
Its 19 checks covered:

- exact class hashes for all three new instances;
- deployed STRK20 pool and all four verifier bundles;
- policy administrator, FX publisher, and emergency administrator;
- immutable seal pool and registry bindings;
- baseline policy-root activity;
- exact active verifier address for every proof mode/version.

This evidence proves deployment and configuration. A small payroll signed by a
non-relayer Ready account remains the required browser cutover test; it must not
be inferred from administrative deployment receipts.
