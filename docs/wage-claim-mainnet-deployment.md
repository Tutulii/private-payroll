# Wage-Claim vNext Mainnet deployment

Deployed and independently read back on Starknet Mainnet on 2026-08-29.
The canonical machine evidence is
`evidence/phase3-wage-claim-mainnet.json`.

## Active topology

| Component | Address | Profile |
| --- | --- | --- |
| Snapshot v5 verifier | `0x6ff3b2b74fe14c70bf96bf274c75ec78f2ab346cc6a359410b15d2baf2c1d4e` | mode 0, version 5 |
| Claim v6 verifier | `0x6258a5dd16d03e73f13b2f4e653a9f7675ddfbcacfc5e923c53438ec957b9d4` | mode 2, version 6 |
| Remediation v7 verifier | `0x25ec16cca6a625bb89aa3f0cdd279c84f569d4dada9f857ba4c5efb1750fdf9` | mode 3, version 7 |
| Exception vNext seal | `0x3394e58bb2bb294e0ae92514079a1394c6c66eae8a6c033a6f7f449b1d12ce` | payroll, snapshot, claim and remediation |

The existing policy registry remains
`0x34701f573096b7bab0e5678e1ed2f17a87c8d56eb5f4d70bcf2197bab8e4477`;
the tenant obligation registry remains
`0x44b22f1a17d2710c2f51ed0b37b8b0ff8435262d3c8c0f2f17be07c84ac23b5`.

## Receipts and cost

- Snapshot declaration: `0x2ee211219b023934cd38225892edcafe12c9d5088dccb442f180193a874a0b1`
- Claim declaration: `0x51ae214e24dffafd6bd587cb0680baa461b593a7fc84822a012eb32b0412f6b`
- Remediation declaration: `0xac74ff79461478434274bbf39c7be12b10c99add241a7f436ec8a241c2c6d4`
- Seal declaration: `0x19d8e72e0301bc30ac19dd309b32b5753cd6995a3a37c62bece8d0e8ac455a3`
- Atomic four-contract deployment: `0x2b6642ad06e55e956f82fc05259a3319436f009436fb610da06a7543f0bd5f5`
- Registry activation: `0x3d0153e2bcd11d46dd526677611cf7f8f54cd794d9b6a884b4d0cb7f1692be5`

Total actual fee was `556.046888846221282790 STRK`.

## Verification result

At frozen block `14041891`, all four declarations existed, every deployed
address contained its reviewed class hash, all three registry profiles pointed
to the expected verifier, and PayrollIntegrity v2 remained active. Snapshot
v5, Claim v6 and Remediation v7 accepted their real proof fixtures and rejected
one-bit-tampered calldata.

This is deployment evidence, not the P3-06 completion claim. P3-06 remains
partial until the hosted web and prover use this seal and one browser-origin
Mainnet claim/remediation cycle is recorded through reconciled private payment.
