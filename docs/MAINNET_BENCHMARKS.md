# PAYO proof and Mainnet gas benchmarks

Recorded from committed evidence on 2026-09-01. These measurements are not fee
quotes or performance guarantees; hardware, prover load and Starknet pricing
change. FRI is STRK's 10^-18 base unit.

## Proof system

| Proof | Environment | Measured result | Size / memory | Source |
|---|---|---:|---:|---|
| PayrollIntegrity v1, shard 0 | pinned native CI | 47,222 ms | 10,560-byte proof; 3,187 Garaga felts | `docs/phase1-evidence.md` |
| PayrollIntegrity v1, shard 1 | pinned native CI | 46,671 ms | 10,560-byte proof; 3,187 Garaga felts | `docs/phase1-evidence.md` |
| PayrollIntegrity v1, both shards | browser worker | 314,598 ms | 1,817,308 KiB native peak RSS | `docs/phase1-evidence.md` |
| Advanced obligation v2, two shards | application Mainnet-bound runtime | 664,475 ms | 3,223 raw felts per shard | `docs/phase3-evidence.md` |
| Wage claim v6 | application runtime | 35,494 ms | 3,127 verifier calldata felts | `docs/phase3-evidence.md`; `evidence/phase3-wage-claim-mainnet.json` |
| Remediation v7 | application runtime | 38,961 ms | 3,127 verifier calldata felts | `docs/phase3-evidence.md`; `evidence/phase3-wage-claim-mainnet.json` |
| SettlementMatch v8 | hosted native prover | 143,281 ms | 3,247 proof calldata felts; 11 public inputs | `docs/phase4-evidence.md`; `evidence/phase4-mainnet-deployment.json` |

PayrollIntegrity's measured backend circuit size is 864,348, within its enforced
2^20 domain. Advanced v2 remains below the 5,000-felt Starknet transaction limit;
SettlementMatch enforces a 4,992-felt application ceiling. Proofs are randomized,
so valid proof/calldata hashes are not expected to repeat.

## Historical Mainnet deployment gas

| Operation | Actual fee (FRI) | Approx. STRK | Source |
|---|---:|---:|---|
| Advanced v2 verifier declaration | 142419986649573403283 | 142.419987 | `evidence/phase3-v2-mainnet-upgrade.json` |
| Advanced v2 verifier/bundle deployment | 82951309305894383 | 0.082951 | same |
| Advanced v2 registry activation | 41960643943093529 | 0.041961 | same |
| Snapshot v5 verifier declaration | 153082628044146254459 | 153.082628 | `evidence/phase3-wage-claim-mainnet.json` |
| Claim v6 verifier declaration | 153767346893808566971 | 153.767347 | same |
| Remediation v7 verifier declaration | 153274323086315142780 | 153.274323 | same |
| Exception seal declaration | 95541641679958486332 | 95.541642 | same |
| v5/v6/v7/seal deployment | 158956734979101236 | 0.158957 | same |
| v5/v6/v7 activation | 221992407013731012 | 0.221992 | same |
| SettlementMatch v8 declaration | 146132065078799913307 | 146.132065 | `evidence/phase4-mainnet-deployment.json` |
| Agent payroll seal declaration | 39758384700543421851 | 39.758385 | same |
| Policy account declaration | 52960442400965346779 | 52.960442 | same |
| Phase 4 three-contract deployment | 188646064251877865 | 0.188646 | same |
| Settlement verifier-profile activation | 83904085329347585 | 0.083904 | same |

Declarations dominate historical cost because generated verifier classes are
large. Phase 5 reuses these deployed contracts; the isolated-signer cutover does
not redeclare or redeploy them.

## Current Phase 5 simulations

| Operation | Simulated fee (FRI) | Approx. STRK | Mutation |
|---|---:|---:|---:|
| Transfer a 0.5 STRK public gas target to policy account | 134948639218101345 | 0.134949 | no |
| Rotate policy-account owner | 84362292296331120 | 0.084362 | no |

The funding operation additionally transfers exactly 0.5 STRK; its fee is paid
by the relayer. Both values must be freshly simulated again immediately before
human approval. Treasury registration and the autonomous canary will be added
only after their final simulations and accepted receipts exist.

Ready private-payroll receipts intentionally do not expose a trustworthy
plaintext token/amount breakdown. PAYO therefore does not invent a payroll gas
number from visible privacy-fee recovery events. The autonomous canary will
record public gas and a privacy-safe private balance delta separately.
