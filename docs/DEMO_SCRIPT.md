# PAYO three-minute demo script

Target length: 2:50–3:00. Record Mainnet with tiny values; hide notifications,
wallet totals, recovery material, recipient identities and private package data.

## 0:00–0:20 — Problem and one-liner

Show Overview.

> Global payroll leaks salaries and still cannot prove every worker was paid
> correctly. PAYO is private, proof-carrying payroll for humans and AI agents:
> pay in STRK or native USDC, prove the rules, reveal only what each party needs.

Point to shielded balances and the plain 2D interface. Do not open a wallet
history containing unrelated transactions.

## 0:20–0:55 — Agreement intelligence

Show Team and one prepared contributor. Briefly open the advanced agreement:

- private amount and payout identity;
- statutory/policy commitment;
- FX floor or classification commitment;
- recurring, milestone or final-pay plan.

Say that PAYO encrypts records in the browser and commits only roots/predicates;
it does not put salary plaintext onchain.

## 0:55–1:35 — Human private payroll

Show a prepared STRK/native-USDC payroll and its preview. Highlight:

- real wallet balance and fee readiness;
- fixed-capacity completeness proof;
- Ready human approval as the default;
- private settlement and two onchain verifier shards.

Use an already completed Activity receipt to avoid waiting for a new proof while
recording. Show `confirmed`, `proven` and the explorer link, but explain that the
public receipt cannot reveal recipient, salary or private token details.

## 1:35–2:15 — Bounded AI-agent payroll

Show Team capability controls and the MCP tool list. Highlight one exact,
short-lived, one-call capability: allowed token, recipient/run commitment,
maximum amount, purpose, period and expiry. Then show the completed Phase 5
autonomous canary receipt.

Explain:

> The agent never receives a wallet key or arbitrary transaction signer. An
> isolated private-network signer accepts only canonical STRK20 proof actions;
> the policy account enforces the committed limits onchain, and replay fails.

Show the canary's finality, SettlementMatch `FINALIZE`, redacted private balance
delta and revoked/expired policy. Never expose the viewing or owner key.

## 2:15–2:42 — Selective disclosure and wage remedy

Show Activity. Open the Proof Package Inspector or an existing bound wage claim.
Point to a readable scope such as employer/auditor and the condition label
`Missing obligation`, `Below FX floor` or `Incomplete final pay`.

Explain that the recipient decrypts locally, verifies commitments/onchain proof,
and can link a proved shortfall to private remediation without revealing the
whole payroll.

## 2:42–3:00 — Evidence and close

Show the active contract/evidence section or GitHub README:

- STRK, native USDC and mixed Mainnet transactions;
- live generated Noir/Garaga verifiers and PAYO seals;
- current Mainnet contract inventory and proof benchmarks.

Close with:

> PAYO turns payroll from a public spreadsheet or blind transfer into a private,
> recoverable and selectively verifiable protocol—for people and autonomous agents.

After upload, place the HTTPS video URL in `strk20.json`, run
`npm run verify:strk20`, and retain the final unedited source recording privately.
