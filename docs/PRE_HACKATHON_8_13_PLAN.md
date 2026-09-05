# Pre-hackathon privacy, vesting and compliance plan

Status: active implementation target. This plan extends the completed local/Devnet
VestingBook work before its first Mainnet deployment. The existing Mainnet fee
estimate and deterministic v3 addresses become stale if the circuit, verification
key or contract artifacts change and must be regenerated before deployment.

## 1. Universal, accountable private payroll book

Status: **cleared locally/Devnet; Mainnet v3 topology deployed, activated and
proof-verified on 2026-09-05; live book canary remains Block 6.**
Evidence: `evidence/universal-payroll-book-private-devnet.json`, 25 focused
TypeScript tests, 14 VestingBook Cairo lifecycle tests and 5 real generated-verifier
composition tests.

- Route every new ordinary, vesting, agent, claim and remediation settlement through
  one versioned book finalization path.
- Make finalization atomic: consume the relevant nullifier, advance any vesting state,
  append exactly one entry and update proof-bound contributor counts and optional
  disclosed STRK/USDC period totals.
- Reject bypass, duplicate, reordered, stale-state and cross-tenant entries.

## 2. Worker-controlled statements

Status: **cleared locally/browser on 2026-09-05; Mainnet live-book canary remains
Block 6.** Evidence: `lib/crypto/reporting-identity.test.ts`,
`lib/client/payroll-report-workflow.test.ts`,
`lib/disclosure/payroll-book-report.test.ts`, and
`evidence/phase3-devnet-fixtures/rendered-browser-ui-origin.json` (16 focused tests
plus the Linux Chromium production-control flow).

- Let a direct STRK20 viewing-key holder derive a reporting identity and independently
  generate their own book-bound income statement.
- Preserve PAYO X25519 recipient identities as the explicit Ready-wallet fallback;
  never imply that Ready exposes its viewing key when it does not.
- A worker can open only their own lines; employer and tax scopes remain separately
  authorized.

## 3. Familiar tax evidence and policies

Status: **cleared locally/browser on 2026-09-05; Mainnet live-book export remains
Block 6.** Evidence: `lib/disclosure/tax-evidence.test.ts`,
`lib/disclosure/payroll-book-report.test.ts`,
`lib/client/payroll-report-workflow.test.ts`,
`lib/policy/reference-packs.test.ts`, and
`evidence/phase3-devnet-fixtures/rendered-browser-ui-origin.json` (18 focused tests,
706-test application regression, Linux Chromium production-control flow, typecheck,
lint and production build).

- Define one canonical verified income schema and render W-2-, P60- and T4-style
  evidence exports from it. These are not official filings or legal advice.
- Add versioned US, UK and Canadian reference policy packs and bind the exact policy
  identifier/root used for every line and report.
- A report must reconstruct every disclosed line and the complete on-chain period
  accumulator; omission, duplication, mutation and policy substitution fail closed.

## 4. External fact attestations

Status: **cleared locally/browser/Devnet; Mainnet v3 topology deployed, activated and
proof-verified on 2026-09-05; live canary remains Block 6.** Evidence:
`evidence/vesting-tax-devnet.json`, `evidence/vesting-tax-mainnet.json`,
`evidence/block4-external-attestation-browser.json`, 40 focused TypeScript tests,
4 Noir tests, 2 catalog-registry Cairo tests, 2 real generated-verifier tests and
5 production VestingBook composition tests. The complete application regression is
707 passing tests with clean typecheck, lint and production build.

- Accept domain-separated issuer-signed commitments for residency, employment and
  tax status, with subject binding, validity window, nonce and revocation state.
- Commit an approved issuer root through the existing versioned policy/catalog path
  where sound; deploy a separate registry only if the security model cannot be kept
  explicit there.
- Bind credential membership and status into the v3 proof without revealing the
  credential contents.

## 5. Private exit boundary

Status: **cleared locally/browser/upstream on 2026-09-05; reviewed Mainnet instance
and tiny live canary remain Block 6.** Evidence:
`evidence/block5-private-exit-browser.json`,
`evidence/block5-private-exit-upstream.json`, 8 focused PAYO tests, 3 upstream
anonymizer tests, 1 STRK20 open-note composition test, lint and production build.

- Integrate an existing STRK20-compatible private swap route instead of creating a
  new exchange.
- Preserve encrypted-note privacy while the asset stays on supported private rails.
- Warn before any public withdrawal or unsupported destination; PAYO must not promise
  privacy after a user deliberately exits to a publicly linkable address.

## 6. Release gate

Release preparation on 2026-09-05: the pinned upstream anonymizer class and exact
`privacy_invoke` ABI were read back on Mainnet, the deterministic empty-constructor
instance address is unoccupied, and the latest guarded read-only deployment
simulation estimated **0.083765866841584179 STRK** on 2026-09-05. Evidence:
`evidence/private-exit-mainnet-plan.json`. No mutation was submitted.

The final 58-public-input VestingBook topology was declared, atomically deployed and
activated on Mainnet on 2026-09-05. The three class hashes, five-field immutable seal
wiring and proof-version-3 registry profile match the reviewed plan. A read-only call
through the deployed verifier and bundle accepted the real ordered proof pair and
rejected reversed shards. Declarations, deployment and activation consumed exactly
**227.876862512710972474 STRK**, leaving **278.089224220459129477 STRK** at the final
read-back. Evidence: `evidence/vesting-tax-mainnet.json`. The deliberately small live
vesting/book/export canary and the separate private-exit Mainnet instance/canary remain
pending and require explicit approval.

- Freeze the final public statement before generating the Noir VK or Garaga verifier.
- Pass positive and negative TypeScript, PostgreSQL, Noir, Cairo, real-proof
  composition, Devnet and Linux Chromium gates.
- Regenerate the deterministic Mainnet plan and fee estimate from fresh artifacts.
- Obtain explicit user approval before every Mainnet declaration, deployment,
  activation or canary transaction.
- Deploy once, read back all class hashes and immutable wiring, then record tiny live
  ordinary-payroll, vesting, book-export and private-exit evidence.

Hackathon completion means a working, cryptographically bound demonstration of these
flows. It does not mean government e-filing certification, exhaustive worldwide tax
law coverage or privacy after leaving supported private rails.
