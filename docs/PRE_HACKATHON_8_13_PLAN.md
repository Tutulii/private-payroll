# Pre-hackathon privacy, vesting and compliance plan

Status: evidence checkpoint updated 2026-09-07. The vesting, universal-book,
worker-statement and private tax-reviewer scope has completed local, Devnet, hosted
and Mainnet canary gates. The reviewed private-exit instance and autonomous-agent
Mainnet canaries remain separate Phase 5 work. Any future contract artifact change
still requires a regenerated deterministic plan and fresh simulation.

## 1. Universal, accountable private payroll book

Status: **complete for the defined scope. Mainnet v3 topology was deployed,
activated and proof-verified on 2026-09-05; the live vesting/book canary passed on
2026-09-06.** Evidence: `evidence/universal-payroll-book-private-devnet.json`,
`evidence/vesting-tax-mainnet.json`,
`evidence/vesting-tax-mainnet-canary-2026-09-06.json`, 25 focused TypeScript
tests, 16 VestingBook Cairo lifecycle tests and 5 real generated-verifier
composition tests.

- Route every new ordinary, vesting, agent, claim and remediation settlement through
  one versioned book finalization path.
- Make finalization atomic: consume the relevant nullifier, advance any vesting state,
  append exactly one entry and update proof-bound contributor counts and optional
  disclosed STRK/USDC period totals.
- Reject bypass, duplicate, reordered, stale-state and cross-tenant entries.

## 2. Worker-controlled statements

Status: **complete for the defined scope. Cleared locally/browser on 2026-09-05;
a worker-controlled statement was generated and reopened against the verified live
Mainnet book on 2026-09-06.** The recipient-encrypted output remains private.
Evidence: `lib/crypto/reporting-identity.test.ts`,
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

Status: **complete for the defined scope. Cleared locally/browser on 2026-09-05;
tax-reviewer disclosure was generated and opened against the verified live Mainnet
book on 2026-09-06.** The reviewer-encrypted output remains private. Evidence:
`lib/disclosure/tax-evidence.test.ts`,
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

Status: **cleared locally/browser/Devnet; Mainnet v3 topology deployed, activated
and proof-verified on 2026-09-05. The live vesting canary passed on 2026-09-06;
no separate live issuer-credential canary is claimed.** Evidence:
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
**227.876862512710972474 STRK**.

The approved vesting canary succeeded on 2026-09-06 in transaction
`0x06aea439656addfd17b315879696f0ace3880d9878ec01221033ee367d0deaf1`
at block `14461163`. Read-back confirmed the exact next state, consumed release
nullifier, book entry index 2 of 3 and complete accumulator root
`0x7939168b2e65494379eec64d0885403ee78d4a5170f365cd15d2234f120a0b1`.
Evidence: `evidence/vesting-tax-mainnet.json` and
`evidence/vesting-tax-mainnet-canary-2026-09-06.json`. The private-exit Mainnet
instance/canary remains pending and requires separate explicit approval.

The exact v3 VestingBook seal is pinned into both the hosted PAYO web release and
self-hosted prover. Both Fly machines are started, both health endpoints pass, the
served payroll bundle contains the reviewed Mainnet address and advanced payroll fails
closed if that address is absent. Evidence:
`evidence/vesting-tax-hosted-rollout.json`. The original live Ready callback required
manual transaction-hash recovery. Commit `ffdd3a1` deploys exact dual-seal event
recovery, completed-v3 authorization recognition and idempotent encrypted vesting-state
advancement. Its focused recovery tests and Linux Phase 3 browser regression pass; a
second paid run has not re-exercised that callback on Mainnet.

- **Complete:** freeze the public statement and generate the matching Noir VK and
  Garaga verifier.
- **Complete:** pass positive and negative TypeScript, PostgreSQL, Noir, Cairo,
  real-proof composition, Devnet and Linux Chromium gates.
- **Complete:** deploy once and read back all class hashes, wiring and active profile.
- **Complete:** record and independently verify the approved live vesting/book canary.
- **Pending separately:** deploy and test the reviewed private-exit instance and
  complete the autonomous-agent Mainnet canary, each with fresh simulation and
  immediate explicit approval.

Hackathon completion means a working, cryptographically bound demonstration of these
flows. It does not mean government e-filing certification, exhaustive worldwide tax
law coverage or privacy after leaving supported private rails.
