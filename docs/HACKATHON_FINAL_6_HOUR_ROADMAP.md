# PAYO final six-hour roadmap

Status: **FINAL CODE-TO-ROADMAP AUDIT COMPLETE · SIGNED SWAP CANARY PASSED · REPOSITORY-WIDE RELEASE GATE OPEN**
Timebox: **6 hours from implementation start**
Release boundary: **local production review first; Fly.io deployment and GitHub push occurred only after the user's later approval**

## Objective

Turn PAYO's existing private payroll, complete-book verification, worker statements and familiar tax views into one compact, judge-readable release for:

- an authorized tax reviewer;
- employees opening their own evidence;
- contractor and grant networks;
- DAO treasury accountability;
- governance committee disclosure; and
- private compensation for on-chain companies.

This timebox produces a credible **government-integration-ready evidence layer**. It does not claim government filing, certification, identity recognition or acceptance.

## Six-hour success condition

At the end of the timebox, a reviewer can see real data flow from a verified payroll book into:

1. a versioned authority-readiness evidence package;
2. an encrypted complete-book disclosure for verified reviewer or committee identities;
3. a public-accountability summary that reveals only totals already marked public on-chain;
4. employee, contractor and grant use-case explanations grounded in actual PAYO behavior; and
5. clear proof boundaries for fabrication and omission.

Every package must retain the live book root, block number, source commitment and Starknet transaction references. Hardcoded showcase totals are forbidden.

## Hour 0:00–0:30 — Block H1: freeze the truth contract

Status: COMPLETE · shared claim model and seven truth-contract tests passed

- Add one shared claim/coverage model used by UI and downloads.
- Replace **tax authority** in user-facing copy with **authorized tax reviewer** until an accepted government identity provider exists.
- Describe W-2/P60/T4 outputs as **familiar-style verified income evidence**, not official forms.
- Define fabrication coverage as: mutation or substitution after commitment is detected.
- Define omission coverage as: every entry and line in the selected on-chain PAYO book is reconstructed.
- State that source-data truth and payroll operated outside PAYO are outside the proof.
- Remove **first treasury model** and change **single largest barrier** to **a major barrier**.

Exit gate: one wording contract has tests for every prohibited overclaim.

## Hour 0:30–1:40 — Block H2: government-integration-ready evidence

Status: COMPLETE · committed export, bound recipient, negative tests and recipient download passed

Create a versioned downloadable manifest derived only after live-book verification:

- package version and generation time;
- organization, reporting period and jurisdiction;
- report ID, report commitment and recipient identity fingerprint;
- complete-book entry and line coverage;
- gross, deductions and net by token;
- familiar tax-view coverage and diagnostics;
- bound policy versions and legal-review flags;
- live accumulator root and observed block;
- integrity-proof and settlement transaction references;
- readiness state: **verified evidence**;
- filing state: **exported — not submitted**;
- explicit missing-adapter requirements for official filing.

Reject incomplete calendar periods, conflicting recipient references, changed commitments, wrong recipients and stale live-book roots.

Exit gate: valid export passes; mutated, partial and misaddressed exports fail.

## Hour 1:40–2:30 — Block H3: reviewer disclosure experience

Status: COMPLETE · automatic reviewer identity, truthful evidence scope and responsive browser flow passed

- Present one clear **Authorized tax reviewer** path on Activity.
- Resolve and validate the reviewer's wallet-bound public identity automatically.
- Explain that the complete PAYO book is disclosed, while public observers receive only public commitments and opted-in aggregates.
- Show a coverage panel: book entries, payroll lines, reporting period, root and block.
- Show exactly what the proof establishes and what it cannot establish.
- Keep employee My Pay isolated from employer and reviewer full books.
- Keep official filing language visible beside the download and opened result.

Exit gate: a reviewer can understand the evidence without being told it is an official filing.

## Hour 2:30–3:35 — Block H4: DAO public accountability

Status: COMPLETE · public and hidden aggregate evidence, mutation rejection and responsive result card passed

- Add a quarterly accountability summary derived from verified payroll-book entries.
- Show contributor count and STRK/USDC totals only when those values are public in the on-chain entry.
- Show **Aggregate totals kept private** when the entry uses hidden totals.
- Never derive or guess hidden values.
- Convert to a fiat display only when a verified, period-appropriate FX source is bound; otherwise retain token totals.
- Link the summary to the on-chain root and transactions.
- Expose an aggregate-disclosure choice for future payroll only if it is verified through the complete proof and authorization path; otherwise ship the read-only disclosure state.
- Add a small-cohort privacy warning because public aggregates can become identifying when few recipients are included.

Exit gate: every displayed aggregate can be independently traced to verified public entry data.

## Hour 3:35–4:35 — Block H5: committee, contractor and grant use cases

Status: COMPLETE · multi-recipient encryption, identity rejection tests and linked use-case UI passed

### Governance committee

- Allow multiple verified reviewer identities for one encrypted complete-book export.
- Reject duplicate wallets, the connected payer wallet, wrong-chain identities and fingerprint mismatches.
- Display each authorized fingerprint before encryption.
- State that every selected member can independently decrypt the package; this is not threshold cryptography.
- Do not promise revocation of a package already downloaded.

### Contractor and grant networks

- Reuse the existing contractor classification and private STRK20 settlement path.
- Add a grant-purpose presentation without representing grants as employee wages or official tax treatment.
- State the proved-run limit: 1–50 contributors.
- Describe larger networks as multiple independently verified runs; do not claim one batch handles thousands.
- Add the senior-talent use case with **salary privacy is a major hiring barrier**, without claiming it is the single largest barrier.
- Explain that recipient and amount privacy remains subject to STRK20's implemented threat model.

Exit gate: the three use cases link to real controls or evidence, not static promises.

## Hour 4:35–6:00 — Block H6: production gates and local review

Status: SCOPED IMPLEMENTATION GATES AND SIGNED SWAP CANARY PASSED · repository-wide completion gate remains open

- Unit tests for manifest commitments, readiness states and claim wording.
- Negative tests for mutation, omission, hidden-total leakage, duplicate committee identities and wrong recipients.
- Rendered Chromium journeys for reviewer, committee and employee boundaries.
- Responsive checks at 320, 375, 768 and 1280 px.
- Full TypeScript, lint, Vitest, database, production audit and production build gates.
- Start the migrated local PostgreSQL database and production server.
- Inspect desktop and mobile renders.
- Present local URLs and stop for user review.

Exit gate: no failed required gate, no accidental generated files, no push and no deployment.

Verification record:

- ESLint and the production TypeScript gate passed.
- 157 Vitest files passed with 797 application tests; the isolated PostgreSQL run passed all 74 database tests.
- The configured production audit threshold passed. Five low-severity transitive findings remain under Garaga; the available forced fix would apply a breaking downgrade and was not used.
- The optimized production build generated all 39 routes.
- Phase 3 reviewer/employee/history journeys passed 3/3; Phase 4, legacy Block 4 external facts and legacy Block 5 private exit passed 1/1 each.
- Six production routes passed at 320, 375, 430, 768 and 1280 px: 30/30 checks returned HTTP 200, with zero horizontal overflow, clipped leaf text or browser errors.
- Desktop and phone Activity, Team and Wallet screenshots passed visual inspection after the final text-wrap correction.
- The detailed comparison is recorded in `docs/HACKATHON_FINAL_6_HOUR_AUDIT.md`; the mandatory repository-wide completion command still fails, so the release is not marked cleared.

## Post-roadmap private-exit release correction

- Mainnet deployment `0x1245b90664a6d2144b04d9aedeb8e1d6822b6a6ea88e5d45b0024400e32c698` created the reviewed immutable anonymizer at `0x6737a6cdde0e0c4f39d88ec7301e1db8d7c46ffed35ade0ee9a56ed87ab784`.
- Exact class-hash and ABI readback passed; local readiness and one live Ekubo quote passed.
- Fly version 89 serves the reviewed H1–H6 image and canonical Ready-calldata fix; hosted health, six primary routes, anonymizer readiness and a live quote pass.
- The signed Ready-wallet canary reached `Private swap confirmed` for 0.2 USDC into a 6.481607 STRK private note, with a 6.41679 STRK minimum and the anonymizer verified at block 14,504,583. The supplied completion evidence did not expose a transaction hash, so none is asserted.

## Exact claims permitted after this timebox

> PAYO keeps recipient-level payroll encrypted while binding each settled run to a publicly verifiable payroll-book entry. Workers can open only their own evidence. An employer can encrypt the complete committed book to verified reviewer or committee identities. Verification detects mutation, duplication, reordering and omission relative to the selected PAYO book. Public accountability views expose only contributor counts and aggregate totals explicitly disclosed on-chain. Familiar W-2/P60/T4-style views support review; official filing remains on the relevant government channel.

## Explicitly outside the six-hour claim

- Government registration, credentials, certification or production submission.
- Official IRS/SSA, HMRC, CRA or other authority acknowledgements.
- Proof that employer-supplied identity, classification or jurisdiction facts were truthful when entered.
- Proof that no payroll occurred outside PAYO.
- A strict quarterly-only aggregate proof while every underlying run aggregate remains hidden.
- Threshold committee decryption such as two-of-three access.
- One proved payroll run above 50 contributors.
- A production-scale thousands-recipient orchestrator.
- Any further Starknet declaration, deployment, activation or transaction without a separately approved release step.
