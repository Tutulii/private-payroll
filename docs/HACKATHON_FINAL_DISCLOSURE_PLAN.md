# Hackathon final disclosure production plan

Status: ACTIVE
Started: 2026-09-07
Baseline commit: a5922af81456532a7d97237517416a811b01adf0
Baseline deployment: Fly release 83
Scope: external reviewer and employee disclosure experience
Time box: 5-7 hours, hard stop at 8 hours to preserve submission time

## Objective

Ship production-grade disclosure behavior for the defined PAYO scope:

1. An employer encrypts a complete payroll-book evidence package to an explicitly selected external reviewer.
2. A worker opens only their own encrypted statement source and verifies it against the live Mainnet payroll book.

Production-grade for this work means authenticated wallet-bound identity, client-side encryption and decryption, least-privilege access, fail-closed validation, live-chain verification, responsive UI, accessibility, meaningful positive and negative tests, a clean production build, green CI, reviewed deployment and rollback evidence.

This does not make PAYO an IRS, HMRC, CRA or other government filing system. W-2-, P60- and T4-style views remain supporting evidence. Statutory filing stays on the jurisdiction's approved channel.

## Frozen safety boundary

The following working surfaces remain frozen unless a regression proves a change is necessary:

- payroll calculation and private settlement;
- Noir circuits, Garaga verifiers and Cairo contracts;
- Mainnet addresses and registry state;
- STRK20 wallet calls;
- confirmation and recovery workers;
- universal payroll-book commitments;
- production data.

This plan requires no contract deployment, Mainnet transaction, STRK, USDC or database migration. Live release 83 stays active until local gates pass and the user reviews the result.

Rollback target: commit a5922af81456532a7d97237517416a811b01adf0 and Fly release 83.

## Current baseline

Already implemented and evidence-backed:

- Ready-wallet authentication;
- automatic publication of a PAYO X25519 vault identity;
- a directory binding that identity to authenticated chain, wallet and principal;
- complete employer and reviewer books checked against the ordered on-chain accumulator;
- recipient-encrypted worker statement sources;
- worker-only statement generation after complete-book verification;
- familiar readable tax evidence with an official-filing disclaimer;
- Mainnet vesting and payroll-book canary evidence;
- green CI and healthy Fly release 83.

Remaining weaknesses:

- reviewer public identity is manually downloaded and imported;
- employer, reviewer and employee actions are mixed in one Activity card;
- an employee can encounter employer-only contributor controls;
- normal and fallback identity paths are unclear at the decision point.

## Required reviewer journey

1. Reviewer connects Ready and unlocks a PAYO vault once.
2. PAYO publishes the vault public identity through the authenticated wallet directory.
3. Employer selects Tax reviewer - complete encrypted book.
4. Employer enters the reviewer Ready wallet.
5. PAYO validates chain, canonical wallet, principal, X25519 key and fingerprint.
6. Export stays disabled until validation succeeds.
7. PAYO reconstructs and verifies the complete live payroll book.
8. PAYO encrypts the report only to the selected reviewer.
9. The encrypted JSON is delivered through an employer-approved secure channel.
10. The reviewer opens it with their own vault.
11. PAYO decrypts locally and rereads the live on-chain checkpoint.

The employer must not see a misleading Share mine action. Manual identity-file import remains inside an Offline fallback and requires out-of-band fingerprint confirmation.

## Required employee journey

1. Employee opens a dedicated My Pay route.
2. Employee connects and authenticates the receiving Ready wallet.
3. Employee unlocks their own PAYO vault.
4. The page shows the wallet-bound identity state.
5. Employee selects Open my encrypted statement.
6. The page accepts a worker source or worker-scoped final statement.
7. A source decrypts only for its intended recipient and is checked against the live book.
8. PAYO generates and downloads the employee's final recipient-encrypted statement.
9. The result shows period, employer reference, gross, deductions, net, token, coverage, book root, block number and transaction references.
10. Check again rereads live state.

The employee page must never ask the user to choose a contributor, import a reviewer identity, or open an employer or reviewer full book. Direct STRK20 reporting identities remain distinct from the explicitly labelled Ready PAYO-X25519 fallback.

## Security invariants

- Payroll plaintext never enters a PAYO API request.
- Identity publication requires an authenticated Ready session.
- Published principal, chain and wallet must match the authenticated session.
- Starknet addresses and felt chain IDs use canonical comparison.
- Imported identities are schema, key and fingerprint checked.
- Stale lookup responses cannot replace a newer reviewer selection.
- Reviewer export fails closed for a missing, malformed or inconsistent identity.
- A reviewer book is wrapped only to the chosen reviewer principal.
- A worker source is wrapped only to the intended worker identity.
- An unrelated vault cannot decrypt either package.
- Complete-book verification happens before worker filtering.
- Report opening rereads the trusted live checkpoint.
- Historical reference ambiguity never mutates original lines.
- Readable plaintext export is labelled as a privacy exit.
- Disclosure never triggers a wallet transaction or fee.
- No evidence view claims official filing, certification or legal sufficiency.

## Block A - shared wallet-bound identity resolver

Status: COMPLETE · focused lint, TypeScript and 12 resolver tests passed

- Add a role-neutral client helper that validates directory results.
- Validate v2 format, chain, canonical wallet, principal, key and fingerprint.
- Preserve existing API compatibility.
- Use it in contributor and reviewer lookup where safe.
- Test valid, missing, wrong-chain, wrong-wallet, wrong-principal, changed-fingerprint and legacy-v1 results.

Exit gate: focused tests pass and no secret material enters the resolver.

## Block B - employer reviewer experience

Status: COMPLETE · automatic reviewer lookup and existing Phase 3 Chromium journey passed

- Rename the visible option to Tax reviewer - complete encrypted book.
- Add a reviewer Ready wallet field.
- Resolve the wallet-bound encryption identity with bounded debounce.
- Ignore stale responses.
- Show idle, checking, found, missing and error states.
- Disable export until validation succeeds.
- Remove Share mine from the employer path.
- Move file import under Offline identity fallback.
- Show the supporting-evidence and official-filing limitation beside the control.
- Preserve the internal versioned tax_authority scope.

Exit gate: the normal path needs only the reviewer wallet; invalid paths fail clearly; no signature or transaction is requested.

## Block C - dedicated My Pay employee page

Status: COMPLETE · worker-only crypto path, live-book Chromium journey and 320/375/768/1280px overflow gates passed

- Add a My Pay route and navigation entry.
- Extract or reuse shared parsing, decryption and live verification instead of duplicating security logic.
- Accept worker sources and worker-scoped final reports.
- Reject employer and reviewer full books.
- Show a locked state for authentication and vault unlock.
- Provide one primary Open my encrypted statement action.
- Render worker source metadata and final verified statement.
- Preserve Check again and encrypted evidence download.
- Support 320px, 375px, 768px and desktop widths.

Exit gate: no employer controls render; intended worker opens their source; unrelated vault fails before private content renders; live root and block are shown.

## Block D - wording, accessibility and responsive behavior

Status: COMPLETE · reviewer and employee flows passed 320/375/768/1280px overflow gates and visual review

- Use employer-authorized reviewer and encrypted supporting evidence wording.
- Keep the official-filing limitation visible.
- Add explicit labels and live status regions.
- Preserve keyboard use and visible focus.
- Prevent addresses, roots, filenames and fingerprints from overlapping cards.
- Verify loading, empty, warning and failure states on mobile.

Exit gate: employer, reviewer and employee responsibilities are understandable without verbal correction.

## Block E - verification

Status: COMPLETE · full lint, TypeScript, 781-test Vitest suite, production audit threshold, production build and all rendered browser suites passed

Focused checks:

- wallet-bound resolver tests;
- automatic reviewer lookup browser test;
- missing and tampered identity rejection;
- My Pay positive worker flow;
- unrelated-recipient rejection;
- employer and reviewer full-book rejection on My Pay;
- existing historical-reference conflict regression;
- existing worker-source live-book regression.

Repository gates:

- focused ESLint;
- TypeScript;
- focused Vitest;
- full Vitest;
- production audit;
- full lint;
- status verification;
- production build;
- rendered Phase 3 browser controls;
- affected responsive browser checks.

No gate passes from source inspection alone.

## Block F - local review

Status: READY FOR USER REVIEW · isolated PostgreSQL migrated, 74/74 database tests passed, production server healthy on localhost:3000

- Start a local database and production-equivalent web app.
- Exercise reviewer lookup with controlled identities.
- Exercise employee opening with the intended worker vault.
- Inspect desktop and mobile output.
- Present the local result to the user.
- Stop before push or deployment.

## Block G - source and hosted release

Status: PENDING

After local review:

1. Commit only planned files.
2. Preserve unrelated docs/DEMO_FOLLOWUPS.md.
3. Push the reviewed commit.
4. Wait for all GitHub CI gates.
5. Deploy the exact green commit to Fly.
6. Confirm the release database command, machine health and public health endpoint.
7. Confirm served Activity and My Pay bundles contain the reviewed behavior.
8. Record commit, CI run, Fly version and live evidence.

## Acceptance matrix

| Requirement | Evidence |
| --- | --- |
| Reviewer identity is wallet-bound | repository integration and resolver tests |
| Normal reviewer path has no identity file | rendered browser test |
| Offline fallback remains available | rendered browser test |
| Reviewer package remains recipient encrypted | crypto workflow test |
| Worker sees only their own lines | positive and wrong-recipient tests |
| Complete book matches live checkpoint | verifier and live recheck |
| Employee has separate interface | rendered My Pay route |
| Phone and tablet are usable | responsive browser checks |
| No official-filing claim | copy assertion and manual review |
| No transaction or fee | wallet-call assertion |
| Hosted release matches source | green CI, Fly image and bundle check |

## Stop rules

Stop and roll back if:

- payroll, proof, settlement, vesting or recovery changes unexpectedly;
- plaintext payroll enters an API;
- reviewer identity cannot be tied to chain and wallet;
- a worker can open another worker's source;
- disclosure requests a transaction;
- regression or build cannot be restored within the time box;
- the work requires a contract or Mainnet mutation;
- optional work would consume the submission buffer.

## Deferred work

- government reviewer credentials;
- IRS, HMRC, CRA or other e-filing;
- jurisdiction certification;
- encrypted cross-organization inbox;
- notifications and webhooks;
- enterprise SSO;
- external security and legal audits.

## Execution order

1. Create this plan.
2. Complete and test Block A.
3. Complete and test Block B.
4. Complete and test Block C.
5. Complete Block D.
6. Run all Block E gates.
7. Run Block F and obtain local user review.
8. Perform Block G only after local review.
9. Update this file with evidence and truthful final status.

## Progress log

- 2026-09-07: Plan created from commit a5922af and Fly release 83.
