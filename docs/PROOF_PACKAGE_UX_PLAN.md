# PAYO Proof Package UX Production Plan

Status: implementation complete; release verification in progress

This is the compact implementation plan for making PAYO's encrypted proof packages useful to an authorized human without weakening payroll privacy. It is intentionally one focused release: no new smart-contract deployment, payroll transaction, or ZK proof generation is required.

## 1. Readable proof-package inspector

- Add an **Open proof package** control to Activity.
- Import `payo-encrypted-proof-package-v1` JSON locally; never upload its ciphertext.
- Decrypt only with the unlocked recipient PAYO vault.
- Validate the outer schema, recipient identity, grant window/revocation, encrypted archive commitment, file manifest, balanced journal, proof binding, and embedded on-chain verification evidence.
- Show a simple `Verified`, `Expired`, `Revoked`, `Wrong recipient`, `Tampered`, or `Invalid` result rather than raw cryptographic errors.

## 2. Linked claim context

- Include the original claim type in encrypted remediation disclosures.
- Show the readable claim type, claim ID, amount, token, workflow, and settlement status in the inspector.
- Keep these facts inside recipient ciphertext; never add them to plaintext filenames, operational logs, or public API metadata.

## 3. Clear creation success

- Replace toast-only completion with a persistent result card.
- Show workflow, recipient scope, expiry, package commitment, and verified state.
- Provide **Open package**, **Download again**, and **Copy commitment** actions.

## 4. Privacy-safe filenames

- Use deterministic, readable names such as `payo-wage-remediation-employer-20260828.json`.
- Do not place `missing-obligation`, identities, amounts, or other private dispute facts in the plaintext filename.

## 5. Public recipient identity exchange

- Export `payo-public-identity-v1` JSON containing only the PAYO principal ID, X25519 public key, a verification fingerprint, and creation time.
- Never export a vault secret key, recovery password, organization secret, or recovery ciphertext.
- Import and strictly validate a recipient identity file, show its fingerprint, and fill the disclosure form.
- Keep **Use my PAYO identity** as the fast self-recipient path.

## 6. Production verification and completion gate

- Positive test: create, download, import, decrypt, verify, and display a claim/remediation package.
- Negative tests: malformed JSON, unsupported format, wrong recipient, wrong public key, modified ciphertext, modified commitment, expired grant, revoked grant, and unsafe identity export/import.
- Browser evidence must exercise the real Activity controls without exposing a production test route.
- Required gates: unit tests, database integration tests, rendered Chromium evidence, typecheck, lint, status verification, production build, clean worktree, hosted health check, and a real authorized package opened in production.

## Implementation evidence

Implemented in this release:

- The Activity page can create, reopen, download and inspect recipient-encrypted packages without uploading package contents.
- The inspector distinguishes current public-input-bound packages from legacy packages and never labels a transaction receipt alone as a verified ZK proof.
- Current packages pin the public-input digest to the configured PAYO seal and chain, require a matching proof-completion event, and read the terminal seal state plus both shard cursors.
- ZIP extraction, JSON parsing, identity import and ciphertext handling are bounded and fail closed with privacy-safe errors.
- Claim and remediation packages display decrypted linked context while keeping dispute facts out of filenames and public metadata.
- Public identity exchange validates an X25519 key and fingerprint and excludes secret/recovery material.
- Synthetic browser evidence is served only when `PAYO_BROWSER_EVIDENCE_MODE=1` and is unconditionally unavailable in production.

Local gates completed on 2026-08-28:

- `npm run typecheck`
- `npm run lint`
- `npm test` — 82 files passed, 363 tests passed, one file and 26 conditional tests skipped
- `npm run test:db` after runtime migrations — 26 PostgreSQL integration tests passed
- `npm run build` — production build completed for all 33 application routes
- `npm run verify:status` — status matrix structurally valid; this does not claim the full PAYO master plan is complete

Release gates that necessarily follow the single release commit:

- Rendered Chromium evidence on Linux CI (Playwright does not provide an Android browser binary for this Termux host).
- Clean-clone CI confirmation.
- Fly deployment and hosted health check.
- One real authorized package opened by its recipient in the production UI.

## Deferred

PDF reports, QR sharing, hosted package storage, bulk inspection, a standalone auditor portal, and a separate CLI are outside this release.
