# Contributing to PAYO

Thank you for improving PAYO. This repository combines a Next.js application, encrypted PostgreSQL persistence, Noir proofs, generated Garaga verifiers, Cairo contracts, Starknet integrations, and an MCP server. Changes should remain reviewable across those boundaries.

## Development setup

1. Install the exact Node.js and npm versions in [`toolchains.lock.json`](./toolchains.lock.json).
2. Fork and clone the repository.
3. Run `npm ci` so the committed lockfile controls JavaScript dependencies.
4. Copy `.env.example` to `.env.local` and configure a disposable PostgreSQL database.
5. Run `npm run db:migrate`, then `npm run dev`.

The root [README](./README.md) contains the complete local setup and environment guide.

## Choose the appropriate checks

Run these checks for every application change:

```bash
npm run typecheck
npm test
npm run lint
npm run build
```

Add the relevant integration tier when a change crosses a boundary:

| Change | Required validation |
|---|---|
| Database schema, repository, lease, or recovery | Migration plus `npm run test:db` against a disposable database |
| Rendered payroll, disclosure, claim, or recovery flow | Matching Playwright suite in `tests/browser/` |
| MCP method, capability, or agent execution | `npm run test:mcp` and the related adversarial tests |
| Commitment or schema encoding | Existing golden vectors in every affected language |
| Noir circuit or verification key | Circuit tests, reproducible artifact comparison, native proof verification, and generated-verifier checks |
| Cairo contract or verifier composition | `scarb build`, `snforge test`, and the relevant integration harness |
| Mainnet configuration or evidence | Read-only verification command and a machine-readable evidence update |

Do not use a production database for tests. Do not submit a Mainnet transaction as part of routine contribution validation.

## Cryptographic and contract changes

Commitments, proof public inputs, verifier artifacts, and contract calldata are protocol surfaces. A change to one side must update every affected encoder, vector, circuit, generated artifact, verifier, decoder, test, and evidence check.

- Keep amounts as atomic-unit integer strings; never use JavaScript floating point for value calculations.
- Preserve domain separation and random salts for sensitive commitments.
- Never weaken a failing proof, registry, identity, expiry, replay, or authorization check to make a test pass.
- Generated verifier source must be reproducible from the pinned toolchain. Do not hand-edit generated verifier logic.
- Keep test-only harnesses out of production deployment configuration.

## Privacy requirements

- Never add plaintext payroll, wallet keys, recovery packages, viewing keys, access tokens, employee data, or unredacted payroll exports to fixtures, logs, screenshots, issues, or pull requests.
- Use synthetic identities and deliberately small values in test evidence.
- Treat readable exports as sensitive even when they were derived from verified encrypted evidence.
- Preserve tenant checks and authenticated associated data when changing encrypted records.
- Redact wallet notifications and unrelated balances from browser evidence.

## Pull requests

Keep each pull request focused. The description should explain:

- the concrete trigger or problem;
- the resulting behavior;
- the trust, privacy, proof, database, or Mainnet boundary affected;
- the commands used to validate the change; and
- any limitation that remains relevant to reviewers.

Include tests when behavior, security boundaries, state transitions, or serialization changes. Documentation-only corrections should still pass the checks relevant to the edited files.

## Commit messages

Use a short imperative subject that describes the final behavior, for example:

```text
Recover Ready payroll confirmation from pool events
Reject cross-tenant disclosure package imports
Document hosted prover trust boundary
```

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Follow [`SECURITY.md`](./SECURITY.md) and use the repository's private security-advisory channel.

By contributing, you agree that your contribution is licensed under the repository's [MIT License](./LICENSE).
