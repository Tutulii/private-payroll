# PAYO

[![PAYO CI](https://github.com/Tutulii/private-payroll/actions/workflows/ci.yml/badge.svg)](https://github.com/Tutulii/private-payroll/actions/workflows/ci.yml)
[![Starknet Mainnet](https://img.shields.io/badge/Starknet-SN__MAIN-6c63ff)](./docs/MAINNET_CONTRACTS.md)
[![STRK20](https://img.shields.io/badge/privacy-STRK20-111827)](./strk20.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-1f2937)](./LICENSE)

**Private payroll on Starknet, with proof when someone is allowed to see it.**

PAYO lets an organization pay contributors in private STRK or native USDC, prove the payroll calculation against committed agreements, and issue encrypted evidence to an employer, a worker, or a named reviewer. Individual compensation stays out of the public transaction graph; commitments and verification state remain accountable on Starknet.

[Open the live Mainnet app](https://private-payroll.fly.dev) · [Read the architecture](./architecture.md) · [Inspect deployed contracts](./docs/MAINNET_CONTRACTS.md) · [Review Mainnet evidence](./evidence) · [See proof benchmarks](./docs/MAINNET_BENCHMARKS.md)

> **Project status:** live, open-source Mainnet MVP. Human payroll and evidence workflows have Mainnet execution records. Contracts and circuits remain experimental and have not received an independent production security audit. See [Security and limitations](#security-and-limitations) before using real payroll funds.

PAYO is built specifically for Starknet rather than migrated from another chain. Its design uses Starknet account abstraction, Cairo contracts, and the STRK20 privacy stack as core protocol components.

## The problem

A public payroll reveals more than a transfer. Repeated payments expose the contributor list, salary bands, payday timing, treasury behavior, and which wallets are valuable enough to target. Moving payroll into a private database removes public surveillance, but it also asks workers and reviewers to trust whatever report the operator produces later.

PAYO keeps settlement private while preserving a verifiable record of the payroll that was committed inside PAYO:

- **Private settlement:** STRK20 private notes hide recipient-level STRK and USDC payments from public observers.
- **Proof-bound calculation:** Noir proofs bind payroll arithmetic, agreement commitments, policy inputs, validity windows, nullifiers, and the selected payroll book.
- **Selective disclosure:** readable evidence is encrypted to the specific employer, worker, or reviewer who should receive it.
- **Ordered accountability:** Starknet records the book checkpoint and proof state without receiving plaintext salaries.

## One payroll, three controlled views

Every view is derived from the same committed payroll book. PAYO changes who can decrypt the details, not which book is being checked.

| Recipient | What they receive | What stays hidden |
|---|---|---|
| Employer | Complete selected payroll book, totals, proof references, and onchain checkpoint | Nothing inside the employer's selected book |
| Worker | Personal income statement opened with the worker's wallet-bound reporting identity | Other contributors and their compensation |
| Authorized reviewer | Complete encrypted book addressed to the reviewer's registered identity | The book remains unreadable to the public and unrelated wallets |
| Public observer | Contract calls, commitments, proof state, nullifiers, and explicitly public aggregates | Recipient identities, salary lines, deductions, and encrypted evidence |

An authorized-reviewer package is supporting evidence. PAYO verifies the recipient wallet and encryption identity; it does not certify that the wallet belongs to a government authority or submit an official tax filing.

## Product flow

```mermaid
flowchart LR
    A[Create organization] --> B[Add contributor identity]
    B --> C[Encrypt agreement]
    C --> D[Protect payday snapshot]
    D --> E[Generate two ZK proof shards]
    E --> F[Approve in Ready]
    F --> G[Private STRK20 settlement]
    G --> H[Confirm and verify on Starknet]
    H --> I[Employer, worker, or reviewer evidence]
```

1. The employer connects Ready, creates an organization, and records a contributor's wallet-bound public reporting identity.
2. PAYO encrypts the agreement in the browser and commits its obligation without publishing salary terms.
3. Before payday, the employer protects the exact due batch. The snapshot prevents the selected obligations from changing underneath the proof.
4. A native Barretenberg prover generates two linked UltraKeccak ZK Honk shards from the encrypted payroll witness.
5. Ready presents the private STRK20 settlement and PAYO action for approval. PAYO never receives the employer's wallet key.
6. Durable workers reconcile the submitted transaction, wait for finality, and deliver the proof shards through a fee-funded permissionless relayer.
7. The verified book checkpoint becomes the common source for employer, worker, and reviewer evidence.

If Ready closes before returning a transaction hash, PAYO keeps a recoverable submission and searches for the canonical STRK20 settlement event before asking the employer to do anything again. It never treats a missing browser response as permission to repay the batch.

## Verified capabilities

| Capability | Current boundary | Evidence |
|---|---|---|
| Private human payroll | STRK-only, native-USDC-only, and mixed STRK/USDC Mainnet runs through Ready | [STRK](./evidence/payo-strk-mainnet.json) · [USDC](./evidence/payo-usdc-mainnet.json) · [mixed](./evidence/payo-mixed-mainnet.json) |
| PayrollIntegrity proofs | Two linked shards; agreement, policy, arithmetic, schedule, validity-window, and nullifier bindings | [Proof evidence](./docs/phase2-evidence.md) |
| Recurring and advanced agreements | Recurring, checkpoint, milestone, vesting, classification, FX-floor, and offboarding inputs | [Advanced-obligation evidence](./docs/phase3-evidence.md) |
| Stateful vesting | Accrued release, replay protection, ordered book update, and a successful Mainnet canary | [Vesting evidence](./evidence/vesting-tax-mainnet.json) |
| Private compliance book | Employer book, worker-only statement, and named-reviewer encrypted book checked against the live accumulator | [Vesting and tax evidence](./evidence/vesting-tax-mainnet.json) |
| Wage claims | Snapshot, claim, and remediation contracts are deployed; the end-to-end workflow remains experimental | [Wage-claim deployment](./docs/wage-claim-mainnet-deployment.md) |
| Private swap | Reviewed STRK20/Ekubo anonymizer, block-pinned quote checks, and a recorded Mainnet canary | [Private-exit evidence](./evidence/private-exit-mainnet.json) |
| Agent/MCP access | Eight capability-scoped MCP tools and Devnet execution evidence; no completed autonomous Mainnet payroll canary | [MCP guide](./packages/mcp/README.md) · [agent evidence](./docs/phase4-evidence.md) |

The implementation deliberately separates three claims:

1. **Calculation proven** — the verifier accepted the committed payroll calculation.
2. **Wallet confirmed** — Starknet accepted the STRK20 settlement transaction.
3. **Settlement matched** — locally opened private-note evidence was reconciled with the approved manifest.

Ready-backed payrolls can establish the first two claims. SettlementMatch requires a locally controlled STRK20 viewing key, which Ready does not expose to a dapp.

## Architecture

```mermaid
flowchart TB
    Browser[PAYO web client] -->|XChaCha20-Poly1305 ciphertext| Vault[(PostgreSQL vault)]
    Browser -->|encrypted proof job| Prover[Native Noir + Barretenberg prover]
    Prover -->|proof shards + public roots| Browser
    Browser -->|reviewed wallet request| Ready[Ready wallet]
    Ready --> Pool[STRK20 privacy pool]
    Pool --> Seal[PAYO Cairo seal]
    Relayer[Fee-only proof relayer] --> Verifiers[Garaga Cairo verifiers]
    Verifiers --> Seal
    Seal --> Book[Ordered payroll book]
    Book --> Disclosure[Recipient-encrypted evidence]
    Vault --> Disclosure
```

The browser encrypts vault records with XChaCha20-Poly1305 and wraps data-encryption keys to authorized X25519 identities. The hosted prover decrypts a witness only inside volatile job memory, which makes the prover an explicit trust boundary. Organizations that do not accept that boundary can operate the prover themselves.

The onchain layer receives commitments, verifier versions, validity windows, nullifiers, proof state, and configured public aggregates. It does not receive plaintext agreements, salaries, deductions, or disclosure packages.

### Starknet stack

| Layer | PAYO integration |
|---|---|
| Private settlement | STRK20 Privacy SDK and canonical Mainnet pool |
| Wallet | Ready Wallet API and Starknet account abstraction |
| Proofs | Noir `1.0.0-beta.16`, native Barretenberg `3.0.0-nightly.20251104`, UltraKeccak ZK Honk |
| Verification | Garaga `1.1.0` generated verifiers composed with PAYO Cairo contracts |
| Contracts | Cairo/Scarb `2.16.1`, Starknet Foundry `0.57.0` |
| Market data | Proof-bound Pragma reference data where a usable policy feed is available |
| Private liquidity | Reviewed single-hop STRK20/Ekubo anonymizer |
| Application | Next.js, TypeScript, PostgreSQL, Drizzle, durable workers, Fly.io |

Exact versions and artifact hashes are pinned in [`toolchains.lock.json`](./toolchains.lock.json). The complete trust model, protocol states, storage model, and failure recovery design live in [`architecture.md`](./architecture.md).

## Mainnet deployment and evidence

PAYO runs on **Starknet Mainnet (`SN_MAIN`)** and uses the canonical STRK20 pool at:

```text
0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a
```

The application uses separate contract profiles for the original payroll seal, the wage-claim lifecycle, the universal vesting/payroll book, and restricted agent execution. The authoritative inventory records every active address, class hash, role, and read-back state:

- [`docs/MAINNET_CONTRACTS.md`](./docs/MAINNET_CONTRACTS.md) — active contract topology
- [`evidence/mainnet-contract-inventory.json`](./evidence/mainnet-contract-inventory.json) — machine-readable inventory
- [`docs/MAINNET_BENCHMARKS.md`](./docs/MAINNET_BENCHMARKS.md) — measured proof and transaction costs
- [`strk20.json`](./strk20.json) — public STRK20 transaction and deployment manifest

Evidence files contain transaction hashes, block numbers, commitments, deployment receipts, and read-back results. They are reproducible technical records, not user counts, revenue claims, or independent audits.

## Run locally

### Requirements

- Node.js `24.17.0`
- npm `12.0.2`
- PostgreSQL 17
- Git
- A Starknet Mainnet RPC endpoint
- Ready Wallet API `0.10.3` or newer for live wallet flows

Docker is optional, but it is the shortest way to start a disposable PostgreSQL instance.

### 1. Install PAYO

```bash
git clone https://github.com/Tutulii/private-payroll.git
cd private-payroll
npm ci
cp .env.example .env.local
```

### 2. Start PostgreSQL

```bash
docker run --name payo-postgres \
  -e POSTGRES_USER=payo \
  -e POSTGRES_PASSWORD=payo \
  -e POSTGRES_DB=payo \
  -p 5432:5432 \
  -d postgres:17
```

### 3. Configure the minimum local environment

```dotenv
DATABASE_URL=postgresql://payo:payo@127.0.0.1:5432/payo
NEXT_PUBLIC_STARKNET_RPC_URL=https://your-mainnet-rpc
STARKNET_RPC_URL=https://your-server-side-mainnet-rpc
PAYO_AUTH_AUDIENCE=http://localhost:3000
PAYO_WORKER_SECRET=replace-with-at-least-32-random-bytes
```

Generate secrets with a cryptographically secure tool such as `openssl rand -hex 32`. Never commit `.env.local`.

### 4. Migrate and run

```bash
npm run db:migrate
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

This configuration is enough to build and inspect the application. Live payroll, proof-relayer, indexing, private-swap, and agent operations fail closed until their additional deployment variables are configured. Every variable is documented in [`.env.example`](./.env.example); deployed addresses are published in [`docs/MAINNET_CONTRACTS.md`](./docs/MAINNET_CONTRACTS.md).

## Verify the repository

The standard application checks are:

```bash
npm run audit:production
npm run typecheck
npm test
npm run lint
npm run verify:status
npm run build
```

Database concurrency, idempotency, recovery, leases, and reorg-safe indexing use an explicit disposable database:

```bash
docker exec payo-postgres createdb -U payo payo_test

PAYO_TEST_DATABASE_URL=postgresql://payo:payo@127.0.0.1:5432/payo_test \
DATABASE_URL=postgresql://payo:payo@127.0.0.1:5432/payo_test \
npm run db:migrate

PAYO_TEST_DATABASE_URL=postgresql://payo:payo@127.0.0.1:5432/payo_test \
DATABASE_URL=postgresql://payo:payo@127.0.0.1:5432/payo_test \
npm run test:db
```

Rendered product and recovery paths are exercised with Playwright:

```bash
npm run test:browser:phase3
npm run test:browser:phase4
npm run test:browser:recovery
```

Noir, Barretenberg, Garaga, Cairo, and Devnet reproduction requires the pinned native toolchain and more memory than the web build. Start with [`circuits/README.md`](./circuits/README.md) and [`contracts/README.md`](./contracts/README.md). Routine validation must never submit a Mainnet transaction.

## Repository layout

| Path | Responsibility |
|---|---|
| [`app/`](./app) | Next.js routes, Ready integration, product UI, and API handlers |
| [`lib/client/`](./lib/client) | Vault, payroll, evidence, claim, and recovery orchestration |
| [`lib/domain/`](./lib/domain) | Versioned schemas, commitments, calculations, and state transitions |
| [`lib/persistence/`](./lib/persistence) | PostgreSQL repositories, idempotency, leases, and chain cursors |
| [`lib/proof/`](./lib/proof) | Witness construction, prover protocols, public inputs, and calldata |
| [`lib/starknet/`](./lib/starknet) | Ready, STRK20, contract, quote, and transaction adapters |
| [`circuits/`](./circuits) | Noir circuits, verification keys, and reproducible artifacts |
| [`contracts/`](./contracts) | Cairo seals, registries, bundles, generated verifiers, and tests |
| [`packages/mcp/`](./packages/mcp) | Capability-scoped MCP server and adversarial tests |
| [`drizzle/`](./drizzle) | Versioned PostgreSQL migrations |
| [`scripts/`](./scripts) | Deployment planning, evidence verification, workers, and recovery tools |
| [`evidence/`](./evidence) | Machine-readable Mainnet, Devnet, browser, and deployment evidence |
| [`docs/`](./docs) | Contract inventory, benchmarks, runbooks, and technical reports |

## Hosted services

| Service | Exposure | Responsibility |
|---|---|---|
| `private-payroll` | Public HTTPS | Web application, API, authentication, encrypted vault, indexer, and durable workflow workers |
| `private-payroll-prover` | Authenticated HTTPS | Memory-intensive native Barretenberg proof jobs |
| `payo-privacy-discovery` | Fly private network | Block-pinned STRK20 note discovery |
| `payo-transaction-prover` | Fly private network | Transaction-OS proving for direct Privacy SDK execution |
| `payo-policy-signer` | Fly private network | Narrow policy-owner signatures with no arbitrary-call API |

Production releases run database migrations before the new web image becomes active. Fly definitions are versioned in `fly.*.toml`; operator checks and rollback procedures are documented in [`docs/MAINNET_RELEASE_RUNBOOK.md`](./docs/MAINNET_RELEASE_RUNBOOK.md).

## Security and limitations

- PAYO is non-custodial. Ready or the restricted policy account authorizes settlement; PAYO contracts do not hold an employer's payroll treasury.
- The hosted prover sees the plaintext witness transiently while generating a proof. Self-hosting removes that operator dependency.
- Ready does not expose the viewing key required for SettlementMatch, so a Ready-backed run must not be described as note-level settlement matched.
- Completeness covers the selected PAYO onchain book. PAYO cannot prove that an employer made no payroll payments outside PAYO or that source facts were truthful when entered.
- A reviewer package proves encryption to a selected identity and consistency with the selected book. It does not establish government authority, employment status, or filing acceptance.
- Reference US, UK, and Canadian policy packs are calculation examples, not legal or tax advice and not official W-2, P60, or T4 filings.
- Private settlement still exposes timing, contract interaction, calldata size, and possibly the submitting account.
- Low-entropy commitments require random salts; a commitment alone does not make a guessable salary private.
- Contracts and circuits are experimental and unaudited. Use deliberately limited values until an independent review is complete.
- The autonomous agent path has implementation and Devnet evidence, but no completed autonomous Mainnet payroll canary.

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/Tutulii/private-payroll/security/advisories/new). The reporting scope and disclosure process are in [`SECURITY.md`](./SECURITY.md).

## Contributing

Contributions are welcome. [`CONTRIBUTING.md`](./CONTRIBUTING.md) explains the test tiers, privacy rules, and extra review required for commitments, circuits, generated verifiers, contracts, and Mainnet evidence.

PAYO is built by [Tutulii](https://github.com/Tutulii) and [gulbadanjhumur397-web](https://github.com/gulbadanjhumur397-web), and released under the [MIT License](./LICENSE).
