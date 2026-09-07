# PAYO

[![PAYO CI](https://github.com/Tutulii/private-payroll/actions/workflows/ci.yml/badge.svg)](https://github.com/Tutulii/private-payroll/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-1f2937.svg)](./LICENSE)
[![Node.js 24](https://img.shields.io/badge/Node.js-24-3c873a.svg)](./toolchains.lock.json)
[![Starknet Mainnet](https://img.shields.io/badge/network-Starknet%20Mainnet-6c63ff.svg)](./docs/MAINNET_CONTRACTS.md)

> **Private payroll with public proof and disclosure controlled by the people who need it.**

PAYO is a non-custodial payroll workspace on Starknet. Organizations can pay people and bounded AI agents in private STRK or native USDC, prove that committed payroll rules were followed, and produce encrypted evidence for employers, workers, and authorized reviewers without publishing individual salaries.

[Live application](https://private-payroll.fly.dev) · [Architecture](./architecture.md) · [Mainnet contracts](./docs/MAINNET_CONTRACTS.md) · [Proof benchmarks](./docs/MAINNET_BENCHMARKS.md) · [Evidence directory](./evidence)

PAYO was built for the [STRK20 Private Sprint](https://strk20.starknet.io/hackathon) and follows its private-payroll brief: private batches, recurring agreements, vesting, wage claims, scoped agent authority, and selective disclosure.

## Why PAYO

Public payroll transactions expose a company's contributor graph, compensation bands, payment timing, and treasury behavior. A conventional private database hides those details from the public but asks workers and reviewers to trust the payroll operator's records.

PAYO combines three properties:

- **Confidential settlement.** STRK20 hides recipient, asset, and amount details inside private notes.
- **Verifiable calculation.** Noir proofs bind the payment to encrypted agreements, policy snapshots, schedules, and a complete selected payroll book.
- **Scoped disclosure.** The employer can export a complete book, a worker can open only their statement, and an authorized reviewer can receive an encrypted complete-book package.

The core idea is simple: privacy should remove payroll data from public surveillance without removing evidence that the committed obligations were handled consistently.

## Review PAYO in five minutes

1. Open the [live application](https://private-payroll.fly.dev). The public deployment and proof-benchmark surfaces can be inspected without moving funds.
2. Read the [active Mainnet contract inventory](./docs/MAINNET_CONTRACTS.md), including addresses, class hashes, and the verified vesting/compliance-book topology.
3. Inspect the machine-readable evidence for [STRK payroll](./evidence/payo-strk-mainnet.json), [native-USDC payroll](./evidence/payo-usdc-mainnet.json), [mixed payroll](./evidence/payo-mixed-mainnet.json), [vesting and the complete payroll book](./evidence/vesting-tax-mainnet.json), and the [private exit](./evidence/private-exit-mainnet.json).
4. Review the measured [proof and Mainnet gas benchmarks](./docs/MAINNET_BENCHMARKS.md).
5. Clone the repository and run the verified build path below.

Live payroll actions use Mainnet assets and require a compatible Ready wallet. Repository evidence lets a reviewer inspect deployed bindings and historical runs without spending funds or waiting for proof generation.

## Verified capabilities

| Capability | What the implementation does | Primary evidence |
|---|---|---|
| Human private payroll | Builds STRK, native-USDC, and mixed private batches; Ready remains the human signer | [STRK](./evidence/payo-strk-mainnet.json), [USDC](./evidence/payo-usdc-mainnet.json), [mixed](./evidence/payo-mixed-mainnet.json) |
| Proof-bound payroll | Generates two linked PayrollIntegrity shards and binds roots, policy version, validity window, and run nullifier to the PAYO seal | [Phase 1 evidence](./docs/phase1-evidence.md), [Phase 2 evidence](./docs/phase2-evidence.md) |
| Advanced agreements | Supports recurring, checkpoint, milestone, vesting, classification, FX-floor, and offboarding inputs | [Advanced-obligation evidence](./docs/phase3-evidence.md) |
| Stateful vesting | Proves accrued release from immutable terms, rejects stale state/replay, and appends the release to an ordered book | [Vesting Mainnet evidence](./evidence/vesting-tax-mainnet.json) |
| Private compliance book | Produces encrypted employer, worker, and authorized-reviewer evidence checked against the live book accumulator | [Compliance-book evidence](./evidence/vesting-tax-mainnet.json) |
| Wage claims and remediation | Binds a private shortfall claim to a protected obligation snapshot and a later private remedy | [Wage-claim deployment evidence](./evidence/phase3-wage-claim-mainnet.json) |
| Private STRK/USDC swap | Uses a reviewed single-hop Ekubo anonymizer with quote, route, block, and class-hash checks | [Private-exit evidence](./evidence/private-exit-mainnet.json) |
| Bounded agent payroll | Exposes eight MCP tools, encrypted capabilities, transactional limits, a restricted policy account, and SettlementMatch for direct Privacy SDK accounts | [Agent evidence](./docs/phase4-evidence.md) |

The autonomous agent path has implementation and Devnet evidence; this repository does not claim a completed autonomous Mainnet payroll canary. Ready-backed runs can prove calculation and transaction confirmation, while SettlementMatch requires a locally controlled viewing key that Ready does not expose to a dapp.

## How it works

```mermaid
flowchart LR
    User[Employer, worker, or reviewer] --> Client[PAYO web client]
    Client -->|authenticated ciphertext| Vault[(PostgreSQL vault)]
    Client -->|encrypted proof job| Prover[Noir + Barretenberg prover]
    Prover -->|proof + public roots| Client
    Client -->|review and approve| Ready[Ready wallet]
    Ready --> Pool[STRK20 privacy pool]
    Pool --> Seal[PAYO seal + Garaga verifiers]
    Seal --> Book[Ordered payroll book]
    Client -->|recipient-encrypted package| Evidence[Employer, worker, or reviewer evidence]
    Book -->|public checkpoint| Evidence
```

Sensitive vault records are encrypted in the browser with XChaCha20-Poly1305. Data-encryption keys are wrapped independently to authorized X25519 identities. The hosted prover receives an encrypted job and an ephemeral decryption principal, opens the witness only in volatile job memory, and must not log it. Teams that cannot trust the hosted prover with transient witness access can run the prover themselves.

The onchain system sees commitments, verifier versions, validity windows, nullifiers, and explicitly public aggregates. It does not receive plaintext salary lines.

### Evidence states

PAYO keeps three states separate:

1. **Calculation proven** — PayrollIntegrity accepted the committed agreement and payroll arithmetic.
2. **Wallet confirmed** — Starknet accepted the STRK20 transaction.
3. **Settlement proven** — SettlementMatch reconciled approved manifest lines with locally opened private-note evidence.

A Ready-backed payroll can reach the first two states. The third state is available to direct Privacy SDK accounts that control their viewing key.

## Product surfaces

| Route | Purpose |
|---|---|
| `/` | Treasury, payday, team, activity, and agent summary |
| `/team` | Contributors, one-wallet/one-contributor enforcement, encrypted agreements, and agent capabilities |
| `/payroll` | Due-obligation selection, proof generation, Ready approval, submission recovery, and confirmation |
| `/activity` | Receipts, proof inspection, compliance-book exports, reviewer imports, wage claims, and remediation |
| `/my-pay` | Worker-only encrypted statement opening and live-book verification |
| `/wallet` | Ready connection, shielded balances, private swap, and explicit public-exit boundary |
| `/deployment` | Public deployment and verifier bindings |
| `/proof-benchmark` | Reproducible proof measurements and evidence links |

## Privacy model

| Data | Public chain | PAYO storage | Authorized client or recipient |
|---|---:|---:|---:|
| Pool interaction and timing | Visible | Operational metadata | Visible |
| Contract, verifier, and proof version | Visible | Visible | Visible |
| Commitment roots and nullifier | Visible | Visible | Visible |
| Worker identity and payout address | Hidden | Ciphertext | Decrypted by scope |
| Salary, deductions, and token choice | Hidden | Ciphertext | Decrypted by scope |
| Full payroll book | Hidden | Ciphertext | Employer or selected reviewer |
| Worker income statement | Hidden | Ciphertext | Selected worker |

Direct wallet submission can reveal the transaction-signing account and timing. A relay or paymaster is required when hiding the submitter is part of the threat model. Commitments also do not protect low-entropy values by themselves, so sensitive leaves include random salts.

## Run locally

### Prerequisites

- Node.js `24.17.0`
- npm `12.0.2`
- PostgreSQL 17
- Git
- A Starknet Mainnet RPC endpoint
- Ready Wallet API `0.10.3` or newer for live wallet flows

Exact cryptographic and Starknet toolchain versions are pinned in [`toolchains.lock.json`](./toolchains.lock.json).

### Install and start

```bash
git clone https://github.com/Tutulii/private-payroll.git
cd private-payroll
npm ci
cp .env.example .env.local
```

Start a disposable local PostgreSQL instance, or point `DATABASE_URL` at an existing PostgreSQL 17 database:

```bash
docker run --name payo-postgres \
  -e POSTGRES_USER=payo \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=payo \
  -p 5432:5432 \
  -d postgres:17
```

Set these values in `.env.local` before starting the application:

```dotenv
DATABASE_URL=postgresql://payo:password@localhost:5432/payo
NEXT_PUBLIC_STARKNET_RPC_URL=https://your-mainnet-rpc
STARKNET_RPC_URL=https://your-server-side-mainnet-rpc
PAYO_AUTH_AUDIENCE=http://localhost:3000
PAYO_WORKER_SECRET=replace-with-at-least-32-random-bytes
```

Then migrate and start:

```bash
npm run db:migrate
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Generate secrets with a cryptographically secure tool such as `openssl rand -hex 32`; never commit `.env.local`.

The basic web build needs the variables above. Live proof, worker, agent, and Mainnet execution services require the additional fail-closed variables documented in [`.env.example`](./.env.example). Public deployed addresses and their class hashes are recorded in [`docs/MAINNET_CONTRACTS.md`](./docs/MAINNET_CONTRACTS.md).

## Verify the repository

The default CI path runs dependency, TypeScript, domain, database, browser, evidence, lint, and production-build checks.

```bash
npm run audit:production
npm run typecheck
npm test
npm run lint
npm run build
```

Database integration tests intentionally require an explicit disposable test database:

```bash
PAYO_TEST_DATABASE_URL=postgresql://payo:password@localhost:5432/payo_test \
DATABASE_URL=postgresql://payo:password@localhost:5432/payo_test \
npm run test:db
```

Rendered browser paths:

```bash
npm run test:browser:phase3
npm run test:browser:phase4
npm run test:browser:recovery
```

Noir, Barretenberg, Garaga, Cairo, and Devnet verification needs the pinned native toolchain and substantially more memory than the web build. Reproduction commands and artifact checks are documented in [`circuits/README.md`](./circuits/README.md) and [`contracts/README.md`](./contracts/README.md).

## Repository map

| Path | Contents |
|---|---|
| [`app/`](./app) | Next.js routes, wallet flows, API endpoints, and product UI |
| [`lib/client/`](./lib/client) | Client vault, agreement, payroll, proof, disclosure, and recovery orchestration |
| [`lib/domain/`](./lib/domain) | Versioned schemas, commitments, calculations, and state transitions |
| [`lib/persistence/`](./lib/persistence) | PostgreSQL repositories, transactions, idempotency, leases, and reorg-safe cursors |
| [`lib/proof/`](./lib/proof) | Browser/hosted proof protocols, witness composition, and verifier calldata |
| [`lib/starknet/`](./lib/starknet) | Ready, STRK20, Mainnet contract, quote, and transaction adapters |
| [`circuits/`](./circuits) | Noir circuits and reproducible verification artifacts |
| [`contracts/`](./contracts) | Cairo seals, registries, bundles, generated verifiers, and integration tests |
| [`packages/mcp/`](./packages/mcp) | Structured MCP payroll gateway and adversarial tests |
| [`drizzle/`](./drizzle) | Versioned PostgreSQL migrations |
| [`scripts/`](./scripts) | Evidence verification, deployment planning, workers, and recovery tooling |
| [`evidence/`](./evidence) | Machine-readable Mainnet, Devnet, browser, and deployment evidence |
| [`docs/`](./docs) | Contract inventory, benchmarks, runbooks, and technical evidence reports |

## Deployment model

The hosted system is split by trust and resource requirements:

| Service | Exposure | Responsibility |
|---|---|---|
| `private-payroll` | Public HTTPS | Next.js UI/API, authentication, encrypted vault access, and durable workflow workers |
| `private-payroll-prover` | Authenticated HTTPS | Dedicated, serialized proof jobs for heavy browser-incompatible workloads |
| `payo-privacy-discovery` | Fly private network | Block-pinned STRK20 note discovery |
| `payo-transaction-prover` | Fly private network | Transaction-OS proving for direct Privacy SDK execution |
| `payo-policy-signer` | Fly private network only | Narrow policy-owner signatures; no arbitrary-call API |

Production releases run database migrations before the new web image becomes active. Service definitions are versioned in `fly.*.toml`; operational safeguards, rollback steps, and secret boundaries are documented in [`docs/MAINNET_RELEASE_RUNBOOK.md`](./docs/MAINNET_RELEASE_RUNBOOK.md).

## Security and limitations

- PAYO is non-custodial: Ready or the restricted policy account authorizes settlement; PAYO contracts do not hold the payroll treasury.
- Vault records are encrypted before persistence, but the configured hosted prover is trusted with the plaintext witness during a proof job. Self-hosting removes that operator dependency.
- Ready does not expose a STRK20 viewing key to the dapp, so Ready-backed private-note reconciliation cannot be labelled SettlementMatch-proven.
- Reference US, UK, and Canadian policy packs demonstrate committed calculations. They are not official filings, legal advice, tax advice, or a substitute for authority rules.
- Contracts and circuits are experimental and have not received an independent production security audit.
- A private transaction still exposes timing, contract interaction, calldata size, and possibly the submitting account.

Please report security issues privately through [GitHub Security Advisories](https://github.com/Tutulii/private-payroll/security/advisories/new). See [`SECURITY.md`](./SECURITY.md) for scope and reporting guidance.

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) for setup, test tiers, cryptographic-change requirements, and pull-request expectations.

PAYO is available under the [MIT License](./LICENSE).
