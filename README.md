# PAYO

> **Proof-carrying private payroll for humans and AI agents — pay in STRK or USDC and prove every obligation was met without revealing a single salary.**

PAYO is a non-custodial payroll workspace on Starknet. It combines STRK20 private settlement with encrypted pay agreements, payroll-integrity proofs, selective disclosure, and policy-constrained MCP access for AI agents.

The project is being built for the [STRK20 Private Sprint](https://strk20.starknet.io/hackathon). The protocol design follows the sprint's private-payroll RFP: private batches, recurring channels, vesting, termination records, scoped signing authority, and receipts that reveal only what their holder chooses.

## Why PAYO exists

Normal onchain payroll exposes who was paid, how much they earn, when they are paid, and which treasury funds them. Centralized payroll hides this from the public by creating a new data custodian that sees everything.

PAYO is designed around a different promise:

- **Private from the public:** STRK20 conceals private transfer recipients, assets, and amounts.
- **Private from PAYO:** sensitive payroll records are encrypted before they leave an authorized client.
- **Accountable to the right people:** workers, auditors, and tax professionals receive scoped proof packages instead of an entire payroll database.
- **Programmable for humans and agents:** people receive wages and agents receive policy-bounded budgets through the same obligation system.

Privacy alone is not enough. An employer could otherwise hide underpayment as easily as it hides a legitimate salary. PAYO's protocol goal is therefore **proof-carrying payroll**: a private payment travels with evidence that the committed calculation and payment policy were satisfied.

## Status

PAYO labels capabilities according to evidence, not intention.

| Capability | Status | Evidence |
|---|---|---|
| Ready wallet discovery and Wallet API detection | Working | Browser integration |
| Mainnet STRK shielding with a live privacy-fee quote | Working | Ready + STRK20 |
| Mainnet private STRK batch payroll, up to 50 recipients | Working | Ready + STRK20 |
| Confirmation tracking and shielded-balance refresh | Working | Starknet receipt |
| Native USDC private payroll | Safety-gated | Full token path exists; UI disabled until live pool compatibility passes |
| Encrypted persistent payroll vault | Built and tested locally | XChaCha20-Poly1305/X25519 envelopes, authenticated API, PostgreSQL migration |
| PayrollIntegrity ZK proof core | Phase 1 complete; not deployed | [Green Phase 1 evidence](./docs/phase1-evidence.md): 45 Noir tests, two linked native and browser ZK proofs, reproducible Garaga verifier, and real Cairo verifier → bundle → seal checks |
| PAYO payroll-seal contract | Built and tested locally | Real two-proof verifier → bundle → seal integration passes; contracts are not deployed |
| Advanced obligation engine | Built and tested locally | Bounded policy DSL, multi-source FX snapshots, schedules, vesting, and offboarding tests |
| Compliance proof export | Built and tested locally | Balanced journal and verifier-bound ZIP package |
| MCP policy gateway | Built and tested locally | Signed capabilities and adversarial tests; generic wallet signing is prohibited |
| SettlementMatch proof | Research dependency | Ready does not expose its viewing key |

Three distinct states are never collapsed into one:

1. **Calculation proven** — the private manifest satisfied the committed payroll rules.
2. **Wallet confirmed** — Starknet confirmed the STRK20 transaction.
3. **Settlement proven** — private note evidence was reconciled with the approved manifest.

A Ready transaction can reach the first two states. The third requires viewing-key-derived evidence that the current Ready Wallet API does not expose to a dapp.

## Working application

The current Next.js application includes:

- Overview (`/`) — private treasury, payday, team, activity, and MCP summary.
- Payroll (`/payroll`) — live Mainnet shielding and private batch execution.
- People & Agents (`/team`) — compensation directory and scoped agent access.
- Activity (`/activity`) — privacy-aware records and selective-disclosure concepts.
- Wallet (`/wallet`) — Ready discovery, Wallet API version, public and shielded balances, and Privy identity.

The visual system uses warm paper tones, flat illustration, strong outlines, and restrained 2D animation instead of glass, neon, or sci-fi crypto styling.

### Try the current Mainnet flow

1. Install Ready and select Starknet Mainnet.
2. Open `/wallet`, connect Ready, and approve account access.
3. If the account is unregistered, complete the one-time setup at the linked STRK20 application.
4. Open `/payroll#private-payroll` and shield a deliberately small amount of STRK.
5. Add registered Starknet recipients and review all amounts in Ready.
6. Approve once, wait for confirmation, and inspect the Starkscan receipt.

Mainnet assets have real value. PAYO never requests or stores a recovery phrase, viewing key, or Ready private key.

## Master implementation roadmap

The roadmap below is the target, not a completion claim. The evidence-backed status is tracked in [`docs/implementation-status.json`](./docs/implementation-status.json), and the strict execution and release gates are in [`MASTER_PLAN.md`](./MASTER_PLAN.md). Run `npm run verify:status` for the current count. “Built locally” is deliberately different from “deployed.”

### Phase 0 — Protocol and safety foundation

- Lock canonical encrypted schemas and cross-language commitment encoding.
- Add this roadmap and the full [architecture specification](./architecture.md).
- Pin the Starknet, Scarb, Noir, Barretenberg, and Garaga toolchains.
- Publish an explicit visible-versus-hidden privacy model.
- Verify native Circle USDC against Ready and the live STRK20 pool before enabling it.

### Phase 1 — ZK-first PayrollIntegrity

- Build a fixed 64-leaf Noir circuit supporting up to 50 real recipients.
- Prove completeness, uniqueness, pay arithmetic, policy application, FX floors, schedule eligibility, and final-pay components.
- Generate a version-pinned Garaga verifier for Starknet.
- Run proof generation in a browser worker and reveal only roots, a nullifier, proof version, and validity window.
- Ship US and UK reference policy packs as examples, not legal certification.

### Phase 2 — Dual-token settlement and durable payroll

- Make STRK and native USDC first-class token descriptors with correct decimal handling.
- Support single-token and mixed-token payroll batches.
- Add client-encrypted organizations, agreements, payroll runs, proof bundles, and receipts.
- Add durable idempotency, confirmation recovery, reorg handling, and transaction indexing.
- Deploy the non-custodial PAYO seal, verifier, and policy-registry contracts.

### Phase 3 — Advanced obligations

- `StatutoryCorrect`: prove that a committed deductions policy was applied.
- `FXFloor`: prove that settlement value met the worker's chosen reference-currency floor.
- `ClassificationConsistency`: prove that payment treatment matched committed facts and policy; never claim a legal-status determination.
- Batch, recurring, checkpoint-streamed, milestone, and private vesting plans.
- `OffboardingCorrect`: ordinary pay, accrued leave, notice, severance, and adjustments.
- Private wage claims and private remediation payments.
- Encrypted accounting and auditor proof packages.

### Phase 4 — Human and AI-agent payroll

- Expose structured MCP tools for drafting, validating, requesting, and verifying payroll.
- Issue encrypted, expiring agent capabilities with token, recipient, purpose, amount, and period limits.
- Keep human approval as the initial default.
- Add bounded autonomy through a structured-intent signing gateway that never signs arbitrary calldata.
- Use direct Privacy SDK accounts for agent workflows that require local viewing-key control.

### Phase 5 — Mainnet evidence and release

- Record at least three successful Mainnet transactions that touch STRK20 and PAYO contracts.
- Demonstrate STRK payroll, USDC payroll, and one advanced obligation or agent flow.
- Publish contract addresses, class hashes, proof benchmarks, demo URL, and a three-minute demo.
- Complete `strk20.json` and publish deployment, recovery, security, and known-limitations runbooks.

## Privacy model

| Data | Public | PAYO service | Authorized employer | Worker |
|---|---:|---:|---:|---:|
| Pool interaction and timing | Yes | Yes | Yes | Yes |
| PAYO contract and proof version | Yes | Yes | Yes | Yes |
| Commitment roots and nullifier | Yes | Yes | Yes | Yes |
| Worker identity and payout address | No | Ciphertext | Yes | Own record |
| Salary, deductions, token choice | No | Ciphertext | Yes | Own record |
| Full payroll book | No | Ciphertext | Yes | No |
| Scoped income or audit receipt | Holder chooses | Ciphertext | Holder chooses | Holder chooses |

Direct wallet submission may reveal the transaction-signing Starknet account and timing. A paymaster or relay is required when hiding the submitter is part of the threat model.

## Architecture

The normative design is in [architecture.md](./architecture.md). It covers:

- trust boundaries and encrypted-key ownership;
- domain schemas and workflow states;
- PayrollIntegrity and SettlementMatch proofs;
- STRK20 `privacy_invoke` contracts;
- STRK/USDC and FX handling;
- MCP capabilities and the signing boundary;
- failure recovery, versioning, and disclosure limits.

## Development

### Requirements

- Node.js 24+
- npm 12+
- A Starknet Mainnet RPC URL
- Ready for live STRK20 wallet tests
- Scarb and Starknet Foundry for Cairo work
- Noir, Barretenberg, and Garaga for proof work

### Frontend

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

### Environment

Copy `.env.example` to `.env.local` and provide only the values required by the layer being run.

```bash
NEXT_PUBLIC_PRIVY_APP_ID=your-privy-app-id
NEXT_PUBLIC_STARKNET_RPC_URL=https://your-mainnet-rpc
PRIVY_APP_SECRET=your-rotated-server-only-secret
```

Privy secrets are server credentials. Never prefix them with `NEXT_PUBLIC_`, expose them in client code, or commit them. Any secret shared outside a secure secret manager must be rotated.

### Verify

```bash
npm run typecheck
npm test
npm run lint
npm run build
npm run verify:status
```

`npm run verify:completion` is the release gate. It intentionally fails while any roadmap or architecture requirement lacks integrated code, tests, deployment, or Mainnet evidence.

Database migration:

```bash
npm run db:migrate
```

Circuit, proof, and contract verification:

```bash
cd circuits/payroll_integrity
nargo test && nargo build
nargo execute witness-shard-0 --prover-name Prover
nargo execute witness-shard-1 --prover-name Prover-shard-1
cd ../.. && npm run proof:prove
cd contracts && scarb build && snforge test
cd integrity_verifier && scarb build && snforge test
```

The version-pinned proof/verifier commands are in [circuits/README.md](./circuits/README.md), and MCP setup is in [packages/mcp/README.md](./packages/mcp/README.md). A roadmap item is not considered shipped merely because its source directory exists.

## Security and legal boundaries

- Contracts and proof circuits are experimental until independently reviewed.
- Reference policy packs demonstrate verifiable calculation; they are not legal, tax, accounting, or employment advice.
- Classification depends on real-world facts and cannot be certified from a contract label alone.
- PAYO is non-custodial; funds remain controlled by the user's Starknet or policy account.
- Native USDC will not be silently substituted with a bridged asset if STRK20 support is unavailable.

## License

MIT
